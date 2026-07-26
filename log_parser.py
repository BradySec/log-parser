"""Format-detecting web/application log parser.

Use it either way: import log_parser as a library, or run it from the command
line via parse_logs.py or python -m log_parser.

Reads a log file in any of several common formats, normalises every line into
the same record shape, writes a CSV, and prints a summary.

Supported formats:
  combined  Apache/Nginx combined log format (with referrer and user agent)
  common    Apache/Nginx common log format
  fixed8    DATE TIME LEVEL IP METHOD URL STATUS 123ms
  json      One JSON object per line, common key names
  generic   TIMESTAMP LEVEL message, including syslog-style dates

Usage:
    python parse_logs.py access.log          # or: python -m log_parser access.log
    python parse_logs.py access.log --gzip
    python parse_logs.py access.log --no-csv
    python parse_logs.py --help

As a library:
    from log_parser import parse_line, run, make_anonymiser
"""

from __future__ import annotations

import argparse
import csv
import gzip
import hashlib
import hmac
import ipaddress
import json
import os
import re
import secrets
import sys
from collections import Counter
from contextlib import ExitStack
from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta
from typing import Callable, Iterable, Iterator, Optional, Sequence

__version__ = "2.0.0"

# --------------------------------------------------------------------------
# Configuration
# --------------------------------------------------------------------------

#: Paths only a scanner or an attacker asks for. A 4xx on one of these is
#: someone probing you; a 4xx on a real page is a broken link worth fixing.
SUSPICIOUS_PATHS = (
    ".env", ".git", ".aws", ".ssh", "wp-login", "wp-admin",
    "xmlrpc.php", "phpmyadmin", "server-status", "admin/config",
)

#: Cardinality ceiling for per-key tallies. Logs with millions of unique URLs
#: would otherwise grow the counters without bound; we only ever print the top
#: few, so pruning the long tail costs nothing that matters.
COUNTER_CAP = 200_000
COUNTER_KEEP = 50_000

#: Lines sampled to guess the file's dominant format before the main pass.
DETECT_SAMPLE = 50

#: Bits kept when truncating an address. Zeroing the last IPv4 octet or the
#: last 80 bits of IPv6 keeps the geography while breaking the link to a
#: household, which is the usual anonymisation recipe for analytics.
IPV4_KEEP_BITS = 24
IPV6_KEEP_BITS = 48

#: Hex digits kept from the HMAC digest. 12 is ~48 bits: collision-free in
#: practice for any realistic number of distinct clients, and short enough to
#: read in a terminal.
HASH_LENGTH = 12

CSV_COLUMNS = ("date", "time", "tz", "level", "ip", "method",
               "url", "status", "duration_ms", "bytes", "format")
CSV_HEADERS = ("Date", "Time", "TZ", "Level", "IP", "Method",
               "URL", "Status", "DurationMS", "Bytes", "Format")

# --------------------------------------------------------------------------
# Patterns
# --------------------------------------------------------------------------

CLF_RE = re.compile(
    r'^(?P<ip>\S+)'
    r'\s+\S+\s+(?P<user>\S+)'                   # identd and auth user, usually "-"
    r'\s+\[(?P<ts>[^\]]+)\]'                    # any bracketed timestamp style
    r'\s+"(?P<request>[^"]*)"'                  # "GET /path HTTP/1.1"
    r'\s+(?P<status>\d{3})'
    r'\s+(?P<bytes>\d+|-)'
    r'(?:\s+"(?P<referrer>[^"]*)"\s+"(?P<agent>[^"]*)")?'
    r'(?:\s+(?P<duration>\d+(?:\.\d+)?)\s*(?P<unit>ms|s))?'   # optional timing tail
    r'\s*$'
)

FIXED_RE = re.compile(
    r'^(?P<date>\d{4}[-/]\d{2}[-/]\d{2})'
    r'[ T](?P<time>\d{2}:\d{2}:\d{2}(?:[.,]\d+)?)'
    r'\s+\[?(?P<level>[A-Za-z]+)\]?'
    r'\s+(?P<ip>\d{1,3}(?:\.\d{1,3}){3}|[0-9a-fA-F:]{3,})'
    r'\s+(?P<method>[A-Z]{3,7})'
    r'\s+(?P<url>\S+)'
    r'\s+(?P<status>\d{3})'
    r'\s+(?P<duration>\d+(?:\.\d+)?)\s*(?P<unit>ms|s)?'
    r'\s*$'
)

GENERIC_RE = re.compile(
    r'^\[?(?P<ts>\d{4}[-/]\d{2}[-/]\d{2}[ T]\d{2}:\d{2}:\d{2}(?:[.,]\d+)?'
    r'|[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\]?'
    r'\s*\[?(?P<level>TRACE|DEBUG|INFO|NOTICE|WARN|WARNING|ERROR|CRIT|'
    r'CRITICAL|FATAL|ALERT|EMERG)\]?'
    r'[:\s-]+(?P<message>.*)$',
    re.IGNORECASE,
)

REQUEST_RE = re.compile(r'^(?P<method>[A-Z]{3,7})\s+(?P<url>\S+)(?:\s+(?P<proto>\S+))?$')
IP_RE = re.compile(r'\b\d{1,3}(?:\.\d{1,3}){3}\b')
DURATION_RE = re.compile(r'(\d+(?:\.\d+)?)\s*(ms|s)\b')
STATUS_RE = re.compile(r'\b(?:status|code)[=: ]+(\d{3})\b', re.IGNORECASE)
INLINE_REQUEST_RE = re.compile(r'\b([A-Z]{3,7})\s+(/\S*)')
OFFSET_RE = re.compile(r'\s*(?P<offset>[+-]\d{4})$')
ZONE_NAME_RE = re.compile(r'\s*(?P<name>Z|UTC|GMT)$')
SUBSECOND_RE = re.compile(r'([.,]\d+)(?=\s|$)')

#: Tried in order. Formats without an explicit year inherit the current one.
TS_FORMATS = (
    "%d/%b/%Y:%H:%M:%S",        # 10/Oct/2000:13:55:36   (Apache standard)
    "%d/%b/%Y %H:%M:%S",
    "%b %d %Y at %H:%M:%S",     # Jul 30 2026 at 05:12:34
    "%b %d %Y %H:%M:%S",
    "%Y-%m-%d %H:%M:%S",
    "%Y-%m-%dT%H:%M:%S",
    "%Y/%m/%d %H:%M:%S",
    "%b %d %H:%M:%S",           # syslog, no year
    "%d/%b/%Y",
    "%Y-%m-%d",
)

#: Key aliases so different JSON producers land in the same columns.
JSON_KEYS = {
    "ip": ("ip", "client_ip", "clientip", "remote_addr", "remote_ip", "host", "src_ip"),
    "ts": ("timestamp", "time", "@timestamp", "date", "datetime", "ts"),
    "level": ("level", "severity", "loglevel", "log_level"),
    "method": ("method", "verb", "request_method", "http_method"),
    "url": ("url", "path", "uri", "request", "request_uri", "endpoint"),
    "status": ("status", "status_code", "response_code", "code", "http_status"),
    "duration": ("duration_ms", "duration", "latency_ms", "latency",
                 "response_time", "elapsed_ms", "took_ms", "request_time"),
    "bytes": ("bytes", "size", "bytes_sent", "body_bytes_sent", "response_size"),
}



# --------------------------------------------------------------------------
# Anonymisation
# --------------------------------------------------------------------------

def truncate_ip(value: str) -> Optional[str]:
    """Zero the host portion of an address, keeping the network.

    ``192.168.239.106`` becomes ``192.168.239.0`` and an IPv6 address is cut to
    its /48. Returns None if the value is not an IP address at all.
    """
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return None
    bits = IPV4_KEEP_BITS if address.version == 4 else IPV6_KEEP_BITS
    return str(ipaddress.ip_network(f"{value}/{bits}", strict=False).network_address)


def hash_ip(value: str, salt: str) -> str:
    """Salted HMAC-SHA256 of an address, truncated for readability.

    Distinct clients stay distinct, so per-visitor counts survive, but the
    address cannot be recovered without the salt. This is pseudonymisation, not
    anonymisation: with the salt the mapping is reversible by brute force over
    the small IPv4 space, so the salt is itself sensitive.
    """
    digest = hmac.new(salt.encode(), value.encode(), hashlib.sha256).hexdigest()
    return f"ip_{digest[:HASH_LENGTH]}"


def make_anonymiser(mode: Optional[str], salt: Optional[str] = None
                    ) -> Optional[Callable[[str], str]]:
    """Build the function that rewrites addresses, or None for no rewriting.

    ``truncate`` falls back to hashing for values that are not IP addresses,
    such as the hostnames some servers log, since there is no meaningful
    network portion to keep and leaving them intact would defeat the point.
    """
    if not mode or mode == "none":
        return None
    if salt is None:
        salt = secrets.token_hex(16)

    def anonymise(value: str) -> str:
        if not value:
            return value
        if mode == "truncate":
            return truncate_ip(value) or hash_ip(value, salt)
        return hash_ip(value, salt)

    return anonymise


def redact_line(line: str, anonymise: Optional[Callable[[str], str]]) -> str:
    """Apply the anonymiser to every address in a raw line.

    Used for the skipped-lines file: writing unparsed lines verbatim would
    otherwise leak the addresses the CSV had just protected.
    """
    if anonymise is None:
        return line
    return IP_RE.sub(lambda match: anonymise(match.group(0)), line)


# --------------------------------------------------------------------------
# Record
# --------------------------------------------------------------------------

@dataclass
class Record:
    """One parsed log line, normalised across every supported format.

    Fields a given format does not carry stay empty or None rather than
    invalidating the line.
    """

    format: str
    date: str = ""
    time: str = ""
    tz: str = ""                     # original UTC offset, if the line had one
    level: str = ""
    ip: str = ""
    method: str = ""
    url: str = ""
    status: Optional[int] = None
    duration_ms: Optional[int] = None
    bytes: str = ""

    def as_row(self) -> list:
        """Values in CSV_COLUMNS order, with None rendered as empty."""
        data = asdict(self)
        return ["" if data[name] is None else data[name] for name in CSV_COLUMNS]


# --------------------------------------------------------------------------
# Field helpers
# --------------------------------------------------------------------------

def split_timestamp(raw: Optional[str], now: Optional[datetime] = None
                    ) -> tuple[str, str, str]:
    """Normalise any timestamp into ``(date, time, tz)``.

    Times carrying a UTC offset are converted to UTC and the original offset is
    preserved in ``tz``, so logs from mixed regions sort correctly. An
    unrecognised layout is passed through rather than discarded.
    """
    if not raw:
        return "", "", ""

    text = str(raw).strip().strip("[]")

    tz = ""
    offset = OFFSET_RE.search(text)
    if offset:
        tz = offset.group("offset")
        text = text[:offset.start()].strip()
    else:
        named = ZONE_NAME_RE.search(text)
        if named:
            tz = "+0000"
            text = text[:named.start()].strip()

    text = SUBSECOND_RE.sub("", text)

    for fmt in TS_FORMATS:
        try:
            stamp = datetime.strptime(text, fmt)
        except ValueError:
            continue
        if "%Y" not in fmt:
            stamp = stamp.replace(year=(now or datetime.now()).year)
        if tz and tz != "+0000":
            sign = 1 if tz[0] == "+" else -1
            delta = timedelta(hours=int(tz[1:3]), minutes=int(tz[3:5]))
            stamp -= sign * delta
        return stamp.strftime("%Y-%m-%d"), stamp.strftime("%H:%M:%S"), tz

    parts = text.split(" ", 1)
    return (parts[0], parts[1], tz) if len(parts) == 2 else (text, "", tz)


def to_milliseconds(value, unit: Optional[str] = "ms") -> Optional[int]:
    """Convert a duration to whole milliseconds. Returns None if unparseable."""
    if value is None or value == "":
        return None
    try:
        number = float(value)
    except (TypeError, ValueError):
        return None
    if unit == "s":
        number *= 1000
    return round(number)


def to_status(value) -> Optional[int]:
    """Coerce a status code to int, or None if it is not a 3-digit code."""
    text = str(value).strip()
    return int(text) if text.isdigit() and len(text) == 3 else None


def split_request(text: str) -> tuple[str, str]:
    """Split ``"GET /path HTTP/1.1"`` into ``("GET", "/path")``.

    A malformed request line becomes ``("", <whole thing>)`` so the URL column
    still shows what was attempted.
    """
    match = REQUEST_RE.match((text or "").strip())
    if match:
        return match.group("method"), match.group("url")
    return "", (text or "").strip()


def first_present(obj: dict, names: Sequence[str]):
    """First non-empty value among ``names``, or None."""
    for name in names:
        if name in obj and obj[name] not in (None, ""):
            return obj[name]
    return None


# --------------------------------------------------------------------------
# Per-format parsers. Each takes a stripped line and returns a Record or None.
# --------------------------------------------------------------------------

def parse_json(line: str) -> Optional[Record]:
    """One JSON object per line, keyed by any of the JSON_KEYS aliases."""
    if not line.startswith("{"):
        return None
    try:
        obj = json.loads(line)
    except ValueError:
        return None
    if not isinstance(obj, dict):
        return None

    method = first_present(obj, JSON_KEYS["method"]) or ""
    url = first_present(obj, JSON_KEYS["url"]) or ""
    if isinstance(url, str):
        parsed_method, parsed_url = split_request(url)
        if parsed_method:                       # field held a full request line
            method, url = method or parsed_method, parsed_url

    duration, unit = first_present(obj, JSON_KEYS["duration"]), "ms"
    if isinstance(duration, str):
        found = DURATION_RE.search(duration)
        if found:
            duration, unit = found.group(1), found.group(2)

    date, time, tz = split_timestamp(first_present(obj, JSON_KEYS["ts"]))
    return Record(
        format="json",
        date=date, time=time, tz=tz,
        level=str(first_present(obj, JSON_KEYS["level"]) or "").upper(),
        ip=str(first_present(obj, JSON_KEYS["ip"]) or ""),
        method=str(method), url=str(url),
        status=to_status(first_present(obj, JSON_KEYS["status"])),
        duration_ms=to_milliseconds(duration, unit),
        bytes=str(first_present(obj, JSON_KEYS["bytes"]) or ""),
    )


def parse_clf(line: str) -> Optional[Record]:
    """Apache/Nginx common and combined log format."""
    match = CLF_RE.match(line)
    if not match:
        return None
    group = match.groupdict()
    method, url = split_request(group["request"])
    date, time, tz = split_timestamp(group["ts"])
    return Record(
        format="combined" if group.get("agent") is not None else "common",
        date=date, time=time, tz=tz,
        ip=group["ip"], method=method, url=url,
        status=to_status(group["status"]),
        duration_ms=to_milliseconds(group.get("duration"), group.get("unit") or "ms"),
        bytes=group["bytes"] if group["bytes"] != "-" else "0",
    )


def parse_fixed(line: str) -> Optional[Record]:
    """The fixed 8-field format: DATE TIME LEVEL IP METHOD URL STATUS 123ms."""
    match = FIXED_RE.match(line)
    if not match:
        return None
    group = match.groupdict()
    return Record(
        format="fixed8",
        date=group["date"].replace("/", "-"),
        time=group["time"],
        level=group["level"].upper(),
        ip=group["ip"], method=group["method"], url=group["url"],
        status=to_status(group["status"]),
        duration_ms=to_milliseconds(group["duration"], group["unit"] or "ms"),
    )


def parse_generic(line: str) -> Optional[Record]:
    """TIMESTAMP LEVEL message, with request details recovered from the text.

    The extracted IP is the first one in the message, which is a guess: for a
    line naming several hosts it may not be the client.
    """
    match = GENERIC_RE.match(line)
    if not match:
        return None
    group = match.groupdict()
    message = group["message"]
    date, time, tz = split_timestamp(group["ts"])

    ip = IP_RE.search(message)
    status = STATUS_RE.search(message)
    duration = DURATION_RE.search(message)
    request = INLINE_REQUEST_RE.search(message)
    return Record(
        format="generic",
        date=date, time=time, tz=tz,
        level=group["level"].upper(),
        ip=ip.group(0) if ip else "",
        method=request.group(1) if request else "",
        url=request.group(2) if request else "",
        status=to_status(status.group(1)) if status else None,
        duration_ms=to_milliseconds(*duration.groups()) if duration else None,
    )


#: Ordered by specificity: JSON is unambiguous, CLF and fixed8 are strict, and
#: generic is the loosest so it goes last.
PARSERS = (parse_json, parse_clf, parse_fixed, parse_generic)


def parse_line(line: str, parsers: Sequence = PARSERS) -> Optional[Record]:
    """Return the first successful parse of ``line``, or None if none match."""
    for parser in parsers:
        record = parser(line)
        if record is not None:
            return record
    return None


def detect_order(lines: Iterable[str], parsers: Sequence = PARSERS) -> tuple:
    """Reorder ``parsers`` to put the sample's dominant format first.

    Saves up to three failed regex attempts per line on a uniform file, which
    is the common case and the one where throughput matters.
    """
    hits: Counter = Counter()
    for line in lines:
        for parser in parsers:
            if parser(line) is not None:
                hits[parser] += 1
                break
    if not hits:
        return tuple(parsers)
    return tuple(sorted(parsers, key=lambda p: -hits[p]))


# --------------------------------------------------------------------------
# Tallies
# --------------------------------------------------------------------------

class CappedCounter(Counter):
    """A Counter that prunes its long tail instead of growing without bound.

    Only the top few keys are ever reported, so once the counter exceeds
    ``cap`` we keep the ``keep`` largest and drop the rest. Counts for surviving
    keys stay exact; a key pruned and later seen again restarts from zero, which
    can only understate something already too rare to appear in the output.
    """

    def __init__(self, cap: int = COUNTER_CAP, keep: int = COUNTER_KEEP):
        super().__init__()
        self.cap = cap
        self.keep = keep
        self.pruned = 0

    def add(self, key) -> None:
        self[key] += 1
        if len(self) > self.cap:
            survivors = dict(self.most_common(self.keep))
            self.pruned += len(self) - len(survivors)
            self.clear()
            self.update(survivors)


@dataclass
class Stats:
    """Running totals for the summary."""

    parsed: int = 0
    skipped: int = 0
    timed: int = 0
    total_duration: int = 0
    formats: Counter = field(default_factory=Counter)
    statuses: Counter = field(default_factory=Counter)
    levels: Counter = field(default_factory=Counter)
    ips: CappedCounter = field(default_factory=CappedCounter)
    urls: CappedCounter = field(default_factory=CappedCounter)
    probes_by_ip: CappedCounter = field(default_factory=CappedCounter)
    probe_paths: CappedCounter = field(default_factory=CappedCounter)
    broken_links: CappedCounter = field(default_factory=CappedCounter)

    def add(self, record: Record) -> None:
        self.parsed += 1
        self.formats[record.format] += 1

        if record.duration_ms is not None:
            self.timed += 1
            self.total_duration += record.duration_ms
        if record.level:
            self.levels[record.level] += 1
        if record.ip:
            self.ips.add(record.ip)
        if record.url:
            self.urls.add(record.url)

        if record.status is None:
            return
        self.statuses[f"{record.status // 100}xx"] += 1
        if record.status < 400:
            return

        if is_suspicious(record.url):
            self.probes_by_ip.add(record.ip or "unknown")
            self.probe_paths.add(record.url)
        elif record.status < 500:
            # Only 4xx are broken links; a 5xx is a server fault, already
            # counted in the status totals above.
            self.broken_links.add(record.url)

    @property
    def mean_duration(self) -> Optional[float]:
        return self.total_duration / self.timed if self.timed else None

    def error_rate(self, prefix: str) -> Optional[float]:
        total = sum(self.statuses.values())
        return self.statuses[prefix] / total * 100 if total else None


def is_suspicious(url: str) -> bool:
    """True if the path is one only a scanner would request."""
    lowered = (url or "").lower()
    return any(marker in lowered for marker in SUSPICIOUS_PATHS)


# --------------------------------------------------------------------------
# Pipeline
# --------------------------------------------------------------------------

def iter_records(lines: Iterable[str], parsers: Sequence = PARSERS
                 ) -> Iterator[tuple[int, str, Optional[Record]]]:
    """Yield ``(lineno, raw, record)`` for every meaningful line.

    Blank lines and ``#`` comments are dropped. ``record`` is None when nothing
    matched, leaving the caller to decide how to report it.
    """
    for lineno, line in enumerate(lines, start=1):
        cleaned = line.strip()
        if not cleaned or cleaned.startswith("#"):
            continue
        yield lineno, cleaned, parse_line(cleaned, parsers)


def summarise(stats: Stats) -> list[str]:
    """Build the summary as lines of text, one screen long regardless of input."""
    if not stats.parsed:
        return []

    out = ["", "--- Summary ---"]
    out.append("Formats detected    : " + ", ".join(
        f"{name} ({n})" for name, n in stats.formats.most_common()))
    out.append(f"Unique IPs          : {len(stats.ips)}")

    mean = stats.mean_duration
    out.append(
        f"Mean response       : {mean:.1f} ms (from {stats.timed} timed lines)"
        if mean is not None else
        "Mean response       : n/a (no durations in this log)"
    )

    client = stats.error_rate("4xx")
    if client is not None:
        # 4xx is the client's fault and is mostly noise. 5xx is your fault.
        out.append(f"Client errors (4xx) : {client:.1f}%")
        out.append(f"Server errors (5xx) : {stats.error_rate('5xx'):.1f}%")
        out.append("")
        out.append("Status codes:")
        out += [f"  {code}: {n}" for code, n in sorted(stats.statuses.items())]

    sections = (
        ("Log levels:", stats.levels, "{key:<8} {n}"),
        ("Top 10 IPs by requests:", stats.ips, "{key:<18} {n}"),
        ("Top 10 IPs probing suspicious paths:", stats.probes_by_ip, "{key:<18} {n}"),
        ("Most probed paths:", stats.probe_paths, "{n:>6}  {key}"),
        ("Top 4xx on real paths (likely broken links, worth fixing):",
         stats.broken_links, "{n:>6}  {key}"),
        ("Top 10 URLs:", stats.urls, "{n:>6}  {key}"),
    )
    for title, counter, template in sections:
        if not counter:
            continue
        out.append("")
        out.append(title)
        out += [f"  {template.format(key=key, n=n)}"
                for key, n in counter.most_common(10)]
    return out


def run(input_filename: str, output_filename: Optional[str],
        bad_filename: str, use_gzip: bool = False,
        detect_sample: int = DETECT_SAMPLE,
        anonymise: Optional[Callable[[str], str]] = None) -> Stats:
    """Parse ``input_filename``, optionally write a CSV, and return the stats.

    The CSV is built under a temporary name and swapped into place only on
    success, so a crash partway leaves any previous CSV untouched.

    ``anonymise``, if given, rewrites every address before it reaches the
    tallies, the CSV or the skipped-lines file, so no raw address survives
    anywhere in the output.
    """
    stats = Stats()
    temp_filename = f"{output_filename}.tmp" if output_filename else None

    with ExitStack() as stack:
        # errors="replace" means one bad byte cannot kill the run.
        infile = stack.enter_context(
            open(input_filename, "r", encoding="utf-8", errors="replace"))
        badfile = stack.enter_context(
            open(bad_filename, "w", encoding="utf-8"))

        sample = [line.strip() for _, line in zip(range(detect_sample), infile)]
        parsers = detect_order([s for s in sample if s and not s.startswith("#")])
        infile.seek(0)

        writer = None
        if output_filename:
            opener = gzip.open if use_gzip else open
            outfile = stack.enter_context(
                opener(temp_filename, "wt", newline="", encoding="utf-8"))
            writer = csv.writer(outfile)
            writer.writerow(CSV_HEADERS)

        for lineno, raw, record in iter_records(infile, parsers):
            if record is None:
                stats.skipped += 1
                badfile.write(f"line {lineno}: {redact_line(raw, anonymise)}\n")
                continue
            if anonymise is not None:
                record.ip = anonymise(record.ip)
            stats.add(record)
            if writer is not None:
                writer.writerow(record.as_row())

    if output_filename:
        os.replace(temp_filename, output_filename)
    return stats


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Parse web and application logs of any supported format.",
    )
    parser.add_argument("logfile", nargs="?", default="server.log",
                        help="log file to read (default: server.log)")
    parser.add_argument("-o", "--output", default="parsed_logs.csv",
                        help="CSV to write (default: parsed_logs.csv)")
    parser.add_argument("--skipped", default="skipped_lines.log",
                        help="where to record unparseable lines")
    parser.add_argument("--no-csv", action="store_true",
                        help="print the summary only, write no CSV")
    parser.add_argument("--gzip", action="store_true",
                        help="gzip the CSV, appending .gz to its name")

    privacy = parser.add_argument_group(
        "privacy",
        "Client IPs are personal data under the GDPR. These options rewrite "
        "every address before it reaches the CSV, the summary or the "
        "skipped-lines file.")
    privacy.add_argument("--anonymise-ips", "--anonymize-ips",
                         dest="anonymise_ips",
                         choices=("none", "truncate", "hash"), default="none",
                         help="truncate: zero the last IPv4 octet (/24) or cut "
                              "IPv6 to /48. hash: salted HMAC, keeping distinct "
                              "clients distinct. Default: none")
    privacy.add_argument("--salt", default=None,
                         help="salt for --anonymise-ips=hash. Omit for a random "
                              "per-run salt, which prevents correlating one run "
                              "against another; supply a fixed value only if you "
                              "need to track a client across runs, and treat it "
                              "as a secret")
    parser.add_argument("--version", action="version",
                        version=f"%(prog)s {__version__}")
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = build_parser().parse_args(argv)

    if not os.path.isfile(args.logfile):
        print(f"Error: could not find '{args.logfile}'.", file=sys.stderr)
        return 1

    output = None if args.no_csv else args.output
    if output and args.gzip:
        output += ".gz"

    if args.salt and args.anonymise_ips != "hash":
        print("Warning: --salt only applies to --anonymise-ips=hash.",
              file=sys.stderr)

    anonymise = make_anonymiser(args.anonymise_ips, args.salt)

    print(f"Starting log parsing on '{args.logfile}'...")
    if anonymise is not None:
        detail = ("truncated to network prefix" if args.anonymise_ips == "truncate"
                  else f"hashed with a {'supplied' if args.salt else 'random per-run'} salt")
        print(f"Anonymising IPs: {detail}.")
    stats = run(args.logfile, output, args.skipped, use_gzip=args.gzip,
                anonymise=anonymise)

    if output:
        print(f"Parsed {stats.parsed} log lines. Saved results to '{output}'.")
    else:
        print(f"Parsed {stats.parsed} log lines. (--no-csv: no file written.)")

    if stats.skipped:
        print(f"Skipped {stats.skipped} lines. "
              f"Full list written to '{args.skipped}'.")

    print("\n".join(summarise(stats)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())