"""Format-detecting web/application log parser.

Reads a log file in any of several common formats, normalises every line into
the same record shape, writes a CSV, and prints a summary.

Supported formats:
  combined  Apache/Nginx combined log format (with referrer and user agent)
  common    Apache/Nginx common log format
  fixed8    DATE TIME[ZONE] LEVEL IP METHOD URL STATUS 123ms
  json      One JSON object per line, common key names
  generic   TIMESTAMP LEVEL message, including syslog-style dates

Plain and gzipped input are both read; the format is detected from the file's
first bytes, not its name.

Usage:
    python parse_logs.py access.log
    python parse_logs.py access.log.gz
    python parse_logs.py access.log --gzip
    python parse_logs.py access.log --no-csv
    python parse_logs.py access.log --redact
    python parse_logs.py access.log --assume-tz +0200
    python parse_logs.py access.log --counter-cap 0
    python parse_logs.py --help
"""

from __future__ import annotations

import argparse
import csv
import gzip
import ipaddress
import json
import math
import os
import random
import re
import sys
from collections import Counter
from contextlib import ExitStack, contextmanager
from dataclasses import dataclass, field, asdict, replace
from datetime import datetime, timedelta
from typing import Callable, Iterable, Iterator, Optional, Sequence
from urllib.parse import unquote

__version__ = "3.1.0"

# --------------------------------------------------------------------------
# Configuration
# --------------------------------------------------------------------------

#: Path components only a scanner or an attacker asks for. Matched against
#: whole path segments, never as substrings: "/blog/using.gitlab-ci" is not a
#: probe for ".git", and "/docs/.environment-setup" is not a probe for ".env".
#: A segment also matches when it extends a marker with a dot, so ".env" also
#: catches ".env.production" and "wp-login" catches "wp-login.php".
SUSPICIOUS_SEGMENTS = frozenset({
    ".env", ".git", ".aws", ".ssh", ".htpasswd", ".npmrc",
    "wp-login", "wp-admin", "xmlrpc.php", "phpmyadmin",
    "server-status", "id_rsa", "credentials",
})

#: Markers that only mean anything as consecutive segments.
SUSPICIOUS_SEQUENCES = (("admin", "config"),)

#: Any request for one of the above is worth counting whatever the outcome:
#: a 4xx is a probe that bounced, and anything below this threshold is a probe
#: that was served. 400 counts a 3xx redirect as served, on the grounds that
#: the path existed and was not refused; lower it to 300 to require a 2xx.
PROBE_SUCCESS_MAX = 400

#: How much of an address survives --redact. IPv4 /24 keeps the network,
#: IPv6 /48 keeps the routing prefix. Widen the IPv6 value to 64 to separate
#: households on a residential prefix, at the cost of some anonymity.
IPV4_MASK_BITS = 24
IPV6_MASK_BITS = 48

#: Cardinality ceiling for per-key tallies. Logs with millions of unique URLs
#: would otherwise grow the counters without bound; we only ever print the top
#: few, so pruning the long tail costs nothing that matters. Past the cap the
#: unique counts become bounds rather than figures, so --counter-cap raises or
#: removes the limit when an exact answer matters more than the memory.
COUNTER_CAP = 200_000
COUNTER_KEEP = 50_000

#: Durations kept for percentiles. Beyond this the sample is a uniform random
#: subset of everything seen, which makes p50/p95 estimates rather than facts.
DURATION_SAMPLE = 50_000

#: Lines sampled to guess the file's dominant format before the main pass.
DETECT_SAMPLE = 50

CSV_COLUMNS = ("date", "time", "tz", "level", "ip", "method",
               "url", "status", "duration_ms", "bytes", "format")
CSV_HEADERS = ("Date", "Time", "TZ", "Level", "IP", "Method",
               "URL", "Status", "DurationMS", "Bytes", "Format")


@dataclass
class Config:
    """Process-wide parsing settings.

    The per-format parsers are plain functions called through ``parse_line``,
    with nowhere to thread options through, so the two settings that affect
    timestamp interpretation live here instead. ``main`` sets them once before
    parsing starts; library callers can set them directly.
    """

    #: Offset to assume for timestamps that carry no zone, e.g. "+0200".
    #: Empty means leave such timestamps exactly as written.
    assume_tz: str = ""

    #: What "now" means when a format omits the year (syslog). Defaults to the
    #: log file's modification time, which dates an old rotated file correctly
    #: where the wall clock would not.
    reference_time: Optional[datetime] = None


CONFIG = Config()


@contextmanager
def configured(**overrides):
    """Apply ``CONFIG`` overrides for the duration of a block, then restore.

    ``CONFIG`` is process-wide, so a run that set it permanently would decide
    how the *next* run reads its timestamps. Scoping the change keeps one call
    to ``run`` from reaching into the next one.
    """
    saved = replace(CONFIG)
    for name, value in overrides.items():
        if value is not None:
            setattr(CONFIG, name, value)
    try:
        yield CONFIG
    finally:
        for name in ("assume_tz", "reference_time"):
            setattr(CONFIG, name, getattr(saved, name))

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
    r'(?P<tz>\s?(?:[+-]\d{2}:?\d{2}|Z|UTC|GMT))?'   # zone, if the writer emits one
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
OFFSET_RE = re.compile(r'\s*(?P<offset>[+-]\d{2}:?\d{2})$')
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

def normalise_offset(text: str) -> str:
    """Turn any accepted zone spelling into ``+HHMM``. Empty if unrecognised.

    Offsets outside the range real zones occupy (-12:00 to +14:00) are
    rejected rather than applied, so a malformed tail like "+2500" cannot
    silently shift a timestamp by a day.
    """
    value = (text or "").strip()
    if not value:
        return ""
    if value.upper() in ("Z", "UTC", "GMT"):
        return "+0000"
    match = re.fullmatch(r'(?P<sign>[+-])(?P<hh>\d{2}):?(?P<mm>\d{2})', value)
    if not match:
        return ""
    hours, minutes = int(match.group("hh")), int(match.group("mm"))
    if minutes > 59:
        return ""
    total = hours * 60 + minutes
    if match.group("sign") == "-" and total > 12 * 60:
        return ""
    if match.group("sign") == "+" and total > 14 * 60:
        return ""
    return f"{match.group('sign')}{hours:02d}{minutes:02d}"


def split_timestamp(raw: Optional[str], now: Optional[datetime] = None,
                    assume_tz: Optional[str] = None) -> tuple[str, str, str]:
    """Normalise any timestamp into ``(date, time, tz)``.

    Times carrying a UTC offset are converted to UTC and the original offset is
    preserved in ``tz``, so logs from mixed regions sort correctly. A timestamp
    with no zone is left as written unless ``assume_tz`` (or ``CONFIG``) says
    what clock the writer was on, in which case it is converted like any other
    and the assumed offset is recorded in ``tz``. An unrecognised layout is
    passed through rather than discarded.
    """
    if not raw:
        return "", "", ""

    text = str(raw).strip().strip("[]")
    if assume_tz is None:
        assume_tz = CONFIG.assume_tz

    tz = ""
    offset = OFFSET_RE.search(text)
    if offset:
        # +02:00 and +0200 are the same offset; store one shape. An
        # out-of-range tail is not an offset at all, so leave the text intact
        # and let the format loop decide what to make of it.
        candidate = normalise_offset(offset.group("offset"))
        if candidate:
            tz = candidate
            text = text[:offset.start()].strip()
    if not tz:
        named = ZONE_NAME_RE.search(text)
        if named:
            tz = "+0000"
            text = text[:named.start()].strip()

    text = SUBSECOND_RE.sub("", text)
    assumed = not tz and bool(assume_tz)
    if assumed:
        tz = normalise_offset(assume_tz)

    for fmt in TS_FORMATS:
        try:
            stamp = datetime.strptime(text, fmt)
        except ValueError:
            continue
        if "%Y" not in fmt:
            # Syslog omits the year. Assume the reference year, then step back
            # one if that puts the line in the future: a December log read in
            # January is last year's, not next year's.
            reference = now or CONFIG.reference_time or datetime.now()
            stamp = stamp.replace(year=reference.year)
            if stamp - reference > timedelta(days=1):
                stamp = stamp.replace(year=reference.year - 1)
        if tz and tz != "+0000":
            sign = 1 if tz[0] == "+" else -1
            delta = timedelta(hours=int(tz[1:3]), minutes=int(tz[3:5]))
            stamp -= sign * delta
        return stamp.strftime("%Y-%m-%d"), stamp.strftime("%H:%M:%S"), tz

    parts = text.split(" ", 1)
    # Nothing parsed, so no conversion happened; do not claim a zone.
    tz = "" if assumed else tz
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
# Anonymisation
#
# Masking works on text, not on parsed fields, so it reaches every sink: the
# CSV, the printed summary, and skipped_lines.log. Skipped lines never become
# a Record at all, and a malformed address is a common reason a line fails to
# parse, so field-level masking would systematically miss the addresses most
# in need of it.
# --------------------------------------------------------------------------

_HEXTET = r'[0-9A-Fa-f]{1,4}'
_DOTTED = r'\d{1,3}(?:\.\d{1,3}){3}'

#: Structural IPv6 matcher. Deliberately strict: a loose class like
#: [0-9A-Fa-f:]+ also matches a clock time such as 13:55:36, so every branch
#: demands either eight hextets or a "::" compression marker. Anything matched
#: here is still validated by the ipaddress module before it is rewritten.
IPV6_CORE = (
    r'(?:'
    rf'(?:{_HEXTET}:){{6}}{_DOTTED}'                  # 6 hextets + IPv4 tail
    rf'|(?:{_HEXTET}:){{1,5}}:{_DOTTED}'              # compressed + IPv4 tail
    rf'|::(?:{_HEXTET}:){{0,5}}{_DOTTED}'             # ::ffff:192.0.2.1
    rf'|(?:{_HEXTET}:){{7}}{_HEXTET}'                 # eight hextets, no ::
    rf'|(?:{_HEXTET}:){{1,7}}:'                       # trailing ::
    rf'|(?:{_HEXTET}:){{1,6}}:{_HEXTET}'
    rf'|(?:{_HEXTET}:){{1,5}}(?::{_HEXTET}){{1,2}}'
    rf'|(?:{_HEXTET}:){{1,4}}(?::{_HEXTET}){{1,3}}'
    rf'|(?:{_HEXTET}:){{1,3}}(?::{_HEXTET}){{1,4}}'
    rf'|(?:{_HEXTET}:){{1,2}}(?::{_HEXTET}){{1,5}}'
    rf'|{_HEXTET}:(?::{_HEXTET}){{1,6}}'
    rf'|:(?::{_HEXTET}){{1,7}}'                       # leading ::
    r'|::'
    r')'
)

#: Wraps the address in the decorations logs actually carry: square brackets,
#: a %zone suffix, and a port. The conditional groups keep brackets balanced
#: and allow a port only when bracketed, since 2001:db8::1:443 is ambiguous.
IPV6_RE = re.compile(
    r'(?<![0-9A-Za-z:.])'
    r'(?P<open>\[)?'
    rf'(?P<addr>{IPV6_CORE})'
    r'(?P<zone>%[0-9A-Za-z._~-]+)?'
    r'(?(open)\])'
    r'(?(open)(?::(?P<port>\d{1,5}))?)'
    r'(?![0-9A-Za-z:])'
)

IPV4_MASK_RE = re.compile(rf'(?<![0-9A-Za-z.:]){_DOTTED}(?![0-9A-Za-z.])')

#: Credential-ish key names, matched in query strings, headers, and the
#: key=value soup that unparseable lines tend to be made of.
SECRET_KV_RE = re.compile(
    r'(?P<key>\b(?:'
    r'api[_-]?key|access[_-]?token|refresh[_-]?token|id[_-]?token|'
    r'auth(?:orization)?|bearer|secret|signature|sig|token|'
    r'session(?:[_-]?id)?|sid|passw(?:or)?d|pwd|otp|nonce|cookie'
    r')\b)(?P<sep>\s*[=:]\s*)(?P<value>"[^"]*"|\'[^\']*\'|[^\s&;,"\']+)',
    re.IGNORECASE,
)

BEARER_RE = re.compile(r'\b(?P<scheme>Bearer|Basic|Digest)\s+[A-Za-z0-9._~+/=-]{8,}',
                       re.IGNORECASE)

#: Local part is masked, domain kept: an address is identifying, the domain it
#: belongs to is usually the useful part for triage.
EMAIL_RE = re.compile(
    r'\b[A-Za-z0-9._%+-]+@(?P<domain>[A-Za-z0-9.-]+\.[A-Za-z]{2,})\b')


def mask_ipv4(text: str) -> Optional[str]:
    """Zero the host bits: 203.0.113.47 -> 203.0.113.0. None if not an IPv4."""
    try:
        address = ipaddress.IPv4Address(text)
    except ValueError:
        return None
    network = ipaddress.ip_network(f"{address}/{IPV4_MASK_BITS}", strict=False)
    return str(network.network_address)


def mask_ipv6(text: str) -> Optional[str]:
    """Keep the routing prefix, zero the rest: 2001:db8:1:2::5 -> 2001:db8:1::

    IPv4-mapped addresses are masked inside the mapping instead, so
    ::ffff:203.0.113.47 stays recognisably v4-in-v6 rather than collapsing to
    a bare "::" as a flat /48 would make it. Returns None if the text is not
    actually an address, which is what keeps a stray hex-and-colon token from
    being rewritten.
    """
    try:
        address = ipaddress.IPv6Address(text)
    except ValueError:
        return None
    if address.ipv4_mapped is not None:
        return f"::ffff:{mask_ipv4(str(address.ipv4_mapped))}"
    network = ipaddress.ip_network(f"{address}/{IPV6_MASK_BITS}", strict=False)
    return str(network.network_address)


def _sub_ipv6(match: re.Match) -> str:
    """Rebuild a matched IPv6 token around its masked address.

    Brackets and port survive; the %zone is dropped, since an interface name
    is host-specific and anonymisation should shed it.
    """
    masked = mask_ipv6(match.group("addr"))
    if masked is None:
        return match.group(0)
    if not match.group("open"):
        return masked
    port = match.group("port")
    return f"[{masked}]" + (f":{port}" if port else "")


def _sub_ipv4(match: re.Match) -> str:
    return mask_ipv4(match.group(0)) or match.group(0)


def anonymise(text: str) -> str:
    """Mask addresses and obvious secrets in ``text``.

    Order matters. Secrets go first so that a token containing dotted digits
    is blanked whole rather than partly rewritten, and IPv6 precedes IPv4 so
    that a mapped form like ::ffff:192.0.2.1 is masked as one address instead
    of having its dotted tail rewritten out from under it.

    This is a redactor, not a guarantee. It knows about addresses, e-mail
    local parts, and the credential key names in SECRET_KEY_RE; a log that
    carries identifiers in some other shape still carries them afterwards.
    """
    if not text:
        return text
    text = SECRET_KV_RE.sub(lambda m: f"{m.group('key')}{m.group('sep')}***", text)
    text = BEARER_RE.sub(lambda m: f"{m.group('scheme')} ***", text)
    text = EMAIL_RE.sub(lambda m: f"***@{m.group('domain')}", text)
    return IPV4_MASK_RE.sub(_sub_ipv4, IPV6_RE.sub(_sub_ipv6, text))


def keep(text: str) -> str:
    """Identity redactor, used when --redact is off."""
    return text


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
        # "-" means the server did not record a size, which is not zero.
        bytes=group["bytes"] if group["bytes"] != "-" else "",
    )


def parse_fixed(line: str) -> Optional[Record]:
    """The fixed 8-field format: DATE TIME LEVEL IP METHOD URL STATUS 123ms.

    The timestamp goes through ``split_timestamp`` rather than being copied out
    of the regex, so a zone-bearing line lands on the same UTC clock as every
    other format. A line with no zone cannot be normalised by anyone and is
    passed through as written.
    """
    match = FIXED_RE.match(line)
    if not match:
        return None
    group = match.groupdict()
    stamp = f"{group['date']} {group['time']}{group['tz'] or ''}"
    date, time, tz = split_timestamp(stamp)
    return Record(
        format="fixed8",
        date=date, time=time, tz=tz,
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

    Pruning does destroy one thing the summary reports directly: ``len()`` is
    the number of keys *held*, not the number ever seen. Once pruning has
    happened the two differ, so the counter tracks what it discarded and can
    bound the true figure rather than quietly understating it.
    """

    def __init__(self, cap: int = COUNTER_CAP, keep: int = COUNTER_KEEP):
        super().__init__()
        self.cap = cap
        self.keep = keep
        self.pruned = 0      # cumulative keys dropped, counting repeats
        self.prunes = 0      # number of prune events

    def add(self, key) -> None:
        self[key] += 1
        if len(self) > self.cap:
            survivors = dict(self.most_common(self.keep))
            self.pruned += len(self) - len(survivors)
            self.prunes += 1
            self.clear()
            self.update(survivors)

    @property
    def capped(self) -> bool:
        """True once pruning has happened, i.e. once the tallies are lossy."""
        return self.prunes > 0

    def distinct_range(self) -> tuple[int, int]:
        """Bounds on the number of distinct keys ever seen: ``(low, high)``.

        Everything still held is distinct, so ``len()`` is a floor. Each key
        dropped was distinct when dropped but may be counted again by a later
        prune if it reappeared, so ``len() + pruned`` is a ceiling and not an
        estimate. With no pruning the bounds coincide and the count is exact.
        """
        return len(self), len(self) + self.pruned


def describe_hit(record: Record) -> str:
    """One-line description of a successful request to a suspicious path."""
    return (f"{record.status} {record.method or '?'} {record.url} "
            f"from {record.ip or 'unknown'}")


class DurationSample:
    """Keeps a bounded, uniform sample of durations for percentile estimates.

    A mean hides the tail that users actually feel, so the summary needs
    percentiles, and exact percentiles need every value. Holding a few million
    integers is avoidable: past ``size`` this switches to reservoir sampling,
    where every value seen has an equal chance of being in the sample. The
    result is an estimate, and ``exact`` says which kind of number it is.
    """

    def __init__(self, size: int = DURATION_SAMPLE, seed: int = 0):
        self.size = size
        self.seen = 0
        self.values: list[int] = []
        self._random = random.Random(seed)     # seeded: same log, same estimate

    def add(self, value: int) -> None:
        self.seen += 1
        if len(self.values) < self.size:
            self.values.append(value)
            return
        # Classic reservoir step: the nth value survives with probability
        # size/n, replacing a uniformly chosen incumbent.
        index = self._random.randrange(self.seen)
        if index < self.size:
            self.values[index] = value

    @property
    def exact(self) -> bool:
        """True while the sample still holds everything that was seen."""
        return self.seen <= self.size

    def percentile(self, fraction: float) -> Optional[int]:
        """Nearest-rank percentile, or None if nothing has been recorded."""
        if not self.values:
            return None
        ordered = sorted(self.values)
        rank = max(0, math.ceil(fraction * len(ordered)) - 1)
        return ordered[rank]


@dataclass
class Stats:
    """Running totals for the summary."""

    cap: float = COUNTER_CAP
    parsed: int = 0
    skipped: int = 0
    timed: int = 0
    total_duration: int = 0
    probe_attempts: int = 0
    probe_successes: int = 0
    durations: DurationSample = field(default_factory=DurationSample)
    formats: Counter = field(default_factory=Counter)
    statuses: Counter = field(default_factory=Counter)
    levels: Counter = field(default_factory=Counter)
    ips: CappedCounter = field(default_factory=CappedCounter)
    urls: CappedCounter = field(default_factory=CappedCounter)
    probes_by_ip: CappedCounter = field(default_factory=CappedCounter)
    probe_paths: CappedCounter = field(default_factory=CappedCounter)
    probe_hits: CappedCounter = field(default_factory=CappedCounter)
    broken_links: CappedCounter = field(default_factory=CappedCounter)

    #: The capped tallies, in one place so the cap can be applied to all of
    #: them and the summary can ask which of them lost data.
    TALLIES = ("ips", "urls", "probes_by_ip", "probe_paths",
               "probe_hits", "broken_links")

    def __post_init__(self) -> None:
        if self.cap == COUNTER_CAP:
            return
        # A keep close to the cap would prune on nearly every add, so scale it
        # with the cap rather than leaving the default 50k above a small limit.
        keep = max(1, int(self.cap // 4)) if self.cap != math.inf else 0
        for name in self.TALLIES:
            counter = getattr(self, name)
            counter.cap, counter.keep = self.cap, keep

    def add(self, record: Record) -> None:
        self.parsed += 1
        self.formats[record.format] += 1

        if record.duration_ms is not None:
            self.timed += 1
            self.total_duration += record.duration_ms
            self.durations.add(record.duration_ms)
        if record.level:
            self.levels[record.level] += 1
        if record.ip:
            self.ips.add(record.ip)
        if record.url:
            self.urls.add(record.url)

        # A request for a scanner path is worth counting whatever it returned,
        # and whether or not the line carried a status at all. The outcome
        # decides how alarming it is, not whether it gets recorded.
        probe = is_suspicious(record.url)
        if probe:
            self.probe_attempts += 1
            self.probes_by_ip.add(record.ip or "unknown")
            self.probe_paths.add(record.url)
            if record.status is not None and record.status < PROBE_SUCCESS_MAX:
                # Served, not refused: the probe found something.
                self.probe_successes += 1
                self.probe_hits.add(describe_hit(record))

        if record.status is None:
            return
        self.statuses[f"{record.status // 100}xx"] += 1

        # Only 4xx on a real path is a broken link; a 5xx is a server fault,
        # already counted in the status totals above.
        if 400 <= record.status < 500 and not probe:
            self.broken_links.add(record.url)

    @property
    def mean_duration(self) -> Optional[float]:
        return self.total_duration / self.timed if self.timed else None

    def error_rate(self, prefix: str) -> Optional[float]:
        total = sum(self.statuses.values())
        return self.statuses[prefix] / total * 100 if total else None


def path_segments(url: str) -> list[str]:
    """Split a URL into lowercase path segments.

    Query and fragment are dropped, percent-encoding is decoded, and backslash
    separators are folded to forward slashes, since a scanner asking for
    ``/%2egit/config`` or ``/..\\.env`` means the same thing as the plain form.
    """
    path = (url or "").split("?", 1)[0].split("#", 1)[0]
    path = unquote(path).replace("\\", "/").lower()
    return [segment for segment in path.split("/") if segment]


def is_suspicious(url: str) -> bool:
    """True if the path is one only a scanner would request.

    Matching is per segment, not by substring: ``/blog/using.gitlab-ci`` is a
    real article rather than a probe for ``.git``, and ``/docs/.environment``
    is documentation rather than a probe for ``.env``. A segment that extends
    a marker with a dot still counts, so ``.env.production`` and
    ``wp-login.php`` are both caught.
    """
    segments = path_segments(url)
    if not segments:
        return False
    if not SUSPICIOUS_SEGMENTS.isdisjoint(segments):
        return True
    if any(segment.startswith(f"{marker}.")
           for segment in segments for marker in SUSPICIOUS_SEGMENTS):
        return True
    return any(tuple(segments[i:i + len(sequence)]) == sequence
               for sequence in SUSPICIOUS_SEQUENCES
               for i in range(len(segments) - len(sequence) + 1))


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

    # Anything served from a scanner path leads the summary: it is the one
    # finding here that may mean a live compromise rather than background noise.
    if stats.probe_hits:
        out.append("")
        out.append(f"!! {stats.probe_successes} SUCCESSFUL requests to suspicious "
                   f"paths (of {stats.probe_attempts} attempted) - investigate first:")
        out += [f"  {n:>6}  {key}" for key, n in stats.probe_hits.most_common(10)]

    out.append("")
    out.append("Formats detected    : " + ", ".join(
        f"{name} ({n})" for name, n in stats.formats.most_common()))

    low, high = stats.ips.distinct_range()
    if low == high:
        out.append(f"Unique IPs          : {low}")
    else:
        # Never print the floor alone: past the cap it is the number of
        # addresses still held, which is not the number seen.
        out.append(f"Unique IPs          : between {low} and {high} "
                   f"(counter hit its {stats.ips.cap} key cap)")

    mean = stats.mean_duration
    if mean is None:
        out.append("Mean response       : n/a (no durations in this log)")
    else:
        out.append(f"Mean response       : {mean:.1f} ms "
                   f"(from {stats.timed} timed lines)")
        p50 = stats.durations.percentile(0.50)
        p95 = stats.durations.percentile(0.95)
        # The mean is exact but flattens the tail; the percentiles are what a
        # slow endpoint actually shows up in.
        note = "" if stats.durations.exact else \
            f" (estimated from a {len(stats.durations.values)} value sample)"
        out.append(f"Median / p95        : {p50} ms / {p95} ms{note}")

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
        ("Top 10 IPs probing suspicious paths (any outcome):",
         stats.probes_by_ip, "{key:<18} {n}"),
        ("Most probed paths (any outcome):", stats.probe_paths, "{n:>6}  {key}"),
        ("Top 4xx on real paths (likely broken links, worth fixing):",
         stats.broken_links, "{n:>6}  {key}"),
        ("Top 10 URLs:", stats.urls, "{n:>6}  {key}"),
    )
    capped_any = False
    for title, counter, template in sections:
        if not counter:
            continue
        marked = isinstance(counter, CappedCounter) and counter.capped
        capped_any = capped_any or marked
        out.append("")
        out.append(title + (" [capped]" if marked else ""))
        out += [f"  {template.format(key=key, n=n)}"
                for key, n in counter.most_common(10)]

    if capped_any:
        out.append("")
        out.append("[capped] means the tally outgrew its key limit and the long "
                   "tail was dropped.")
        out.append("Rare entries are missing, and anything that reappeared after "
                   "being dropped is undercounted.")
        out.append("Raise COUNTER_CAP if you need these lists to be exact.")
    return out


def open_log(filename: str):
    """Open a log for reading, transparently decompressing gzip.

    Detection is by the gzip magic number rather than the file name, since
    rotated logs are named every possible way. ``errors="replace"`` means one
    bad byte cannot kill the run.
    """
    with open(filename, "rb") as probe:
        compressed = probe.read(2) == b"\x1f\x8b"
    opener = gzip.open if compressed else open
    return opener(filename, "rt", encoding="utf-8", errors="replace")


def run(input_filename: str, output_filename: Optional[str],
        bad_filename: str, use_gzip: bool = False,
        detect_sample: int = DETECT_SAMPLE,
        redact: Callable[[str], str] = keep,
        cap: float = COUNTER_CAP,
        assume_tz: Optional[str] = None,
        reference_time: Optional[datetime] = None) -> Stats:
    """Parse ``input_filename``, optionally write a CSV, and return the stats.

    The CSV is built under a temporary name and swapped into place only on
    success, so a crash partway leaves any previous CSV untouched and takes
    its own temporary file with it.

    ``redact`` is applied to parsed records and to skipped lines alike, so an
    address cannot reach one output while being masked in the other.

    The bad-lines file is opened only if there is something to put in it: a
    run that skips nothing leaves any previous copy alone rather than
    truncating it.

    ``assume_tz`` and ``reference_time`` apply to this call only. Year-less
    syslog dates are read against ``reference_time``, which defaults to the
    file's own modification time so that an old rotated log is not dragged
    forward into the current year.
    """
    stats = Stats(cap=cap)
    temp_filename = f"{output_filename}.tmp" if output_filename else None

    if reference_time is None:
        try:
            reference_time = datetime.fromtimestamp(
                os.path.getmtime(input_filename))
        except OSError:
            reference_time = None

    try:
        with configured(assume_tz=assume_tz, reference_time=reference_time), \
                ExitStack() as stack:
            infile = stack.enter_context(open_log(input_filename))
            badfile = None

            sample = [line.strip()
                      for _, line in zip(range(detect_sample), infile)]
            parsers = detect_order(
                [s for s in sample if s and not s.startswith("#")])
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
                    if badfile is None:
                        badfile = stack.enter_context(
                            open(bad_filename, "w", encoding="utf-8"))
                    badfile.write(f"line {lineno}: {redact(raw)}\n")
                    continue
                # Mask before the record is tallied, so the summary's top-IP
                # and probe listings show the same masked form the CSV does.
                record.ip = redact(record.ip)
                record.url = redact(record.url)
                stats.add(record)
                if writer is not None:
                    writer.writerow(record.as_row())
    except BaseException:
        # Including KeyboardInterrupt: an abandoned run should not leave a
        # half-written .tmp behind for someone to find later and wonder about.
        if temp_filename and os.path.exists(temp_filename):
            try:
                os.remove(temp_filename)
            except OSError:
                pass
        raise

    if output_filename:
        os.replace(temp_filename, output_filename)
    return stats


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------

def non_negative(text: str) -> int:
    """argparse type for counts that cannot sensibly be negative."""
    value = int(text)
    if value < 0:
        raise argparse.ArgumentTypeError("must be 0 or greater")
    return value


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="parse_logs.py",
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
    parser.add_argument("--redact", "--anonymise-ips", "--anonymize-ips",
                        dest="redact", action="store_true",
                        help="mask addresses and obvious secrets in every "
                             "output (CSV, summary, and skipped-lines file): "
                             f"IPv4 to /{IPV4_MASK_BITS}, IPv6 to "
                             f"/{IPV6_MASK_BITS}, e-mail local parts, and "
                             "credential-shaped key=value pairs")
    parser.add_argument("--assume-tz", default="", metavar="OFFSET",
                        help="offset to assume for timestamps with no zone, "
                             "e.g. +0200 or Z (default: leave them as written)")
    parser.add_argument("--counter-cap", type=non_negative, default=COUNTER_CAP,
                        metavar="N",
                        help=f"key limit for the per-IP and per-URL tallies "
                             f"(default: {COUNTER_CAP}; 0 removes the limit so "
                             f"unique counts are exact, at the cost of memory)")
    parser.add_argument("--version", action="version",
                        version=f"%(prog)s {__version__}")
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = build_parser().parse_args(argv)

    if not os.path.isfile(args.logfile):
        print(f"Error: could not find '{args.logfile}'.", file=sys.stderr)
        return 1

    assume_tz = ""
    if args.assume_tz:
        assume_tz = normalise_offset(args.assume_tz)
        if not assume_tz:
            print(f"Error: '{args.assume_tz}' is not a usable offset. "
                  f"Use +HHMM, +HH:MM, or Z, within -1200 to +1400.",
                  file=sys.stderr)
            return 1

    output = None if args.no_csv else args.output
    if output and args.gzip:
        output += ".gz"

    print(f"Starting log parsing on '{args.logfile}'...")
    if args.redact:
        print(f"Redacting: IPv4 to /{IPV4_MASK_BITS}, IPv6 to "
              f"/{IPV6_MASK_BITS}, zone IDs dropped, e-mail local parts and "
              f"credential values masked.")
    if assume_tz:
        print(f"Assuming {assume_tz} for timestamps with no zone.")

    stats = run(args.logfile, output, args.skipped, use_gzip=args.gzip,
                redact=anonymise if args.redact else keep,
                cap=math.inf if args.counter_cap == 0 else args.counter_cap,
                assume_tz=assume_tz or None)

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
