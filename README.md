# LOG PARSER

A log parser that works out the format of each line for itself.

Point it at an access log, an application log, or a mixture of both. It detects
the format, normalises everything into one consistent shape, writes a CSV, and
prints a summary that stays one screen long no matter how big the input is.

```
$ python3 parse_logs.py access.log
Starting log parsing on 'access.log'...
Parsed 100 log lines. Saved results to 'parsed_logs.csv'.

--- Summary ---

!! 2 SUCCESSFUL requests to suspicious paths (of 14 attempted) - investigate first:
       2  200 GET /.env from 203.0.113.9

Formats detected    : combined (100)
Unique IPs          : 100
Mean response       : n/a (no durations in this log)
Client errors (4xx) : 29.0%
Server errors (5xx) : 7.0%
...
```

---

## Why it exists

Most log scripts are written against one exact layout, usually with
`line.split()` and fixed positions. The moment the real log differs — a
timestamp containing spaces, a missing field, a different date style — every
line fails the shape check and the parser silently reports nothing.

This version tries several patterns per line instead of assuming one, and
treats every field as optional. A log with no durations still parses; it just
reports `n/a` for the mean instead of dividing by zero.

---

## Requirements

Python 3.9 or newer. No third-party packages — standard library only.
Developed and tested against 3.12.

```bash
git clone <your-repo-url>
cd parse_logs
python3 parse_logs.py --help
```

Everything lives in `parse_logs.py`, which is both the entry point and the
importable module:

```python
from parse_logs import parse_line, run, anonymise

record = parse_line('127.0.0.1 - - [10/Oct/2000:13:55:36 -0700] "GET / HTTP/1.1" 200 2326')
print(record.status, record.url)          # 200 /

stats = run("access.log", "out.csv", "bad.log", redact=anonymise)
print(stats.parsed, stats.error_rate("5xx"))
```

`run()` takes its configuration as arguments — `redact`, `cap`, `assume_tz`,
`reference_time` — and restores any process-wide state when it returns, so
calling it in a loop over rotated files behaves the same as calling it once.

---

## Usage

```bash
python3 parse_logs.py access.log                 # parse, write parsed_logs.csv
python3 parse_logs.py access.log.gz              # compressed input, read directly
python3 parse_logs.py access.log --gzip          # write parsed_logs.csv.gz
python3 parse_logs.py access.log --no-csv        # summary only
python3 parse_logs.py access.log -o results.csv  # custom output path
python3 parse_logs.py access.log --redact        # strip client IPs and secrets
python3 parse_logs.py access.log --assume-tz +0200
python3 parse_logs.py                            # defaults to server.log
```

| Flag | Effect |
| --- | --- |
| `logfile` | File to read. Positional, defaults to `server.log`. Gzip is detected from the file's first bytes, not its name. |
| `-o`, `--output` | CSV to write. Defaults to `parsed_logs.csv`. |
| `--skipped` | Where unparseable lines are recorded. Defaults to `skipped_lines.log`. |
| `--no-csv` | Print the summary only; write no CSV. |
| `--gzip` | Compress the CSV, appending `.gz` to its name. |
| `--redact` | Mask addresses and obvious secrets everywhere. Off by default. Also accepted as `--anonymise-ips` / `--anonymize-ips`. |
| `--assume-tz` | Offset to assume for timestamps carrying no zone, e.g. `+0200` or `Z`. Default: leave them as written. |
| `--counter-cap` | Key limit for the per-IP and per-URL tallies. Default 200,000; `0` removes the limit. |
| `--version` | Print the version and exit. |

Exit code is `0` on success and `1` if the input file does not exist or an
option is malformed.

---

## Supported formats

Every line is tested against these in turn. The first match wins.

| Name | Shape | Example |
| --- | --- | --- |
| `json` | One JSON object per line | `{"timestamp":"...","status_code":500,...}` |
| `combined` | Apache/Nginx combined | `1.2.3.4 - - [10/Oct/2000:13:55:36 -0700] "GET / HTTP/1.1" 200 2326 "-" "curl/8.0"` |
| `common` | Apache/Nginx common | same, without the referrer and agent |
| `fixed8` | `DATE TIME[ZONE] LEVEL IP METHOD URL STATUS 123ms` | `2026-07-26 02:51:28 INFO 10.0.0.5 GET /index.html 200 143ms` |
| `generic` | `TIMESTAMP LEVEL message` | `Jul 26 02:51:31 WARN slow for 172.16.0.4 GET /checkout status=503 took 1450 ms` |

The order matters: JSON is unambiguous, `combined`/`common`/`fixed8` are strict,
and `generic` is the loosest, so it goes last and only sees what the others
rejected. A test asserts that the three strict parsers never claim another
format's line. `generic` is deliberately not held to that: it matches anything
with a timestamp and a level, including a well-formed `fixed8` line, which is
exactly why it is last and why format detection pins it there.

Notes on the edges:

- **Bracketed dates are free-form.** Anything inside `[...]` is handed to the
  timestamp parser, so non-standard styles like `[Jul 30 2026 at 05:12:34]`
  work alongside the Apache standard `[10/Oct/2000:13:55:36 -0700]`.
- **CLF timing tails** are picked up if your server appends them
  (`... "curl/8.0" 0.250 s`).
- **`fixed8` may carry a zone** — `+0200`, `+02:00`, `Z` or `UTC` after the
  time — and is normalised to UTC like every other format.
- **JSON key names vary by producer**, so aliases are mapped: `remote_addr`,
  `client_ip` and `host` all become `IP`; `status_code`, `response_code` and
  `code` all become `Status`; `latency`, `duration_ms` and `took_ms` all become
  `DurationMS`. See `JSON_KEYS` to add your own.
- **`generic` guesses.** It takes the first IP-looking string in the message,
  which for a line naming several hosts may not be the client. It is a fallback,
  not a precise parser.

Anything matching nothing at all is written to `skipped_lines.log` with its
line number, so a bad log is diagnosable rather than merely absent. That file is
opened only when there is something to put in it, so a clean run leaves the
previous one intact.

---

## Output

### CSV columns

| Column | Notes |
| --- | --- |
| `Date`, `Time` | Normalised to `YYYY-MM-DD` and `HH:MM:SS`, in UTC |
| `TZ` | The original UTC offset, e.g. `-0700`. Empty if the log had none |
| `Level` | Uppercased. Empty for access logs, which carry no level |
| `IP`, `Method`, `URL` | Empty when the format does not supply them |
| `Status` | Integer, or empty for lines with no status |
| `DurationMS` | Whole milliseconds. Seconds are converted; empty if absent |
| `Bytes` | Response size. A `-` in the log becomes empty, not `0` — the server did not record a size, which is not the same as sending nothing |
| `Format` | Which parser handled the row — useful for spotting misdetection |

Timestamps carrying an offset are converted to UTC and the offset preserved, so
logs collected across regions sort correctly against each other. This applies to
every format, `fixed8` included. Offsets outside the range real zones occupy
(−12:00 to +14:00) are rejected rather than applied.

A timestamp with no zone cannot be normalised by anyone — nothing in the file
says what clock it was written on — so it is left as written with an empty `TZ`.
Use `--assume-tz` when you know the answer. Sorting the CSV by `TZ` shows you
immediately whether you have such rows.

### Summary

- **Successful probes** — requests for scanner paths that were *served* rather
  than refused, listed first with status, method, path and source. A 200 on
  `/.env` is the one finding here that may mean a live compromise rather than
  background noise.
- **Formats detected** — a breakdown by parser. If you expected one format and
  see two, something upstream changed.
- **Mean response, median and p95** — over lines that actually have a duration,
  not over all lines. Reports `n/a` rather than `0.0` when nothing is timed. The
  percentiles come from a bounded sample and say so once that sample overflows.
- **Client errors (4xx) / Server errors (5xx)** — as a percentage of lines that
  carry a status. 4xx is the client's fault and mostly noise; 5xx is yours.
- **Top IPs probing suspicious paths** — every request for a path only a scanner
  asks for (`.env`, `.git`, `wp-login`, `phpmyadmin` and friends; see
  `SUSPICIOUS_SEGMENTS`), whatever it returned. A 4xx is a probe that bounced;
  anything else is one that landed.
- **Top 4xx on real paths** — the same failures on ordinary URLs, which are
  broken links worth fixing. Separating the two is the point: mixed together,
  scanner noise buries the actionable errors.
- **Top IPs / URLs** — ordinary traffic distribution.

Paths are matched by whole segment, not by substring, so `/docs/.environment`
and `/blog/using.gitlab-ci` are not mistaken for scans. Percent-encoded and
backslash forms still are.

Sections whose tallies hit the key cap are marked `[capped]`, and the unique-IP
figure is then reported as a range rather than a number the counter cannot
support. Use `--counter-cap 0` when you need it exact.

---

## Privacy and data protection

Server logs are personal data. Under the GDPR an IP address identifies a person
either directly or in combination with other information, and the CJEU
confirmed in *Breyer* (C-582/14) that this includes dynamic IPs when the
operator has lawful means to identify the subscriber. User agent strings add to
that picture. Everything below applies equally to the UK GDPR, and similar
duties exist under CCPA/CPRA, LGPD and PIPEDA.

This matters here because **the CSV this tool produces inherits the status of
the log it read.** `parsed_logs.csv` is a new copy of the same personal data, in
a more portable form, usually somewhere less protected than the original — a
laptop, a shared drive, an email attachment. `skipped_lines.log` holds raw
lines, so it carries the same content.

Practical points if you run this on production logs:

- **Have a lawful basis.** Security monitoring and troubleshooting normally rest
  on legitimate interests (Art. 6(1)(f)), which requires a balancing assessment
  you should be able to show, not merely assert.
- **Keep it in your retention schedule.** Storage limitation (Art. 5(1)(e))
  applies to derived files too. A CSV that outlives the log it came from is a
  compliance gap. Delete outputs when the analysis is done.
- **Never commit logs or outputs to version control.** Git history is
  effectively permanent and widely copied, which makes erasure requests
  (Art. 17) painful. The supplied `.gitignore` blocks `*.log`,
  `parsed_logs.csv*` and `skipped_lines.log` for this reason.
- **Redact when you can**, using `--redact`. For traffic analysis you rarely
  need full addresses. See the next section.
- **Share summaries, not rows.** The `--no-csv` summary contains aggregates plus
  a top-10 of IPs. Dropping that section leaves output that is not personal data
  at all and is safe to paste into a ticket or chat.
- **Record the processing.** If this runs as a scheduled job it is a processing
  activity, and belongs in your Art. 30 records with its purpose and retention
  period.

### Redacting

Off by default: an incident investigation needs full addresses, so the tool
reproduces whatever the source log contains unless you ask otherwise.

`--redact` rewrites text on its way to every output — the CSV, the printed
summary **and** `skipped_lines.log` — rather than masking parsed fields. That
distinction is the whole point: skipped lines never become a parsed record, and
a malformed address is a common reason a line fails to parse, so field-level
masking would systematically miss the addresses most in need of it. A test
asserts no raw address survives in any output file.

| What | `203.0.113.47` / `2001:db8:1:2::5` becomes | Keeps | Loses |
| --- | --- | --- | --- |
| IPv4 | `203.0.113.0` (a /24) | Network and rough geography | Per-client counts within a /24 |
| IPv6 | `2001:db8:1::` (a /48) | Routing prefix | Per-client counts within a /48 |

Also masked: e-mail local parts (`jane@corp.com` → `***@corp.com`, domain kept
for triage), `Bearer` and `Basic` credentials, and credential-shaped
`key=value` pairs — `token`, `session`, `api_key`, `password`, `signature` and
similar. Brackets and ports on IPv6 addresses survive; zone IDs are dropped.
IPv4-mapped addresses are masked inside the mapping, so `::ffff:203.0.113.47`
becomes `::ffff:203.0.113.0` rather than collapsing to a bare `::`.

Two things to understand:

- **Truncation aggregates clients.** Everything on one /24 or /48 becomes one
  key, so per-IP probe counts and top-IP rankings stop being per-client after
  redaction. A residential /48 can be a whole household. There is no mode that
  preserves per-client counts while hiding identity; if you need that, see
  *Not implemented* below.
- **It is best-effort.** It knows about addresses, e-mail local parts and the
  key names in `SECRET_KV_RE`. A log carrying identifiers in some other shape —
  a customer number, a session ID under an unusual name, a token in a URL path —
  still carries them afterwards. Spot-check `skipped_lines.log` before sharing
  it.

Neither redaction nor anything else here touches URL *paths*. A path with an
email address or token in it is still personal data, and this tool will not save
you from that.

None of the above is legal advice. Your DPO or counsel decides what your
organisation actually needs.

---

## Design notes

**The CSV is written atomically.** Output goes to a `.tmp` file that is only
swapped into place with `os.replace()` once the run completes. A crash partway
leaves any previous CSV untouched rather than half-overwritten, and removes its
own temporary file on the way out. There are tests for both.

**Format detection is sampled.** The first 50 lines decide which of the strict
parsers to try first, so a uniform file avoids up to three failed regex attempts
per line. `parse_generic` is pinned last regardless of what the sample says,
because it matches almost anything: promoting it would let it swallow lines a
stricter parser would have read properly. With that pin the order is a pure
performance hint — results are identical either way, which is tested.

**Counters are capped, and say when they are.** A log with millions of unique
URLs would grow the tallies without bound, so `CappedCounter` prunes its long
tail past 200,000 keys. Counts for surviving keys stay exact. Past the cap the
unique-IP figure becomes a range rather than a number, because `len()` is then
the number of keys *held*, not the number seen.

**Percentiles come from a reservoir.** Exact percentiles need every value;
holding a few million integers is avoidable, so past 50,000 durations the sample
becomes a uniform random subset and the summary labels the result an estimate.

**Year-less dates are read against the file's age.** Syslog omits the year, so
the log file's modification time supplies it, stepping back one year if that
would place a line in the future. A December line parsed in January belongs to
the year it was written.

**Decoding never fails the run.** Input is read with `errors="replace"`, so one
bad byte costs one line rather than the whole job.

---

## Testing

```bash
python3 -m unittest test_parse_logs -v                   # 59 tests
python3 -m unittest test_parse_logs.TestTimestamps       # one class
```

The suite covers timestamp handling across formats and offsets, unit
conversion, each parser against a realistic sample line, cross-format
contamination, detection-order invariance, counter pruning and its bounds,
percentile sampling, redaction including a leak check across every output file,
configuration isolation between runs, and end-to-end runs covering gzip input
and output, binary junk, the atomic-write guarantee and temporary-file cleanup.
No network or fixture files needed — samples are inline and temp files are used
throughout.

Every test corresponds to a defect that was actually found. Each was checked by
reintroducing the original bug and confirming the suite fails, so the coverage
is against real defects rather than against whatever the code happens to do now.

---

## Extending it

**To add a format:** write a function taking a stripped line and returning a
`Record` or `None`, then add it to `PARSERS`. Put loose patterns last. Add a
sample line to `SAMPLES` in the test file and the shared tests will cover it
automatically.

**To recognise more JSON keys:** add aliases to `JSON_KEYS`.

**To change what counts as a probe:** edit `SUSPICIOUS_SEGMENTS` for single path
components and `SUSPICIOUS_SEQUENCES` for multi-segment ones.

**To change how much of an address survives redaction:** edit `IPV4_MASK_BITS`
and `IPV6_MASK_BITS`. Widening the IPv6 value to 64 separates households on a
residential prefix, at the cost of some anonymity.

---

## Not implemented

- **A hash / pseudonymisation mode.** There is no `--salt` and no HMAC option,
  so there is currently no way to keep distinct clients distinct while hiding
  who they are. Truncation is the only mode.
- **A `log_parser.py` / `parse_logs.py` module split.** Everything is one file;
  `python -m log_parser` does not work.

---

## Limitations

- Multi-line entries such as stack traces are not joined; each line is judged
  alone, so continuation lines land in `skipped_lines.log`.
- The `generic` parser infers fields from prose and can pick the wrong IP.
- Timestamps with no zone cannot be reconciled without `--assume-tz`.
- Throughput is around 26,000 lines a second (37 MB peak on a 200,000-line
  file). Fine for a day of traffic; a 50-million-line archive is about half an
  hour. The regex-per-line design is the ceiling.
- Everything is a single pass in one process. It is I/O-bound and fine for
  large files, but there is no parallelism.
- No real-world log has been through it. Every test fixture was written to
  reproduce a known bug, which cannot surface a format quirk nobody
  anticipated. The `skipped_lines.log` count on one of your own files is the
  honest measure.

---

## Project structure

```
parse_logs.py         parsers, stats, redaction, CLI — the whole tool
test_parse_logs.py    unittest suite
README.md             this file
RELEASE.md            release notes
.gitignore
```