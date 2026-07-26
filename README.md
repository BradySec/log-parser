# log_parser

A log parser that works out the format of each line for itself.

Point it at an access log, an application log, or a mixture of both. It detects
the format, normalises everything into one consistent shape, writes a CSV, and
prints a summary that stays one screen long no matter how big the input is.

```
$ python parse_logs.py access.log
Starting log parsing on 'access.log'...
Parsed 100 log lines. Saved results to 'parsed_logs.csv'.

--- Summary ---
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

```bash
git clone <your-repo-url>
cd log_parser
python parse_logs.py --help
```

`parse_logs.py` is a thin entry point; the logic lives in `log_parser.py`, which
you can import directly:

```python
from log_parser import parse_line, run, make_anonymiser

record = parse_line('127.0.0.1 - - [10/Oct/2000:13:55:36 -0700] "GET / HTTP/1.1" 200 2326')
print(record.status, record.url)          # 200 /

stats = run("access.log", "out.csv", "bad.log",
            anonymise=make_anonymiser("truncate"))
print(stats.parsed, stats.error_rate("5xx"))
```

---

## Usage

```bash
python parse_logs.py access.log                  # parse, write parsed_logs.csv
python parse_logs.py access.log --gzip           # write parsed_logs.csv.gz
python parse_logs.py access.log --no-csv         # summary only
python parse_logs.py access.log -o results.csv   # custom output path
python parse_logs.py access.log --anonymise-ips truncate   # strip client IPs
python parse_logs.py                             # defaults to server.log
python -m log_parser access.log                  # equivalent to the above
```

| Flag | Effect |
| --- | --- |
| `logfile` | File to read. Positional, defaults to `server.log`. |
| `-o`, `--output` | CSV to write. Defaults to `parsed_logs.csv`. |
| `--skipped` | Where unparseable lines are recorded. Defaults to `skipped_lines.log`. |
| `--no-csv` | Print the summary only; write no CSV. |
| `--gzip` | Compress the CSV, appending `.gz` to its name. |
| `--anonymise-ips` | `none` (default), `truncate` or `hash`. See below. |
| `--salt` | Salt for `hash` mode. Random per run if omitted. |
| `--version` | Print the version and exit. |

Exit code is `0` on success and `1` if the input file does not exist.

---

## Supported formats

Every line is tested against these in turn. The first match wins.

| Name | Shape | Example |
| --- | --- | --- |
| `json` | One JSON object per line | `{"timestamp":"...","status_code":500,...}` |
| `combined` | Apache/Nginx combined | `1.2.3.4 - - [10/Oct/2000:13:55:36 -0700] "GET / HTTP/1.1" 200 2326 "-" "curl/8.0"` |
| `common` | Apache/Nginx common | same, without the referrer and agent |
| `fixed8` | `DATE TIME LEVEL IP METHOD URL STATUS 123ms` | `2026-07-26 02:51:28 INFO 10.0.0.5 GET /index.html 200 143ms` |
| `generic` | `TIMESTAMP LEVEL message` | `Jul 26 02:51:31 WARN slow for 172.16.0.4 GET /checkout status=503 took 1450 ms` |

The order matters: JSON is unambiguous, `combined`/`common`/`fixed8` are strict,
and `generic` is the loosest, so it goes last and only sees what the others
rejected. A test asserts that no pattern ever claims another format's line.

Notes on the edges:

- **Bracketed dates are free-form.** Anything inside `[...]` is handed to the
  timestamp parser, so non-standard styles like `[Jul 30 2026 at 05:12:34]`
  work alongside the Apache standard `[10/Oct/2000:13:55:36 -0700]`.
- **CLF timing tails** are picked up if your server appends them
  (`... "curl/8.0" 0.250 s`).
- **JSON key names vary by producer**, so aliases are mapped: `remote_addr`,
  `client_ip` and `host` all become `IP`; `status_code`, `response_code` and
  `code` all become `Status`; `latency`, `duration_ms` and `took_ms` all become
  `DurationMS`. See `JSON_KEYS` to add your own.
- **`generic` guesses.** It takes the first IP-looking string in the message,
  which for a line naming several hosts may not be the client. It is a fallback,
  not a precise parser.

Anything matching nothing at all is written to `skipped_lines.log` with its
line number, so a bad log is diagnosable rather than merely absent.

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
| `Bytes` | Response size. A `-` in the log becomes `0` |
| `Format` | Which parser handled the row — useful for spotting misdetection |

Timestamps carrying an offset are converted to UTC and the offset preserved, so
logs collected across regions sort correctly against each other.

### Summary

- **Formats detected** — a breakdown by parser. If you expected one format and
  see two, something upstream changed.
- **Mean response** — averaged over lines that actually have a duration, not
  over all lines. Reports `n/a` rather than `0.0` when nothing is timed.
- **Client errors (4xx) / Server errors (5xx)** — as a percentage of lines that
  carry a status. 4xx is the client's fault and mostly noise; 5xx is yours.
- **Top IPs probing suspicious paths** — 4xx and 5xx hits on paths only a
  scanner asks for (`.env`, `.git`, `wp-login`, `phpmyadmin` and friends; see
  `SUSPICIOUS_PATHS`). This is someone testing you.
- **Top 4xx on real paths** — the same failures on ordinary URLs, which are
  broken links worth fixing. Separating the two is the point: mixed together,
  scanner noise buries the actionable errors.
- **Top IPs / URLs** — ordinary traffic distribution.

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
- **Anonymise or pseudonymise when you can**, using `--anonymise-ips`. For
  traffic analysis you rarely need full addresses. See the next section.
- **Share summaries, not rows.** The `--no-csv` summary contains aggregates plus
  a top-10 of IPs. Dropping that section leaves output that is not personal data
  at all and is safe to paste into a ticket or chat.
- **Record the processing.** If this runs as a scheduled job it is a processing
  activity, and belongs in your Art. 30 records with its purpose and retention
  period.

### Anonymising IPs

Off by default: an incident investigation needs full addresses, so the tool
reproduces whatever the source log contains unless you ask otherwise. Both modes
rewrite addresses before they reach the CSV, the summary **or**
`skipped_lines.log`, so no raw address survives anywhere in the output. A test
asserts exactly that.

```bash
python parse_logs.py access.log --anonymise-ips truncate
python parse_logs.py access.log --anonymise-ips hash
python parse_logs.py access.log --anonymise-ips hash --salt "$IP_SALT"
```

| Mode | `192.168.239.106` becomes | Keeps | Loses |
| --- | --- | --- | --- |
| `truncate` | `192.168.239.0` | Network and rough geography | Per-client counts within a /24 |
| `hash` | `ip_2ce89e8c372d` | Per-client counts, exactly | Any network or geographic meaning |

**`truncate`** zeroes the host portion: IPv4 to a /24, IPv6 to a /48. This is the
usual analytics recipe and the stronger of the two, because the discarded bits
are gone rather than merely obscured. Hostnames, which some servers log instead
of addresses, have no meaningful network portion, so they are hashed instead of
passed through.

**`hash`** is a salted HMAC-SHA256, truncated to 12 hex characters. Distinct
clients stay distinct, so probe detection and top-IP counts remain exact — the
right choice when you need to know *that* one client hit you 4,000 times but not
*who* they are.

Two things to understand about `hash`:

- **It is pseudonymisation, not anonymisation.** The data stays in scope under
  the GDPR. IPv4 is only ~4.3 billion values, so anyone holding the salt can
  recover every address by brute force in minutes. **Treat the salt as a
  secret** — it belongs in a secrets manager, not in a shell history or a
  scheduled job's command line.
- **The salt is random per run unless you supply one.** That is deliberate:
  random salts prevent correlating one day's output against another's. Supply a
  fixed `--salt` only when you genuinely need to track a client across runs, and
  accept that a long-lived salt weakens the pseudonym over time.

Neither mode touches URLs. A path with an email address or token in the query
string is still personal data, and this tool will not save you from that.

None of the above is legal advice. Your DPO or counsel decides what your
organisation actually needs.

---

## Design notes

**The CSV is written atomically.** Output goes to a `.tmp` file that is only
swapped into place with `os.replace()` once the run completes. A crash partway
leaves any previous CSV untouched rather than half-overwritten. There is a test
for this.

**Format detection is sampled.** The first 50 lines decide which parser to try
first, so a uniform file avoids up to three failed regex attempts per line. The
order is a performance hint only — results are identical either way, which is
also tested.

**Counters are capped.** A log with millions of unique URLs would grow the
tallies without bound, so `CappedCounter` prunes its long tail past 200,000
keys. Counts for surviving keys stay exact; only entries too rare to ever
appear in a top-10 are dropped.

**Decoding never fails the run.** Input is read with `errors="replace"`, so one
bad byte costs one line rather than the whole job.

---

## Testing

```bash
python -m unittest -v          # 64 tests
python -m unittest test_parse_logs.TestParsers    # one class
```

The suite covers timestamp handling across formats and offsets, unit
conversion, each parser against a realistic sample line, cross-format
contamination, counter pruning, the statistics maths, both anonymisation modes
including a leak check across every output file, and end-to-end runs covering
gzip output, binary junk, and the atomic-write guarantee. No network
or fixture files needed — samples are inline and temp files are used throughout.

---

## Extending it

**To add a format:** write a function taking a stripped line and returning a
`Record` or `None`, then add it to `PARSERS`. Put loose patterns last. Add a
sample line to `SAMPLES` in the test file and the shared tests will cover it
automatically.

**To recognise more JSON keys:** add aliases to `JSON_KEYS`.

**To change what counts as a probe:** edit `SUSPICIOUS_PATHS`.

---

## Limitations

- Multi-line entries such as stack traces are not joined; each line is judged
  alone, so continuation lines land in `skipped_lines.log`.
- The `generic` parser infers fields from prose and can pick the wrong IP.
- Timestamps without a year (syslog style) inherit the current year, which is
  wrong for logs that span a New Year boundary.
- Everything is a single pass in one process. It is I/O-bound and fine for
  large files, but there is no parallelism.

---

## Project structure

```
log_parser.py         the library: parsers, stats, anonymisation, CLI
parse_logs.py         entry point, calls log_parser.main()
test_parse_logs.py    unittest suite
README.md             this file
.gitignore
```

The split follows the usual convention: a noun for the importable module, a verb
for the thing you run. Both names work, so existing `parse_logs.py` invocations
keep going.
