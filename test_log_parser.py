"""Test suite for log_parser.py. Run with: python -m unittest -v"""

import csv
import gzip
import os
import tempfile
import unittest
from datetime import datetime

import log_parser as lp


# --------------------------------------------------------------------------
# Sample lines, one realistic example per supported format.
# --------------------------------------------------------------------------

SAMPLES = {
    "combined": '192.168.239.106 - - [Jul 30 2026 at 05:12:34] "PUT /contact '
                'HTTP/1.1" 404 9655 "-" "Mozilla/5.0 (X11; Linux x86_64)"',
    "common":   '127.0.0.1 - frank [10/Oct/2000:13:55:36 -0700] '
                '"GET /apache_pb.gif HTTP/1.0" 200 2326',
    "fixed8":   '2026-07-26 02:51:28 INFO 10.0.0.5 GET /index.html 200 143ms',
    "json":     '{"timestamp":"2026-07-26T02:51:30","level":"warn",'
                '"client_ip":"8.8.8.8","request":"GET /api/v2/users",'
                '"status_code":500,"duration_ms":812,"bytes":91}',
    "generic":  'Jul 26 02:51:31 WARN upstream slow for 172.16.0.4 '
                'GET /checkout status=503 took 1450 ms',
}


class TestTimestamps(unittest.TestCase):

    def test_apache_offset_converted_to_utc(self):
        date, time, tz = lp.split_timestamp("10/Oct/2000:13:55:36 -0700")
        self.assertEqual((date, time, tz), ("2000-10-10", "20:55:36", "-0700"))

    def test_positive_offset_converted_to_utc(self):
        date, time, tz = lp.split_timestamp("10/Oct/2000:13:55:36 +0200")
        self.assertEqual((date, time, tz), ("2000-10-10", "11:55:36", "+0200"))

    def test_offset_can_roll_the_date_backwards(self):
        date, time, _ = lp.split_timestamp("10/Oct/2000:01:00:00 +0200")
        self.assertEqual((date, time), ("2000-10-09", "23:00:00"))

    def test_named_zone_treated_as_utc(self):
        self.assertEqual(lp.split_timestamp("2026-07-26T02:51:30Z"),
                         ("2026-07-26", "02:51:30", "+0000"))

    def test_prose_style_date(self):
        self.assertEqual(lp.split_timestamp("Jul 30 2026 at 05:12:34"),
                         ("2026-07-30", "05:12:34", ""))

    def test_subseconds_dropped(self):
        self.assertEqual(lp.split_timestamp("2026-07-26 02:51:30.123"),
                         ("2026-07-26", "02:51:30", ""))

    def test_yearless_syslog_gets_current_year(self):
        stamp = datetime(2019, 1, 1)
        date, _, _ = lp.split_timestamp("Jul 26 02:51:31", now=stamp)
        self.assertTrue(date.startswith("2019-"))

    def test_unknown_layout_passes_through(self):
        date, time, _ = lp.split_timestamp("whenever o'clock")
        self.assertEqual(date, "whenever")
        self.assertEqual(time, "o'clock")

    def test_empty_is_safe(self):
        self.assertEqual(lp.split_timestamp(""), ("", "", ""))
        self.assertEqual(lp.split_timestamp(None), ("", "", ""))


class TestFieldHelpers(unittest.TestCase):

    def test_seconds_scaled_to_milliseconds(self):
        self.assertEqual(lp.to_milliseconds("0.250", "s"), 250)

    def test_milliseconds_rounded(self):
        self.assertEqual(lp.to_milliseconds("143.6", "ms"), 144)

    def test_unparseable_duration_is_none(self):
        self.assertIsNone(lp.to_milliseconds("fast", "ms"))
        self.assertIsNone(lp.to_milliseconds(None))
        self.assertIsNone(lp.to_milliseconds(""))

    def test_status_must_be_three_digits(self):
        self.assertEqual(lp.to_status("404"), 404)
        self.assertIsNone(lp.to_status("40"))
        self.assertIsNone(lp.to_status("okay"))

    def test_malformed_request_keeps_url(self):
        self.assertEqual(lp.split_request("garbage here"), ("", "garbage here"))

    def test_suspicious_paths_are_case_insensitive(self):
        self.assertTrue(lp.is_suspicious("/WP-LOGIN.php"))
        self.assertTrue(lp.is_suspicious("/.env"))
        self.assertFalse(lp.is_suspicious("/environment"))
        self.assertFalse(lp.is_suspicious(""))


class TestParsers(unittest.TestCase):

    def test_each_sample_detects_its_own_format(self):
        for name, line in SAMPLES.items():
            with self.subTest(format=name):
                record = lp.parse_line(line)
                self.assertIsNotNone(record, f"{name} failed to parse")
                self.assertEqual(record.format, name)

    def test_combined_fields(self):
        record = lp.parse_line(SAMPLES["combined"])
        self.assertEqual(record.ip, "192.168.239.106")
        self.assertEqual(record.method, "PUT")
        self.assertEqual(record.url, "/contact")
        self.assertEqual(record.status, 404)
        self.assertEqual(record.bytes, "9655")
        self.assertIsNone(record.duration_ms)

    def test_common_has_no_agent(self):
        record = lp.parse_line(SAMPLES["common"])
        self.assertEqual(record.format, "common")
        self.assertEqual(record.status, 200)

    def test_dash_bytes_becomes_zero(self):
        record = lp.parse_line(
            '1.2.3.4 - - [10/Oct/2000:13:55:36 -0700] "GET / HTTP/1.1" 304 -')
        self.assertEqual(record.bytes, "0")

    def test_clf_timing_tail(self):
        record = lp.parse_line(
            '203.0.113.9 - - [10/Oct/2000:13:55:40 -0700] "GET /.env HTTP/1.1" '
            '404 0 "-" "curl/8.0" 0.250 s')
        self.assertEqual(record.duration_ms, 250)

    def test_fixed8_bracketed_level(self):
        record = lp.parse_line(
            '2026-07-26 02:51:29 [ERROR] 10.0.0.6 POST /wp-login.php 403 12ms')
        self.assertEqual(record.level, "ERROR")
        self.assertEqual(record.duration_ms, 12)

    def test_json_level_normalised_to_upper(self):
        self.assertEqual(lp.parse_line(SAMPLES["json"]).level, "WARN")

    def test_json_request_field_split(self):
        record = lp.parse_line(SAMPLES["json"])
        self.assertEqual((record.method, record.url), ("GET", "/api/v2/users"))

    def test_json_key_aliases(self):
        record = lp.parse_line(
            '{"@timestamp":"2026-07-26 01:02:03","severity":"error",'
            '"remote_addr":"9.9.9.9","uri":"/x","response_code":"503",'
            '"latency":"1.5 s","body_bytes_sent":12}')
        self.assertEqual(record.ip, "9.9.9.9")
        self.assertEqual(record.status, 503)
        self.assertEqual(record.duration_ms, 1500)

    def test_json_non_object_rejected(self):
        self.assertIsNone(lp.parse_json('{"not": '))
        self.assertIsNone(lp.parse_json('[1, 2, 3]'))

    def test_generic_recovers_details_from_message(self):
        record = lp.parse_line(SAMPLES["generic"])
        self.assertEqual(record.ip, "172.16.0.4")
        self.assertEqual(record.url, "/checkout")
        self.assertEqual(record.status, 503)
        self.assertEqual(record.duration_ms, 1450)

    def test_garbage_returns_none(self):
        self.assertIsNone(lp.parse_line("this line is genuinely garbage !!!"))

    def test_no_parser_claims_another_formats_line(self):
        """Guards against a loose pattern silently swallowing another format."""
        for name, line in SAMPLES.items():
            for parser in lp.PARSERS:
                record = parser(line)
                if record is not None:
                    with self.subTest(format=name, parser=parser.__name__):
                        self.assertEqual(record.format, name)
                    break


class TestDetectOrder(unittest.TestCase):

    def test_dominant_format_moves_first(self):
        order = lp.detect_order([SAMPLES["fixed8"]] * 5)
        self.assertIs(order[0], lp.parse_fixed)

    def test_empty_sample_keeps_default_order(self):
        self.assertEqual(lp.detect_order([]), lp.PARSERS)

    def test_reordering_does_not_change_results(self):
        line = SAMPLES["combined"]
        reordered = lp.detect_order([line])
        self.assertEqual(lp.parse_line(line, reordered).url,
                         lp.parse_line(line).url)


class TestCappedCounter(unittest.TestCase):

    def test_prunes_the_long_tail(self):
        counter = lp.CappedCounter(cap=10, keep=3)
        for i in range(5):                       # heavy hitters
            for _ in range(20):
                counter.add(f"hot-{i}")
        for i in range(50):                      # long tail
            counter.add(f"cold-{i}")
        self.assertLessEqual(len(counter), 10)
        self.assertGreater(counter.pruned, 0)

    def test_heavy_hitters_survive_and_stay_exact(self):
        counter = lp.CappedCounter(cap=5, keep=2)
        for _ in range(30):
            counter.add("keep-me")
        for i in range(20):
            counter.add(f"tail-{i}")
        self.assertEqual(counter["keep-me"], 30)
        self.assertIn("keep-me", dict(counter.most_common(2)))


class TestStats(unittest.TestCase):

    def build(self, lines):
        stats = lp.Stats()
        for line in lines:
            record = lp.parse_line(line)
            self.assertIsNotNone(record)
            stats.add(record)
        return stats

    def test_mean_uses_only_timed_lines(self):
        stats = self.build([SAMPLES["combined"], SAMPLES["fixed8"]])
        self.assertEqual(stats.timed, 1)
        self.assertEqual(stats.mean_duration, 143)

    def test_mean_is_none_without_durations(self):
        self.assertIsNone(self.build([SAMPLES["combined"]]).mean_duration)

    def test_error_rate_divides_by_lines_with_a_status(self):
        stats = self.build([SAMPLES["combined"], SAMPLES["common"]])
        self.assertEqual(stats.error_rate("4xx"), 50.0)

    def test_probe_and_broken_link_split(self):
        stats = self.build([
            '2026-07-26 02:51:29 ERROR 10.0.0.6 GET /wp-login.php 403 12ms',
            '2026-07-26 02:51:30 ERROR 10.0.0.7 GET /contact 404 5ms',
        ])
        self.assertEqual(stats.probe_paths["/wp-login.php"], 1)
        self.assertEqual(stats.broken_links["/contact"], 1)
        self.assertNotIn("/wp-login.php", stats.broken_links)

    def test_5xx_is_not_a_broken_link(self):
        stats = self.build([SAMPLES["json"]])          # status 500
        self.assertFalse(stats.broken_links)
        self.assertEqual(stats.statuses["5xx"], 1)

    def test_summary_is_empty_when_nothing_parsed(self):
        self.assertEqual(lp.summarise(lp.Stats()), [])

    def test_summary_reports_missing_durations(self):
        text = "\n".join(lp.summarise(self.build([SAMPLES["combined"]])))
        self.assertIn("n/a", text)


class TestAnonymisation(unittest.TestCase):

    def test_ipv4_truncated_to_network(self):
        self.assertEqual(lp.truncate_ip("192.168.239.106"), "192.168.239.0")

    def test_ipv6_truncated_to_48_bits(self):
        self.assertEqual(lp.truncate_ip("2001:db8:85a3:1234::8a2e"),
                         "2001:db8:85a3::")

    def test_non_ip_is_not_truncatable(self):
        self.assertIsNone(lp.truncate_ip("web-03.internal"))

    def test_hash_is_stable_for_one_salt(self):
        self.assertEqual(lp.hash_ip("1.2.3.4", "pepper"),
                         lp.hash_ip("1.2.3.4", "pepper"))

    def test_hash_differs_by_salt(self):
        self.assertNotEqual(lp.hash_ip("1.2.3.4", "pepper"),
                            lp.hash_ip("1.2.3.4", "salt"))

    def test_hash_keeps_distinct_clients_distinct(self):
        self.assertNotEqual(lp.hash_ip("1.2.3.4", "s"), lp.hash_ip("1.2.3.5", "s"))

    def test_hash_does_not_contain_the_address(self):
        self.assertNotIn("1.2.3.4", lp.hash_ip("1.2.3.4", "s"))

    def test_none_mode_returns_no_anonymiser(self):
        self.assertIsNone(lp.make_anonymiser("none"))
        self.assertIsNone(lp.make_anonymiser(None))

    def test_truncate_mode_hashes_hostnames(self):
        anonymise = lp.make_anonymiser("truncate", salt="s")
        self.assertEqual(anonymise("10.0.0.9"), "10.0.0.0")
        self.assertTrue(anonymise("web-03.internal").startswith("ip_"))

    def test_empty_value_passes_through(self):
        self.assertEqual(lp.make_anonymiser("hash", salt="s")(""), "")

    def test_random_salt_differs_between_anonymisers(self):
        line = "8.8.8.8"
        self.assertNotEqual(lp.make_anonymiser("hash")(line),
                            lp.make_anonymiser("hash")(line))

    def test_redact_line_rewrites_every_address(self):
        anonymise = lp.make_anonymiser("truncate", salt="s")
        redacted = lp.redact_line("from 10.0.0.9 to 172.16.4.5 failed", anonymise)
        self.assertEqual(redacted, "from 10.0.0.0 to 172.16.4.0 failed")

    def test_redact_line_is_a_noop_without_an_anonymiser(self):
        self.assertEqual(lp.redact_line("10.0.0.9", None), "10.0.0.9")


class TestEndToEnd(unittest.TestCase):

    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.dir.cleanup)
        self.log = self.path("mixed.log")
        with open(self.log, "w") as handle:
            handle.write("# rotation header\n\n")
            handle.write("\n".join(SAMPLES.values()) + "\n")
            handle.write("this line is genuinely garbage !!!\n")

    def path(self, name):
        return os.path.join(self.dir.name, name)

    def test_all_formats_parse_and_garbage_is_recorded(self):
        stats = lp.run(self.log, self.path("out.csv"), self.path("bad.log"))
        self.assertEqual(stats.parsed, len(SAMPLES))
        self.assertEqual(stats.skipped, 1)
        self.assertEqual(set(stats.formats), set(SAMPLES))
        with open(self.path("bad.log")) as handle:
            self.assertIn("garbage", handle.read())

    def test_csv_header_and_row_widths_match(self):
        lp.run(self.log, self.path("out.csv"), self.path("bad.log"))
        with open(self.path("out.csv"), newline="") as handle:
            rows = list(csv.reader(handle))
        self.assertEqual(rows[0], list(lp.CSV_HEADERS))
        self.assertTrue(all(len(row) == len(lp.CSV_HEADERS) for row in rows[1:]))
        self.assertEqual(len(rows), len(SAMPLES) + 1)

    def test_gzip_output_is_readable(self):
        lp.run(self.log, self.path("out.csv.gz"), self.path("bad.log"),
               use_gzip=True)
        with gzip.open(self.path("out.csv.gz"), "rt") as handle:
            self.assertIn("Date,Time,TZ", handle.read())

    def test_no_csv_writes_nothing(self):
        stats = lp.run(self.log, None, self.path("bad.log"))
        self.assertEqual(stats.parsed, len(SAMPLES))
        self.assertFalse(os.path.exists(self.path("out.csv")))

    def test_previous_csv_survives_a_crash(self):
        target = self.path("out.csv")
        with open(target, "w") as handle:
            handle.write("previous,contents\n")

        original = lp.Stats.add
        def explode(self, record):
            raise RuntimeError("boom")
        lp.Stats.add = explode
        try:
            with self.assertRaises(RuntimeError):
                lp.run(self.log, target, self.path("bad.log"))
        finally:
            lp.Stats.add = original

        with open(target) as handle:
            self.assertEqual(handle.read(), "previous,contents\n")

    def test_invalid_bytes_do_not_kill_the_run(self):
        path = self.path("binary.log")
        with open(path, "wb") as handle:
            handle.write(SAMPLES["fixed8"].encode() + b"\n\xff\xfe bad bytes\n")
        stats = lp.run(path, None, self.path("bad.log"))
        self.assertEqual(stats.parsed, 1)
        self.assertEqual(stats.skipped, 1)

    def test_anonymisation_leaves_no_raw_ip_anywhere(self):
        """The CSV, the tallies and the skipped file must all be clean."""
        with open(self.log, "a") as handle:
            handle.write("unparseable junk from 192.168.239.106 here\n")

        csv_path, bad_path = self.path("out.csv"), self.path("bad.log")
        stats = lp.run(self.log, csv_path, bad_path,
                       anonymise=lp.make_anonymiser("truncate", salt="s"))

        raw_ips = ("192.168.239.106", "127.0.0.1", "10.0.0.5",
                   "8.8.8.8", "172.16.0.4")
        written = open(csv_path).read() + open(bad_path).read()
        written += "\n".join(lp.summarise(stats))
        for ip in raw_ips:
            with self.subTest(ip=ip):
                self.assertNotIn(ip, written)
        self.assertIn("192.168.239.0", written)

    def test_anonymisation_preserves_row_count(self):
        plain = lp.run(self.log, None, self.path("bad.log"))
        hashed = lp.run(self.log, None, self.path("bad2.log"),
                        anonymise=lp.make_anonymiser("hash", salt="s"))
        self.assertEqual(plain.parsed, hashed.parsed)
        self.assertEqual(len(plain.ips), len(hashed.ips))

    def test_cli_accepts_both_spellings(self):
        for flag in ("--anonymise-ips", "--anonymize-ips"):
            with self.subTest(flag=flag):
                args = lp.build_parser().parse_args([self.log, flag, "hash"])
                self.assertEqual(args.anonymise_ips, "hash")

    def test_missing_file_exits_nonzero(self):
        self.assertEqual(lp.main([self.path("nope.log"), "--no-csv"]), 1)

    def test_main_succeeds(self):
        self.assertEqual(lp.main([self.log, "--no-csv",
                                  "--skipped", self.path("bad.log")]), 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
