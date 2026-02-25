"""Unit tests for siem_report.py"""

import csv
import json
import os
import sys
import tempfile
import unittest
from collections import Counter

# Ensure the repo root is on the path so we can import siem_report directly
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import siem_report


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _write_csv(rows, fieldnames=None):
    """Write *rows* to a temp CSV file and return its path."""
    fh = tempfile.NamedTemporaryFile(
        mode="w", suffix=".csv", delete=False, newline=""
    )
    if fieldnames is None:
        fieldnames = list(rows[0].keys()) if rows else []
    writer = csv.DictWriter(fh, fieldnames=fieldnames)
    writer.writeheader()
    writer.writerows(rows)
    fh.close()
    return fh.name


SAMPLE_ROWS = [
    {
        "_time": "2026-02-25T08:01:12",
        "severity": "high",
        "src_ip": "203.0.113.45",
        "dest_ip": "10.0.1.20",
        "signature": "Exploit.ShellCode",
        "action": "blocked",
        "user": "",
    },
    {
        "_time": "2026-02-25T08:03:44",
        "severity": "critical",
        "src_ip": "198.51.100.7",
        "dest_ip": "10.0.1.15",
        "signature": "ET EXPLOIT Apache Log4j RCE",
        "action": "blocked",
        "user": "",
    },
    {
        "_time": "2026-02-25T08:05:10",
        "severity": "medium",
        "src_ip": "10.0.2.55",
        "dest_ip": "10.0.1.10",
        "signature": "4625 - Failed Logon",
        "action": "allowed",
        "user": "jsmith",
    },
    {
        "_time": "2026-02-25T09:00:00",
        "severity": "low",
        "src_ip": "10.0.2.10",
        "dest_ip": "10.0.1.10",
        "signature": "4624 - Successful Logon",
        "action": "allowed",
        "user": "sysadmin",
    },
]


# ---------------------------------------------------------------------------
# load_logs tests
# ---------------------------------------------------------------------------

class TestLoadLogs(unittest.TestCase):

    def test_load_valid_csv(self):
        path = _write_csv(SAMPLE_ROWS)
        try:
            logs = siem_report.load_logs(path)
            self.assertEqual(len(logs), len(SAMPLE_ROWS))
            self.assertIn("severity", logs[0])
        finally:
            os.unlink(path)

    def test_missing_file_raises(self):
        with self.assertRaises(FileNotFoundError):
            siem_report.load_logs("/nonexistent/path/file.csv")

    def test_empty_csv_raises(self):
        fh = tempfile.NamedTemporaryFile(
            mode="w", suffix=".csv", delete=False
        )
        fh.write("severity,src_ip\n")  # header only, no data rows
        fh.close()
        try:
            with self.assertRaises(ValueError):
                siem_report.load_logs(fh.name)
        finally:
            os.unlink(fh.name)

    def test_sample_log_file_loads(self):
        sample_path = os.path.join(
            os.path.dirname(__file__),
            "..",
            "sample_logs",
            "siem_events.csv",
        )
        logs = siem_report.load_logs(sample_path)
        self.assertGreater(len(logs), 0)


# ---------------------------------------------------------------------------
# analyze_logs tests
# ---------------------------------------------------------------------------

class TestAnalyzeLogs(unittest.TestCase):

    def setUp(self):
        self.metrics = siem_report.analyze_logs(SAMPLE_ROWS)

    def test_total_events(self):
        self.assertEqual(self.metrics["total_events"], len(SAMPLE_ROWS))

    def test_severity_counts(self):
        self.assertEqual(self.metrics["severity_counts"]["critical"], 1)
        self.assertEqual(self.metrics["severity_counts"]["high"], 1)
        self.assertEqual(self.metrics["severity_counts"]["medium"], 1)
        self.assertEqual(self.metrics["severity_counts"]["low"], 1)

    def test_top_src_ips(self):
        self.assertIn("203.0.113.45", self.metrics["top_src_ips"])
        self.assertIn("198.51.100.7", self.metrics["top_src_ips"])

    def test_top_event_types(self):
        self.assertIn("Exploit.ShellCode", self.metrics["top_event_types"])
        self.assertIn("4625 - Failed Logon", self.metrics["top_event_types"])

    def test_top_users(self):
        self.assertIn("jsmith", self.metrics["top_users"])
        self.assertIn("sysadmin", self.metrics["top_users"])
        # Empty user strings should be excluded
        self.assertNotIn("", self.metrics["top_users"])

    def test_action_counts(self):
        self.assertEqual(self.metrics["action_counts"]["blocked"], 2)
        self.assertEqual(self.metrics["action_counts"]["allowed"], 2)

    def test_hourly_counts_populated(self):
        self.assertGreater(len(self.metrics["hourly_counts"]), 0)

    def test_date_range(self):
        start, end = self.metrics["date_range"]
        self.assertIsNotNone(start)
        self.assertIsNotNone(end)
        self.assertLessEqual(start, end)

    def test_empty_logs(self):
        metrics = siem_report.analyze_logs([])
        self.assertEqual(metrics["total_events"], 0)
        self.assertEqual(len(metrics["severity_counts"]), 0)

    def test_dest_ip_counted(self):
        self.assertIn("10.0.1.20", self.metrics["top_dest_ips"])

    def test_sample_log_file_analysis(self):
        sample_path = os.path.join(
            os.path.dirname(__file__),
            "..",
            "sample_logs",
            "siem_events.csv",
        )
        logs = siem_report.load_logs(sample_path)
        metrics = siem_report.analyze_logs(logs)
        # Sample file has a mix of severities
        self.assertGreater(metrics["severity_counts"]["critical"], 0)
        self.assertGreater(metrics["severity_counts"]["high"], 0)
        self.assertGreater(metrics["total_events"], 40)


# ---------------------------------------------------------------------------
# generate_report tests
# ---------------------------------------------------------------------------

class TestGenerateReportText(unittest.TestCase):

    def setUp(self):
        self.metrics = siem_report.analyze_logs(SAMPLE_ROWS)

    def test_text_report_contains_header(self):
        report = siem_report.generate_report(self.metrics, output_format="text")
        self.assertIn("SPLUNK SIEM LOG ANALYSIS REPORT", report)

    def test_text_report_contains_total_events(self):
        report = siem_report.generate_report(self.metrics, output_format="text")
        self.assertIn(str(len(SAMPLE_ROWS)), report)

    def test_text_report_contains_severity_section(self):
        report = siem_report.generate_report(self.metrics, output_format="text")
        self.assertIn("Severity Distribution", report)
        self.assertIn("critical", report)
        self.assertIn("high", report)

    def test_text_report_contains_src_ip(self):
        report = siem_report.generate_report(self.metrics, output_format="text")
        self.assertIn("203.0.113.45", report)

    def test_text_report_contains_event_type(self):
        report = siem_report.generate_report(self.metrics, output_format="text")
        self.assertIn("Exploit.ShellCode", report)

    def test_text_report_contains_user(self):
        report = siem_report.generate_report(self.metrics, output_format="text")
        self.assertIn("jsmith", report)


class TestGenerateReportJson(unittest.TestCase):

    def setUp(self):
        self.metrics = siem_report.analyze_logs(SAMPLE_ROWS)

    def test_json_report_is_valid_json(self):
        report = siem_report.generate_report(self.metrics, output_format="json")
        data = json.loads(report)
        self.assertIsInstance(data, dict)

    def test_json_report_keys(self):
        report = siem_report.generate_report(self.metrics, output_format="json")
        data = json.loads(report)
        expected_keys = [
            "total_events",
            "severity_distribution",
            "top_source_ips",
            "top_destination_ips",
            "top_event_types",
            "top_users",
            "action_breakdown",
            "hourly_event_counts",
            "date_range",
        ]
        for key in expected_keys:
            self.assertIn(key, data, f"Missing key: {key}")

    def test_json_report_total_events(self):
        report = siem_report.generate_report(self.metrics, output_format="json")
        data = json.loads(report)
        self.assertEqual(data["total_events"], len(SAMPLE_ROWS))

    def test_json_report_severity_distribution(self):
        report = siem_report.generate_report(self.metrics, output_format="json")
        data = json.loads(report)
        self.assertIn("critical", data["severity_distribution"])
        self.assertEqual(data["severity_distribution"]["critical"], 1)

    def test_json_report_top_n_respected(self):
        # Add extra IPs so there are more than top_n=2
        rows = [
            dict(SAMPLE_ROWS[0], src_ip=f"1.2.3.{i}") for i in range(10)
        ]
        metrics = siem_report.analyze_logs(rows)
        report = siem_report.generate_report(metrics, top_n=2, output_format="json")
        data = json.loads(report)
        self.assertLessEqual(len(data["top_source_ips"]), 2)


# ---------------------------------------------------------------------------
# _parse_timestamp tests
# ---------------------------------------------------------------------------

class TestParseTimestamp(unittest.TestCase):

    def test_iso_format(self):
        dt = siem_report._parse_timestamp("2026-02-25T08:01:12")
        self.assertIsNotNone(dt)
        self.assertEqual(dt.hour, 8)
        self.assertEqual(dt.minute, 1)

    def test_space_separated_format(self):
        dt = siem_report._parse_timestamp("2026-02-25 09:30:00")
        self.assertIsNotNone(dt)
        self.assertEqual(dt.day, 25)

    def test_invalid_returns_none(self):
        dt = siem_report._parse_timestamp("not-a-timestamp")
        self.assertIsNone(dt)

    def test_empty_string_returns_none(self):
        dt = siem_report._parse_timestamp("")
        self.assertIsNone(dt)


if __name__ == "__main__":
    unittest.main()
