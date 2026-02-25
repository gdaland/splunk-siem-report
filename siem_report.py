#!/usr/bin/env python3
"""
Splunk SIEM Log Analysis Report Generator

Parses Splunk SIEM event logs (CSV format) and produces a structured
analysis report covering severity distribution, top source IPs, event
types, user activity, and hourly event trends.
"""

import csv
import json
import sys
import os
from collections import Counter, defaultdict
from datetime import datetime


# ---------------------------------------------------------------------------
# Data loading
# ---------------------------------------------------------------------------

def load_logs(filepath):
    """Load SIEM log events from a CSV file.

    Parameters
    ----------
    filepath : str
        Path to the CSV log file.

    Returns
    -------
    list[dict]
        List of log event dictionaries (one per row).

    Raises
    ------
    FileNotFoundError
        If *filepath* does not exist.
    ValueError
        If the file is empty or has no header row.
    """
    if not os.path.exists(filepath):
        raise FileNotFoundError(f"Log file not found: {filepath}")

    with open(filepath, newline="", encoding="utf-8") as fh:
        reader = csv.DictReader(fh)
        logs = list(reader)

    if not logs:
        raise ValueError(f"No log events found in: {filepath}")

    return logs


# ---------------------------------------------------------------------------
# Analysis
# ---------------------------------------------------------------------------

def analyze_logs(logs):
    """Analyse a list of SIEM log events and return aggregated metrics.

    Parameters
    ----------
    logs : list[dict]
        Log events as returned by :func:`load_logs`.

    Returns
    -------
    dict
        Dictionary containing the following keys:

        * ``total_events``      – total number of events
        * ``severity_counts``   – Counter keyed by severity label
        * ``top_src_ips``       – Counter of source IP addresses
        * ``top_event_types``   – Counter of event/signature types
        * ``top_users``         – Counter of user accounts seen
        * ``top_dest_ips``      – Counter of destination IP addresses
        * ``action_counts``     – Counter of actions (allow/block/…)
        * ``hourly_counts``     – dict mapping "YYYY-MM-DD HH" to count
        * ``date_range``        – (min_time, max_time) tuple of strings
    """
    metrics = {
        "total_events": len(logs),
        "severity_counts": Counter(),
        "top_src_ips": Counter(),
        "top_event_types": Counter(),
        "top_users": Counter(),
        "top_dest_ips": Counter(),
        "action_counts": Counter(),
        "hourly_counts": defaultdict(int),
        "date_range": (None, None),
    }

    timestamps = []

    for event in logs:
        # Severity
        severity = event.get("severity", event.get("urgency", "unknown")).strip()
        if severity:
            metrics["severity_counts"][severity] += 1

        # Source IP
        src_ip = event.get("src_ip", event.get("src", "")).strip()
        if src_ip:
            metrics["top_src_ips"][src_ip] += 1

        # Destination IP
        dest_ip = event.get("dest_ip", event.get("dest", "")).strip()
        if dest_ip:
            metrics["top_dest_ips"][dest_ip] += 1

        # Event type / signature
        event_type = event.get(
            "signature",
            event.get("EventCode", event.get("event_type", ""))
        ).strip()
        if event_type:
            metrics["top_event_types"][event_type] += 1

        # User
        user = event.get("user", event.get("user_name", "")).strip()
        if user and user not in ("-", "N/A"):
            metrics["top_users"][user] += 1

        # Action
        action = event.get("action", "").strip()
        if action:
            metrics["action_counts"][action] += 1

        # Timestamp → hourly bucket
        raw_time = event.get("_time", event.get("timestamp", "")).strip()
        if raw_time:
            dt = _parse_timestamp(raw_time)
            if dt:
                timestamps.append(dt)
                hour_key = dt.strftime("%Y-%m-%d %H:00")
                metrics["hourly_counts"][hour_key] += 1

    if timestamps:
        metrics["date_range"] = (
            min(timestamps).strftime("%Y-%m-%d %H:%M:%S"),
            max(timestamps).strftime("%Y-%m-%d %H:%M:%S"),
        )

    # Convert defaultdict to plain dict for cleaner serialisation
    metrics["hourly_counts"] = dict(sorted(metrics["hourly_counts"].items()))

    return metrics


def _parse_timestamp(raw):
    """Try several common Splunk timestamp formats and return a datetime."""
    formats = [
        "%Y-%m-%dT%H:%M:%S.%f%z",
        "%Y-%m-%dT%H:%M:%S%z",
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%d %H:%M:%S",
        "%m/%d/%Y %H:%M:%S",
    ]
    for fmt in formats:
        try:
            return datetime.strptime(raw[:26], fmt)
        except ValueError:
            continue
    return None


# ---------------------------------------------------------------------------
# Report generation
# ---------------------------------------------------------------------------

SEVERITY_ORDER = ["critical", "high", "medium", "low", "informational", "unknown"]


def generate_report(metrics, top_n=10, output_format="text"):
    """Generate a formatted SIEM analysis report string.

    Parameters
    ----------
    metrics : dict
        Metrics dictionary as returned by :func:`analyze_logs`.
    top_n : int
        How many entries to show in ranked lists.
    output_format : str
        ``"text"`` for a plain-text report, ``"json"`` for JSON output.

    Returns
    -------
    str
        The formatted report.
    """
    if output_format == "json":
        return _report_json(metrics, top_n)
    return _report_text(metrics, top_n)


def _report_text(metrics, top_n):
    lines = []
    sep = "=" * 60

    lines.append(sep)
    lines.append("  SPLUNK SIEM LOG ANALYSIS REPORT")
    lines.append(sep)

    # Date range
    start, end = metrics["date_range"]
    if start and end:
        lines.append(f"  Period : {start}  →  {end}")
    lines.append(f"  Total Events : {metrics['total_events']:,}")
    lines.append(sep)

    # Severity breakdown
    lines.append("\n[Severity Distribution]")
    severity = metrics["severity_counts"]
    total = metrics["total_events"] or 1
    for level in SEVERITY_ORDER:
        count = severity.get(level, 0)
        if count:
            pct = count / total * 100
            bar = "█" * int(pct / 2)
            lines.append(f"  {level:<15} {count:>6,}  ({pct:5.1f}%)  {bar}")
    # Any severities not in the standard order
    for level, count in sorted(severity.items()):
        if level not in SEVERITY_ORDER:
            pct = count / total * 100
            lines.append(f"  {level:<15} {count:>6,}  ({pct:5.1f}%)")

    # Action breakdown
    if metrics["action_counts"]:
        lines.append("\n[Action Breakdown]")
        for action, count in metrics["action_counts"].most_common():
            pct = count / total * 100
            lines.append(f"  {action:<15} {count:>6,}  ({pct:5.1f}%)")

    # Top source IPs
    if metrics["top_src_ips"]:
        lines.append(f"\n[Top {top_n} Source IPs]")
        for ip, count in metrics["top_src_ips"].most_common(top_n):
            lines.append(f"  {ip:<20} {count:>6,}")

    # Top destination IPs
    if metrics["top_dest_ips"]:
        lines.append(f"\n[Top {top_n} Destination IPs]")
        for ip, count in metrics["top_dest_ips"].most_common(top_n):
            lines.append(f"  {ip:<20} {count:>6,}")

    # Top event types
    if metrics["top_event_types"]:
        lines.append(f"\n[Top {top_n} Event Types / Signatures]")
        for etype, count in metrics["top_event_types"].most_common(top_n):
            lines.append(f"  {etype:<35} {count:>6,}")

    # Top users
    if metrics["top_users"]:
        lines.append(f"\n[Top {top_n} User Accounts]")
        for user, count in metrics["top_users"].most_common(top_n):
            lines.append(f"  {user:<25} {count:>6,}")

    # Hourly trend
    if metrics["hourly_counts"]:
        lines.append("\n[Hourly Event Trend]")
        max_count = max(metrics["hourly_counts"].values())
        for hour, count in metrics["hourly_counts"].items():
            bar = "█" * int(count / max_count * 30)
            lines.append(f"  {hour}  {count:>5,}  {bar}")

    lines.append("\n" + sep)
    return "\n".join(lines)


def _report_json(metrics, top_n):
    output = {
        "date_range": {
            "start": metrics["date_range"][0],
            "end": metrics["date_range"][1],
        },
        "total_events": metrics["total_events"],
        "severity_distribution": dict(metrics["severity_counts"]),
        "action_breakdown": dict(metrics["action_counts"]),
        "top_source_ips": dict(metrics["top_src_ips"].most_common(top_n)),
        "top_destination_ips": dict(metrics["top_dest_ips"].most_common(top_n)),
        "top_event_types": dict(metrics["top_event_types"].most_common(top_n)),
        "top_users": dict(metrics["top_users"].most_common(top_n)),
        "hourly_event_counts": metrics["hourly_counts"],
    }
    return json.dumps(output, indent=2)


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

def main(argv=None):
    """Command-line entry point.

    Usage
    -----
    ::

        python siem_report.py <log_file.csv> [--format text|json] [--top N]
    """
    import argparse

    parser = argparse.ArgumentParser(
        description="Generate a SIEM log analysis report from Splunk CSV exports."
    )
    parser.add_argument("log_file", help="Path to the Splunk SIEM CSV log file")
    parser.add_argument(
        "--format",
        dest="output_format",
        choices=["text", "json"],
        default="text",
        help="Output format (default: text)",
    )
    parser.add_argument(
        "--top",
        dest="top_n",
        type=int,
        default=10,
        help="Number of top entries to display in ranked lists (default: 10)",
    )

    args = parser.parse_args(argv)

    try:
        logs = load_logs(args.log_file)
    except (FileNotFoundError, ValueError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        sys.exit(1)

    metrics = analyze_logs(logs)
    report = generate_report(metrics, top_n=args.top_n, output_format=args.output_format)
    print(report)


if __name__ == "__main__":
    main()
