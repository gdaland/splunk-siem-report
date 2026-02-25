# splunk-siem-report

A lightweight Python tool that parses Splunk SIEM event log exports (CSV format)
and produces a concise analysis report covering threat severity, top attacker IPs,
event types, user activity, and hourly trends.

## Features

- **Severity distribution** – breakdown of critical / high / medium / low / informational events with percentage bars
- **Action breakdown** – allowed vs. blocked event counts
- **Top source & destination IPs** – ranked by event volume
- **Top event types / signatures** – most-seen SIEM alerts
- **Top user accounts** – accounts generating the most events
- **Hourly event trend** – ASCII bar chart showing activity over time
- **Text and JSON output** – pipe JSON output into downstream tools or dashboards

## Requirements

- Python 3.8+
- No third-party packages required (standard library only)

## Usage

```bash
python siem_report.py <log_file.csv> [--format text|json] [--top N]
```

### Arguments

| Argument | Default | Description |
|---|---|---|
| `log_file` | *(required)* | Path to the Splunk SIEM CSV export |
| `--format` | `text` | Output format: `text` or `json` |
| `--top` | `10` | Number of entries to show in ranked lists |

### Examples

```bash
# Plain-text report (default)
python siem_report.py sample_logs/siem_events.csv

# JSON output, top 5 entries per section
python siem_report.py sample_logs/siem_events.csv --format json --top 5
```

## Input Format

The tool expects a CSV file exported from Splunk with the following fields
(all fields are optional; unrecognised columns are ignored):

| Field | Aliases | Description |
|---|---|---|
| `_time` | `timestamp` | Event timestamp (ISO 8601 or `YYYY-MM-DD HH:MM:SS`) |
| `severity` | `urgency` | Severity level |
| `src_ip` | `src` | Source IP address |
| `dest_ip` | `dest` | Destination IP address |
| `signature` | `EventCode`, `event_type` | Event type or signature name |
| `action` | | Action taken (e.g. `blocked`, `allowed`) |
| `user` | `user_name` | User account involved |

A sample log file is provided at [`sample_logs/siem_events.csv`](sample_logs/siem_events.csv).

## Running Tests

```bash
python -m unittest discover -s tests -v
```

## Sample Output

```
============================================================
  SPLUNK SIEM LOG ANALYSIS REPORT
============================================================
  Period : 2026-02-25 08:01:12  →  2026-02-25 10:27:50
  Total Events : 51
============================================================

[Severity Distribution]
  critical             9  ( 17.6%)  ████████
  high                19  ( 37.3%)  ██████████████████
  medium              13  ( 25.5%)  ████████████
  low                  7  ( 13.7%)  ██████
  informational        3  (  5.9%)  ██

[Action Breakdown]
  blocked             28  ( 54.9%)
  allowed             23  ( 45.1%)

[Top 10 Source IPs]
  10.0.2.55                 6
  203.0.113.45              5
  ...

[Top 10 Event Types / Signatures]
  4625 - Failed Logon                      7
  Exploit.ShellCode                        5
  ...
```
