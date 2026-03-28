# parse-esf

A Python utility for parsing Apple Endpoint Security Framework (ESF) JSONL log files into CSV format for analysis.

## Overview

macOS Endpoint Security Framework events can be exported as JSONL (newline-delimited JSON). This tool parses those logs and flattens them into a structured CSV, making it easy to analyze in Excel, pandas, or any data tool.

## Usage

```bash
python parse_esf.py <input.jsonl> <output.csv>
```

### Example

```bash
python parse_esf.py esf_events.jsonl esf_events.csv
```

## Output Fields

| Field | Description |
|---|---|
| `time` | Event timestamp |
| `mach_time` | Mach absolute time |
| `global_seq_num` | Global sequence number |
| `seq_num` | Per-event sequence number |
| `event_type_id` | ESF event type identifier |
| `action_type` | Action type (AUTH or NOTIFY) |
| `result_type` | Result type |
| `result_auth` | Auth result value |
| `result_flags` | Result flags |
| `process_pid` | Process ID |
| `process_ppid` | Parent process ID |
| `process_uid` | Real user ID |
| `process_gid` | Real group ID |
| `process_euid` | Effective user ID |
| `process_session_id` | Session ID |
| `process_exe` | Path to the executable |
| `process_signing_id` | Code signing identifier |
| `process_team_id` | Team ID |
| `process_is_platform_binary` | Whether it is an Apple platform binary |
| `process_codesigning_flags` | Codesigning flags |
| `process_start_time` | Process start time |
| `event_key` | Top-level key of the event data |
| `paths` | Pipe-separated list of paths found in the event |
| `raw_event` | Full event data as JSON |

## Requirements

- Python 3.x
- No external dependencies

## Input Format

The input file should be a UTF-16 encoded JSONL file as exported by ESF tools. Each line (or concatenated stream) should contain a valid ESF event JSON object.
