# File Integrity Monitoring (FIM) System

## Overview

A lightweight Python-based File Integrity Monitoring system that detects unexpected file creation, modification, and deletion using SHA-256 hashing and filesystem event monitoring.

## Features

- SHA-256 file integrity checks using Python `hashlib`
- Real-time file event monitoring using `watchdog`
- Startup comparison against a saved baseline
- Alerts for modified, created, deleted, missing, and unexpected files
- Timestamped activity logs
- Individual JSON incident evidence records
- Security summary report in JSON format

## Technology Stack

- Python 3
- Watchdog
- hashlib
- JSON
- Logging

## Project Structure

- `fim.py` — monitoring and detection engine
- `baseline.json` — saved file hashes
- `activity.log` — activity and alert log
- `evidence/` — JSON incident records
- `report.py` — summary report generator
- `security_report.json` — generated alert summary
- `monitored_files/` — directory used for testing

## Setup

```bash
python -m venv .venv
source .venv/bin/activate
pip install watchdog
```

## Usage

Create or refresh the trusted baseline only after reviewing the current files:

```bash
python fim.py --baseline
```

Start monitoring:

```bash
python fim.py
```

Generate a security summary:

```bash
python report.py
```

## Testing

The lab tests include:

- Modifying an existing file
- Creating a new file
- Deleting a file
- Detecting changes made while monitoring was stopped
- Detecting files missing from the baseline

## Security Notes

This is a learning and portfolio project, not a production-grade security product. Protect the baseline and evidence files from unauthorized modification. Alerts and JSON records are not cryptographically protected against tampering. Test only within the designated lab directory.

## Future Improvements

- Stronger baseline and evidence protection
- Unit tests and automated test coverage
- Better handling of rapid consecutive file events
- Improved command-line options and reporting
- Optional email or SIEM alert integration
