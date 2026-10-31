
import json
from collections import Counter
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
LOG_FILE = BASE_DIR / "activity.log"
EVIDENCE_DIR = BASE_DIR / "evidence"
REPORT_FILE = BASE_DIR / "security_report.json"

def main():
    counts = Counter()
    total_log_alerts = 0

    if LOG_FILE.exists():
        for line in LOG_FILE.read_text(errors="replace").splitlines():
            if " | WARNING | " not in line:
                continue

            total_log_alerts += 1
            parts = line.split(" | ")
            if len(parts) >= 3:
                event_type = parts[2].strip()
                counts[event_type] += 1

    evidence_count = 0
    if EVIDENCE_DIR.exists():
        evidence_count = sum(
            1 for path in EVIDENCE_DIR.glob("*.json")
            if path.is_file()
        )

    report = {
        "log_alert_count": total_log_alerts,
        "evidence_file_count": evidence_count,
        "alerts_by_type": dict(sorted(counts.items())),
    }

    REPORT_FILE.write_text(json.dumps(report, indent=2))

    print("=== FIM Security Summary ===")
    print(f"Alerts in log: {total_log_alerts}")
    print(f"Evidence JSON files: {evidence_count}")
    print("\nAlerts by event type:")

    if counts:
        for event, count in sorted(counts.items()):
            print(f"  {event}: {count}")
    else:
        print("  No alerts recorded.")

    print(f"\nReport saved to: {REPORT_FILE}")

if __name__ == "__main__":
    main()
