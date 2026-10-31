
import hashlib
import json
import logging
import sys
import time
from pathlib import Path
from datetime import datetime

from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

BASE_DIR = Path(__file__).resolve().parent
MONITORED_DIR = BASE_DIR / "monitored_files"
BASELINE_FILE = BASE_DIR / "baseline.json"
EVIDENCE_DIR = BASE_DIR / "evidence"
LOG_FILE = BASE_DIR / "activity.log"

MONITORED_DIR.mkdir(parents=True, exist_ok=True)
EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)

logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(message)s",
)

def sha256_file(path):
    digest = hashlib.sha256()
    try:
        with path.open("rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                digest.update(chunk)
        return digest.hexdigest()
    except OSError as exc:
        logging.error("Could not hash %s: %s", path, exc)
        return None

def scan_files():
    result = {}
    for path in MONITORED_DIR.rglob("*"):
        if path.is_file():
            digest = sha256_file(path)
            if digest is not None:
                result[str(path.relative_to(MONITORED_DIR))] = digest
    return result

def load_baseline():
    try:
        data = json.loads(BASELINE_FILE.read_text())
        if not isinstance(data, dict) or not all(
            isinstance(k, str) and isinstance(v, str)
            for k, v in data.items()
        ):
            raise ValueError("Baseline must contain filename-to-hash mappings")
        return data
    except (OSError, json.JSONDecodeError, ValueError) as exc:
        print(f"[ERROR] Cannot load baseline: {exc}")
        sys.exit(1)

def save_baseline():
    current = scan_files()
    temp_file = BASELINE_FILE.with_suffix(".json.tmp")
    temp_file.write_text(json.dumps(current, indent=2))
    temp_file.replace(BASELINE_FILE)
    print(f"[+] Baseline saved with {len(current)} file(s).")
    logging.info("Baseline updated: %d file(s)", len(current))

def record_alert(event_type, name, old_hash=None, new_hash=None):
    timestamp = datetime.now().astimezone().isoformat()
    record = {
        "timestamp": timestamp,
        "event": event_type,
        "file": name,
        "old_sha256": old_hash,
        "new_sha256": new_hash,
    }
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
    evidence_path = EVIDENCE_DIR / f"alert_{stamp}.json"
    evidence_path.write_text(json.dumps(record, indent=2))
    logging.warning(
        "%s | file=%s | old=%s | new=%s",
        event_type, name, old_hash, new_hash
    )
    print(f"[ALERT] {event_type}: {name}")

def compare_baseline(expected, current):
    changed = 0
    for name in sorted(expected.keys() | current.keys()):
        old_hash = expected.get(name)
        new_hash = current.get(name)

        if old_hash is None:
            record_alert("FILE_CREATED_BEFORE_START", name, None, new_hash)
            changed += 1
        elif new_hash is None:
            record_alert("FILE_MISSING_AT_START", name, old_hash, None)
            changed += 1
        elif old_hash != new_hash:
            record_alert("FILE_CHANGED_BEFORE_START", name, old_hash, new_hash)
            changed += 1

    if changed == 0:
        print("[+] Startup baseline verification passed.")
    else:
        print(f"[!] Startup verification found {changed} issue(s).")
    return current

class FIMHandler(FileSystemEventHandler):
    def __init__(self, known_hashes):
        self.known_hashes = known_hashes.copy()
        self.last_event = {}

    def on_any_event(self, event):
        if event.is_directory:
            return

        path = Path(event.src_path)
        try:
            name = str(path.relative_to(MONITORED_DIR))
        except ValueError:
            return

        now = time.time()
        if now - self.last_event.get(name, 0) < 0.5:
            return
        self.last_event[name] = now

        time.sleep(0.2)
        new_hash = sha256_file(path) if path.is_file() else None
        old_hash = self.known_hashes.get(name)

        if old_hash is None and new_hash is not None:
            record_alert("FILE_CREATED", name, None, new_hash)
            self.known_hashes[name] = new_hash
        elif old_hash is not None and new_hash is None:
            record_alert("FILE_DELETED", name, old_hash, None)
            self.known_hashes.pop(name, None)
        elif old_hash is not None and new_hash is not None and old_hash != new_hash:
            record_alert("FILE_MODIFIED", name, old_hash, new_hash)
            self.known_hashes[name] = new_hash

def main():
    if len(sys.argv) == 2 and sys.argv[1] == "--baseline":
        save_baseline()
        return

    if not BASELINE_FILE.exists():
        print("[ERROR] Baseline missing. Create one with: python fim.py --baseline")
        sys.exit(1)

    expected = load_baseline()
    current = scan_files()
    known_hashes = compare_baseline(expected, current)

    print(f"Monitoring: {MONITORED_DIR}")
    print("Press Ctrl+C to stop.")
    handler = FIMHandler(known_hashes)
    observer = Observer()
    observer.schedule(handler, str(MONITORED_DIR), recursive=True)
    observer.start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[+] Stopping FIM...")
        observer.stop()
    observer.join()
    print("[+] FIM stopped.")

if __name__ == "__main__":
    main()
