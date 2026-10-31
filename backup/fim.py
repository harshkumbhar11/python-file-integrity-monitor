
import hashlib
import json
import logging
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

EVIDENCE_DIR.mkdir(exist_ok=True)
MONITORED_DIR.mkdir(exist_ok=True)

logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(message)s",
)

def sha256_file(file_path):
    """Return SHA-256 hash of a file."""
    digest = hashlib.sha256()
    try:
        with open(file_path, "rb") as file:
            for chunk in iter(lambda: file.read(4096), b""):
                digest.update(chunk)
        return digest.hexdigest()
    except (OSError, PermissionError):
        return None

def scan_files():
    """Collect SHA-256 hashes of regular files in the monitored folder."""
    results = {}
    for path in MONITORED_DIR.rglob("*"):
        if path.is_file():
            file_hash = sha256_file(path)
            if file_hash is not None:
                results[str(path.relative_to(MONITORED_DIR))] = file_hash
    return results

def save_baseline():
    """Create a baseline of the current monitored files."""
    current = scan_files()
    BASELINE_FILE.write_text(json.dumps(current, indent=2))
    print(f"[+] Baseline saved: {len(current)} file(s)")
    logging.info("Baseline created with %d file(s)", len(current))

def write_evidence(event_type, file_path, old_hash=None, new_hash=None):
    """Write a timestamped JSON record for an alert."""
    record = {
        "timestamp": datetime.now().astimezone().isoformat(),
        "event": event_type,
        "file": str(file_path),
        "old_sha256": old_hash,
        "new_sha256": new_hash,
    }
    filename = datetime.now().strftime("alert_%Y%m%d_%H%M%S_%f.json")
    evidence_file = EVIDENCE_DIR / filename
    evidence_file.write_text(json.dumps(record, indent=2))
    logging.warning("%s | file=%s | old=%s | new=%s",
                    event_type, file_path, old_hash, new_hash)
    print(f"[ALERT] {event_type}: {file_path}")
    print(f"        Evidence: {evidence_file.name}")

class FIMHandler(FileSystemEventHandler):
    def __init__(self):
        self.known_hashes = scan_files()
        self.last_event = {}

    def on_any_event(self, event):
        if event.is_directory:
            return

        # Ignore temporary editor files; monitor regular file events.
        path = Path(event.src_path)
        if not path.is_relative_to(MONITORED_DIR):
            return

        relative_name = str(path.relative_to(MONITORED_DIR))
        now = time.time()

        # Files may generate several rapid events while being written.
        if now - self.last_event.get(relative_name, 0) < 0.4:
            return
        self.last_event[relative_name] = now

        # Allow a short delay so a write operation can finish.
        time.sleep(0.2)
        new_hash = sha256_file(path) if path.exists() and path.is_file() else None
        old_hash = self.known_hashes.get(relative_name)

        if old_hash is None and new_hash is not None:
            write_evidence("FILE_CREATED", relative_name, None, new_hash)
            self.known_hashes[relative_name] = new_hash

        elif old_hash is not None and new_hash is None:
            write_evidence("FILE_DELETED", relative_name, old_hash, None)
            self.known_hashes.pop(relative_name, None)

        elif old_hash is not None and new_hash is not None and old_hash != new_hash:
            write_evidence("FILE_MODIFIED", relative_name, old_hash, new_hash)
            self.known_hashes[relative_name] = new_hash

def main():
    print("=== File Integrity Monitoring System ===")
    print(f"Monitoring: {MONITORED_DIR}")
    print("Press Ctrl+C to stop.\n")

    if not BASELINE_FILE.exists():
        save_baseline()
    else:
        print("[+] Existing baseline found.")
        print("[!] Baseline is not automatically updated.")

    handler = FIMHandler()
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
