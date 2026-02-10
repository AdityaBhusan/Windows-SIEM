import json
from pathlib import Path

# ============================
# Windows Mini SIEM - Parser
# (Path-safe version)
# ============================

# Always resolve paths relative to THIS file
BASE_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = BASE_DIR.parent
SAMPLES_DIR = PROJECT_ROOT / "samples"
OUTPUT_DIR = BASE_DIR / "output"

OUTPUT_DIR.mkdir(exist_ok=True)

LOGON_TYPE_MAP = {
    "2": "INTERACTIVE",
    "3": "NETWORK",
    "4": "BATCH",
    "5": "SERVICE",
    "7": "UNLOCK",
    "8": "NETWORK_CLEAR",
    "9": "NEW_CREDENTIALS",
    "10": "RDP",
    "11": "CACHED_INTERACTIVE"
}

def load_events(filename):
    path = SAMPLES_DIR / filename
    if not path.exists():
        print(f"[!] File not found: {path}")
        return []
    with open(path, "r", encoding="utf-8-sig") as f:
        return json.load(f)

def normalize_event(event, event_type):
    logon_raw = str(event.get("logon_type", ""))
    return {
        "timestamp": event.get("timestamp"),
        "event_type": event_type,
        "username": event.get("username"),
        "source_ip": event.get("source_ip"),
        "logon_type": LOGON_TYPE_MAP.get(logon_raw, "UNKNOWN"),
        "host": event.get("workstation")
    }

def main():
    normalized = []

    failed = load_events("sample_4625.json")
    success = load_events("sample_4624.json")

    for e in failed:
        normalized.append(normalize_event(e, "AUTH_FAILURE"))

    for e in success:
        normalized.append(normalize_event(e, "AUTH_SUCCESS"))

    out_file = OUTPUT_DIR / "normalized_auth_events.json"
    with open(out_file, "w", encoding="utf-8") as f:
        json.dump(normalized, f, indent=2)

    print(f"[+] Parsed {len(normalized)} events")
    print(f"[+] Output written to {out_file}")

if __name__ == "__main__":
    main()
