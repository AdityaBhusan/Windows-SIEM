import json
from pathlib import Path
from datetime import datetime, timedelta
from collections import defaultdict

# ======================================
# Windows SIEM - Multi Stage Detector
# ======================================

BASE_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = BASE_DIR.parent

INPUT_FILE = PROJECT_ROOT / "parser" / "output" / "normalized_auth_events.json"
ALERT_DIR = BASE_DIR / "alerts"

ALERT_DIR.mkdir(exist_ok=True)

FAILURE_THRESHOLD = 5
TIME_WINDOW_MINUTES = 2

SUSPICIOUS_PROCESSES = [
    "powershell.exe",
    "cmd.exe",
    "whoami.exe",
    "net.exe",
    "wmic.exe"
]


# ---------- Helpers ----------

def parse_time(ts):
    return datetime.fromisoformat(ts)


def load_events():
    if not INPUT_FILE.exists():
        print(f"[!] Input file missing: {INPUT_FILE}")
        return []

    with open(INPUT_FILE, "r", encoding="utf-8") as f:
        return json.load(f)


# ---------- BRUTE FORCE DETECTION ----------

def detect_bruteforce(events):
    failures_by_ip = defaultdict(list)
    alerts = []

    for e in events:
        if (
            e.get("event_type") == "AUTH_FAILURE"
            and e.get("logon_type") == "RDP"
            and e.get("source_ip") not in ("-", None)
        ):
            failures_by_ip[e["source_ip"]].append(parse_time(e["timestamp"]))

    for ip, times in failures_by_ip.items():
        times.sort()

        for i in range(len(times)):
            start = times[i]
            end = start + timedelta(minutes=TIME_WINDOW_MINUTES)

            count = sum(1 for t in times if start <= t <= end)

            if count >= FAILURE_THRESHOLD:
                alerts.append({
                    "alert_type": "RDP_BRUTE_FORCE",
                    "severity": "HIGH",
                    "source_ip": ip,
                    "failed_attempts": count,
                    "window_minutes": TIME_WINDOW_MINUTES
                })
                break

    return alerts


# ---------- MULTI-STAGE DETECTION ----------

def detect_multi_stage(events):
    alerts = []

    auth_success = []
    admin_events = []
    process_events = []

    for e in events:
        if e["event_type"] == "AUTH_SUCCESS":
            auth_success.append(e)
        elif e["event_type"] == "ADMIN_PRIV_ASSIGNED":
            admin_events.append(e)
        elif e["event_type"] == "PROCESS_CREATED":
            process_events.append(e)

    for login in auth_success:
        login_time = parse_time(login["timestamp"])
        user = login["username"]

        # find admin privilege assignment
        for admin in admin_events:
            if admin["username"] != user:
                continue

            admin_time = parse_time(admin["timestamp"])

            if abs((admin_time - login_time).total_seconds()) > 60:
                continue

            # find suspicious process execution
            for proc in process_events:
                if proc["username"] != user:
                    continue

                proc_time = parse_time(proc["timestamp"])

                if abs((proc_time - admin_time).total_seconds()) > 60:
                    continue

                pname = (proc.get("process_name") or "").lower()

                if any(sp in pname for sp in SUSPICIOUS_PROCESSES):
                    alerts.append({
                        "alert_type": "MULTI_STAGE_PRIV_ESC",
                        "severity": "CRITICAL",
                        "username": user,
                        "process": pname,
                        "stage_chain": [
                            "AUTH_SUCCESS",
                            "ADMIN_PRIV_ASSIGNED",
                            "PROCESS_CREATED"
                        ]
                    })
                    break

    return alerts


# ---------- MAIN ----------

def main():
    events = load_events()

    if not events:
        print("[!] No events to analyze")
        return

    alerts = []

    alerts += detect_bruteforce(events)
    alerts += detect_multi_stage(events)

    if not alerts:
        print("[+] No suspicious activity detected")
        return

    out_file = ALERT_DIR / "siem_alerts.json"

    with open(out_file, "w", encoding="utf-8") as f:
        json.dump(alerts, f, indent=2)

    print(f"[!] {len(alerts)} alert(s) generated")
    print(f"[!] Alerts saved to {out_file}")


if __name__ == "__main__":
    main()
