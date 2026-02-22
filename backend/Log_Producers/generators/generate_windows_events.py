#!/usr/bin/env python3
from datetime import datetime, timezone, timedelta

OUTPUT_PATH = "../logs/windows_events.xml"

base_time = datetime(2026, 2, 20, 12, 0, 0, tzinfo=timezone.utc)

def event_line(ts, event_id, computer, user, ip, action, status):
    return (
        f"<Event><System><EventID>{event_id}</EventID><Computer>{computer}</Computer>"
        f"<TimeCreated>{ts.isoformat()}</TimeCreated></System>"
        f"<EventData><TargetUserName>{user}</TargetUserName><IpAddress>{ip}</IpAddress>"
        f"<Action>{action}</Action><Status>{status}</Status></EventData></Event>"
    )

lines = [
    event_line(base_time, 4624, "WIN-SRV-01", "jdoe", "203.0.113.50", "logon", "success"),
    event_line(base_time + timedelta(minutes=2), 4625, "WIN-SRV-01", "jdoe", "203.0.113.51", "logon", "failed"),
    event_line(base_time + timedelta(minutes=4), 4672, "WIN-SRV-02", "admin1", "203.0.113.52", "privileged_logon", "success"),
    event_line(base_time + timedelta(minutes=6), 5140, "WIN-SRV-02", "svc-backup", "203.0.113.53", "share_access", "success"),
    event_line(base_time + timedelta(minutes=8), 4776, "WIN-SRV-03", "unknown", "203.0.113.54", "pass_the_hash", "failed"),
    event_line(base_time + timedelta(minutes=10), 4624, "WIN-SRV-03", "svc-rdp", "203.0.113.55", "rdp_logon", "success"),
    event_line(base_time + timedelta(minutes=12), 600, "WIN-SRV-04", "powershell", "203.0.113.56", "powershell_obfuscation", "detected"),
    event_line(base_time + timedelta(minutes=14), 7045, "WIN-SRV-04", "system", "203.0.113.57", "service_install", "success"),
    event_line(base_time + timedelta(minutes=16), 4625, "WIN-SRV-05", "svc-app", "203.0.113.58", "logon", "failed"),
    event_line(base_time + timedelta(minutes=18), 4624, "WIN-SRV-05", "svc-app", "203.0.113.59", "logon", "success"),
]

with open(OUTPUT_PATH, "w", encoding="utf-8") as f:
    for line in lines:
        f.write(line + "\n")

print(f"Wrote {len(lines)} Windows Event XML lines to {OUTPUT_PATH}")
