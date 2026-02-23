#!/usr/bin/env python3
import random
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

base_events = [
    (4624, "WIN-SRV-01", "jdoe", "203.0.113.50", "logon", "success"),
    (4625, "WIN-SRV-01", "jdoe", "203.0.113.51", "logon", "failed"),
    (4672, "WIN-SRV-02", "admin1", "203.0.113.52", "privileged_logon", "success"),
    (5140, "WIN-SRV-02", "svc-backup", "203.0.113.53", "share_access", "success"),
    (4776, "WIN-SRV-03", "unknown", "203.0.113.54", "pass_the_hash", "failed"),
    (4624, "WIN-SRV-03", "svc-rdp", "203.0.113.55", "rdp_logon", "success"),
    (600, "WIN-SRV-04", "powershell", "203.0.113.56", "powershell_obfuscation", "detected"),
    (7045, "WIN-SRV-04", "system", "203.0.113.57", "service_install", "success"),
    (4625, "WIN-SRV-05", "svc-app", "203.0.113.58", "logon", "failed"),
    (4624, "WIN-SRV-05", "svc-app", "203.0.113.59", "logon", "success"),
]

lines = []
for i in range(50):
    event_id, computer, user, ip, action, status = random.choice(base_events)
    ts = base_time + timedelta(minutes=i)
    lines.append(event_line(ts, event_id, computer, user, ip, action, status))

with open(OUTPUT_PATH, "w", encoding="utf-8") as f:
    for line in lines:
        f.write(line + "\n")

print(f"Wrote {len(lines)} Windows Event XML lines to {OUTPUT_PATH}")
