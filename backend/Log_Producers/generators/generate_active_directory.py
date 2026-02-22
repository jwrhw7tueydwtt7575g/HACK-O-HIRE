#!/usr/bin/env python3
from datetime import datetime, timezone, timedelta

OUTPUT_PATH = "../logs/active_directory.xml"

base_time = datetime(2026, 2, 20, 13, 0, 0, tzinfo=timezone.utc)

def ad_event(ts, event_id, computer, user, ip, action, status):
    return (
        f"<Event><System><EventID>{event_id}</EventID><Computer>{computer}</Computer>"
        f"<TimeCreated>{ts.isoformat()}</TimeCreated></System>"
        f"<EventData><TargetUserName>{user}</TargetUserName><IpAddress>{ip}</IpAddress>"
        f"<Action>{action}</Action><Status>{status}</Status></EventData></Event>"
    )

lines = [
    ad_event(base_time, 4720, "AD-DC-01", "newuser", "203.0.113.60", "user_created", "success"),
    ad_event(base_time + timedelta(minutes=2), 4728, "AD-DC-01", "svc-admin", "203.0.113.61", "group_member_added", "success"),
    ad_event(base_time + timedelta(minutes=4), 4729, "AD-DC-01", "svc-admin", "203.0.113.61", "group_member_removed", "success"),
    ad_event(base_time + timedelta(minutes=6), 4740, "AD-DC-02", "jdoe", "203.0.113.62", "account_lockout", "success"),
    ad_event(base_time + timedelta(minutes=8), 4768, "AD-DC-02", "unknown", "203.0.113.63", "kerberos_tgt", "failed"),
    ad_event(base_time + timedelta(minutes=10), 4769, "AD-DC-02", "svc-rdp", "203.0.113.64", "kerberos_service", "success"),
    ad_event(base_time + timedelta(minutes=12), 4732, "AD-DC-03", "admin1", "203.0.113.65", "group_member_added", "success"),
    ad_event(base_time + timedelta(minutes=14), 5136, "AD-DC-03", "admin1", "203.0.113.66", "directory_modification", "success"),
    ad_event(base_time + timedelta(minutes=16), 4625, "AD-DC-03", "unknown", "203.0.113.67", "logon", "failed"),
    ad_event(base_time + timedelta(minutes=18), 4624, "AD-DC-03", "admin1", "203.0.113.68", "logon", "success"),
]

with open(OUTPUT_PATH, "w", encoding="utf-8") as f:
    for line in lines:
        f.write(line + "\n")

print(f"Wrote {len(lines)} Active Directory Event XML lines to {OUTPUT_PATH}")
