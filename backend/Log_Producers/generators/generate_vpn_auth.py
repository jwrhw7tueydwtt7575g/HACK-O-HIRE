#!/usr/bin/env python3
import random
from datetime import datetime, timezone, timedelta

OUTPUT_PATH = "../logs/vpn_auth.log"

base_time = datetime(2026, 2, 20, 15, 0, 0, tzinfo=timezone.utc)

base_entries = [
    ("vpn-gw-01", "openvpn", 301, "Auth failed for user alice from 198.51.100.200"),
    ("vpn-gw-01", "openvpn", 302, "Auth success for user bob from 198.51.100.201"),
    ("vpn-gw-02", "ipsec", 401, "MFA failed for user carol from 198.51.100.202"),
    ("vpn-gw-02", "ipsec", 402, "Session established for user dave from 198.51.100.203"),
]

def rfc5424(ts, host, app, pid, msg, msgid="VPN1"):
    return f"<34>1 {ts.isoformat()} {host} {app} {pid} {msgid} - {msg}"

lines = []
for i in range(50):
    host, app, pid, msg = random.choice(base_entries)
    ts = base_time + timedelta(minutes=i)
    lines.append(rfc5424(ts, host, app, pid, msg))

with open(OUTPUT_PATH, "w", encoding="utf-8") as f:
    for line in lines:
        f.write(line + "\n")

print(f"Wrote {len(lines)} VPN syslog lines to {OUTPUT_PATH}")
