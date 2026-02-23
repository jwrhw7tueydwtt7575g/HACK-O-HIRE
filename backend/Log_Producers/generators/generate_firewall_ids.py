#!/usr/bin/env python3
import json
import random
from datetime import datetime, timezone, timedelta

JSON_OUTPUT = "../logs/firewall_ids.jsonl"
CEF_OUTPUT = "../logs/firewall_ids.cef"

base_time = datetime(2026, 2, 20, 14, 0, 0, tzinfo=timezone.utc)

base_json_events = [
    {
        "event_type": "ids",
        "action": "port_scan",
        "src_ip": "203.0.113.70",
        "dest_ip": "192.0.2.50",
        "user": "unknown",
        "level": "warning",
    },
    {
        "event_type": "ids",
        "action": "blocked_ip",
        "src_ip": "203.0.113.71",
        "dest_ip": "192.0.2.50",
        "user": "unknown",
        "level": "info",
    },
    {
        "event_type": "ids",
        "action": "c2_beacon",
        "src_ip": "203.0.113.72",
        "dest_ip": "192.0.2.51",
        "user": "unknown",
        "level": "error",
    },
    {
        "event_type": "ids",
        "action": "data_exfiltration",
        "src_ip": "203.0.113.73",
        "dest_ip": "192.0.2.52",
        "user": "svc-app",
        "level": "warning",
    },
]

base_cef_events = [
    "CEF:0|NetShield|IDS|1.0|2001|Port scan|7|src=203.0.113.70 dst=192.0.2.50 requestMethod=TCP request=/scan msg=Port scan detected",
    "CEF:0|NetShield|IDS|1.0|2002|Blocked IP|5|src=203.0.113.71 dst=192.0.2.50 requestMethod=TCP request=/block msg=IP blocked",
    "CEF:0|NetShield|IDS|1.0|2003|C2 beacon|9|src=203.0.113.72 dst=192.0.2.51 requestMethod=TCP request=/beacon msg=C2 beacon pattern detected",
    "CEF:0|NetShield|IDS|1.0|2004|Data exfil|8|src=203.0.113.73 dst=192.0.2.52 requestMethod=TCP request=/exfil msg=Potential data exfiltration",
]

json_events = []
for i in range(50):
    template = random.choice(base_json_events)
    event = dict(template)
    event["timestamp"] = (base_time + timedelta(minutes=i)).isoformat()
    json_events.append(event)

cef_events = [random.choice(base_cef_events) for _ in range(50)]

with open(JSON_OUTPUT, "w", encoding="utf-8") as f:
    for event in json_events:
        f.write(json.dumps(event) + "\n")

with open(CEF_OUTPUT, "w", encoding="utf-8") as f:
    for line in cef_events:
        f.write(line + "\n")

print(f"Wrote {len(json_events)} JSON events to {JSON_OUTPUT}")
print(f"Wrote {len(cef_events)} CEF events to {CEF_OUTPUT}")
