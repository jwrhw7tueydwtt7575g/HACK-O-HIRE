#!/usr/bin/env python3
import json
import random
from datetime import datetime, timezone, timedelta

OUTPUT_PATH = "../logs/mainframe_zos.jsonl"

base_time = datetime(2026, 2, 20, 17, 0, 0, tzinfo=timezone.utc)

base_events = [
    {"event_type": "racf", "action": "unauthorized_access", "src_ip": "198.51.100.240", "user": "mf-user1", "level": "warning"},
    {"event_type": "batch", "action": "batch_job_anomaly", "src_ip": "198.51.100.241", "user": "mf-batch", "level": "warning"},
    {"event_type": "operator", "action": "operator_override", "src_ip": "198.51.100.242", "user": "mf-ops", "level": "info"},
    {"event_type": "data", "action": "mass_data_extraction", "src_ip": "198.51.100.243", "user": "mf-analyst", "level": "warning"},
]

events = []
for i in range(50):
    template = random.choice(base_events)
    event = dict(template)
    event["timestamp"] = (base_time + timedelta(minutes=i)).isoformat()
    events.append(event)

with open(OUTPUT_PATH, "w", encoding="utf-8") as f:
    for event in events:
        f.write(json.dumps(event) + "\n")

print(f"Wrote {len(events)} events to {OUTPUT_PATH}")
