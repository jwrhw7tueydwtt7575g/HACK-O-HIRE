#!/usr/bin/env python3
import json
import random
from datetime import datetime, timezone, timedelta

OUTPUT_PATH = "../logs/databases.jsonl"

base_time = datetime(2026, 2, 20, 10, 0, 0, tzinfo=timezone.utc)

base_events = [
    {
        "timestamp": base_time.isoformat(),
        "event_type": "query",
        "action": "select",
        "database": "core_ledger",
        "schema": "public",
        "table": "transactions",
        "user": "reporting",
        "src_ip": "198.51.100.30",
        "dest_ip": "192.0.2.30",
        "rows": 120,
        "level": "info",
    },
    {
        "timestamp": base_time.replace(minute=4).isoformat(),
        "event_type": "privilege",
        "action": "grant",
        "database": "core_ledger",
        "schema": "public",
        "user": "dba_admin",
        "target_user": "etl_user",
        "privilege": "SELECT",
        "src_ip": "198.51.100.31",
        "dest_ip": "192.0.2.30",
        "level": "notice",
    },
    {
        "timestamp": base_time.replace(minute=8).isoformat(),
        "event_type": "schema",
        "action": "alter_table",
        "database": "core_ledger",
        "schema": "public",
        "table": "accounts",
        "user": "dba_admin",
        "src_ip": "198.51.100.32",
        "dest_ip": "192.0.2.30",
        "level": "warning",
        "off_hours": True,
    },
    {
        "timestamp": base_time.replace(minute=12).isoformat(),
        "event_type": "export",
        "action": "bulk_export",
        "database": "core_ledger",
        "schema": "public",
        "table": "transactions",
        "user": "etl_user",
        "src_ip": "198.51.100.33",
        "dest_ip": "192.0.2.30",
        "rows": 500000,
        "level": "warning",
    },
    {
        "timestamp": base_time.replace(minute=16).isoformat(),
        "event_type": "auth",
        "action": "login_failed",
        "database": "core_ledger",
        "user": "unknown",
        "src_ip": "198.51.100.34",
        "dest_ip": "192.0.2.30",
        "level": "warning",
    },
    {
        "timestamp": base_time.replace(minute=20).isoformat(),
        "event_type": "schema",
        "action": "create_table",
        "database": "fraud",
        "schema": "public",
        "table": "alerts",
        "user": "dba_admin",
        "src_ip": "198.51.100.35",
        "dest_ip": "192.0.2.31",
        "level": "info",
    },
    {
        "timestamp": base_time.replace(minute=24).isoformat(),
        "event_type": "query",
        "action": "update",
        "database": "fraud",
        "schema": "public",
        "table": "alerts",
        "user": "fraud_ops",
        "src_ip": "198.51.100.36",
        "dest_ip": "192.0.2.31",
        "rows": 5,
        "level": "info",
    },
    {
        "timestamp": base_time.replace(minute=28).isoformat(),
        "event_type": "privilege",
        "action": "revoke",
        "database": "fraud",
        "schema": "public",
        "user": "dba_admin",
        "target_user": "temp_user",
        "privilege": "UPDATE",
        "src_ip": "198.51.100.37",
        "dest_ip": "192.0.2.31",
        "level": "notice",
    },
    {
        "timestamp": base_time.replace(minute=32).isoformat(),
        "event_type": "query",
        "action": "delete",
        "database": "fraud",
        "schema": "public",
        "table": "alerts",
        "user": "fraud_ops",
        "src_ip": "198.51.100.38",
        "dest_ip": "192.0.2.31",
        "rows": 2,
        "level": "warning",
    },
    {
        "timestamp": base_time.replace(minute=36).isoformat(),
        "event_type": "auth",
        "action": "login_success",
        "database": "fraud",
        "user": "fraud_ops",
        "src_ip": "198.51.100.39",
        "dest_ip": "192.0.2.31",
        "level": "info",
    },
]

def build_event(template, ts):
    event = dict(template)
    event["timestamp"] = ts.isoformat()
    if "rows" in event:
        event["rows"] = int(event["rows"] * random.uniform(0.5, 2.0))
    return event

events = []
for i in range(50):
    template = random.choice(base_events)
    ts = base_time + timedelta(minutes=i)
    events.append(build_event(template, ts))

with open(OUTPUT_PATH, "w", encoding="utf-8") as f:
    for event in events:
        f.write(json.dumps(event) + "\n")

print(f"Wrote {len(events)} events to {OUTPUT_PATH}")
