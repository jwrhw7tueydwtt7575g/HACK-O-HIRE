#!/usr/bin/env python3
import json
import random
from datetime import datetime, timezone, timedelta

OUTPUT_PATH = "../logs/core_banking.jsonl"

base_time = datetime(2026, 2, 20, 8, 0, 0, tzinfo=timezone.utc)

base_events = [
    {
        "timestamp": (base_time).isoformat(),
        "event_type": "transaction",
        "action": "transfer_initiated",
        "amount": 1200.50,
        "currency": "USD",
        "src_account": "ACCT-1001",
        "dest_account": "ACCT-2001",
        "src_ip": "198.51.100.10",
        "dest_ip": "203.0.113.10",
        "user": "jdoe",
        "host": "corebank-01",
        "level": "info",
    },
    {
        "timestamp": (base_time.replace(minute=5)).isoformat(),
        "event_type": "auth",
        "action": "login_failed",
        "reason": "bad_password",
        "src_ip": "198.51.100.11",
        "dest_ip": "203.0.113.10",
        "user": "svc-transfer",
        "host": "corebank-01",
        "level": "warning",
    },
    {
        "timestamp": (base_time.replace(minute=10)).isoformat(),
        "event_type": "transaction",
        "action": "transfer_completed",
        "amount": 9800.00,
        "currency": "USD",
        "src_account": "ACCT-3001",
        "dest_account": "ACCT-9001",
        "src_ip": "198.51.100.12",
        "dest_ip": "203.0.113.11",
        "user": "asmith",
        "host": "corebank-02",
        "level": "info",
        "fraud_flag": True,
        "reason": "large_transfer",
    },
    {
        "timestamp": (base_time.replace(minute=15)).isoformat(),
        "event_type": "privileged_op",
        "action": "role_change",
        "target_user": "teller-04",
        "new_role": "supervisor",
        "src_ip": "198.51.100.13",
        "dest_ip": "203.0.113.12",
        "user": "admin1",
        "host": "corebank-02",
        "level": "notice",
    },
    {
        "timestamp": (base_time.replace(minute=20)).isoformat(),
        "event_type": "transaction",
        "action": "transfer_initiated",
        "amount": 250000.00,
        "currency": "USD",
        "src_account": "ACCT-4444",
        "dest_account": "ACCT-7777",
        "src_ip": "198.51.100.14",
        "dest_ip": "203.0.113.13",
        "user": "jdoe",
        "host": "corebank-01",
        "level": "warning",
        "fraud_flag": True,
        "reason": "threshold_exceeded",
    },
    {
        "timestamp": (base_time.replace(minute=25)).isoformat(),
        "event_type": "auth",
        "action": "login_success",
        "src_ip": "198.51.100.15",
        "dest_ip": "203.0.113.10",
        "user": "svc-batch",
        "host": "corebank-01",
        "level": "info",
    },
    {
        "timestamp": (base_time.replace(minute=30)).isoformat(),
        "event_type": "transaction",
        "action": "reversal",
        "amount": 150.75,
        "currency": "USD",
        "src_account": "ACCT-5555",
        "dest_account": "ACCT-6666",
        "src_ip": "198.51.100.16",
        "dest_ip": "203.0.113.14",
        "user": "teller-02",
        "host": "corebank-03",
        "level": "info",
    },
    {
        "timestamp": (base_time.replace(minute=35)).isoformat(),
        "event_type": "privileged_op",
        "action": "limit_override",
        "limit_value": 100000.00,
        "src_ip": "198.51.100.17",
        "dest_ip": "203.0.113.15",
        "user": "admin2",
        "host": "corebank-03",
        "level": "warning",
        "after_hours": True,
    },
    {
        "timestamp": (base_time.replace(minute=40)).isoformat(),
        "event_type": "auth",
        "action": "mfa_failed",
        "src_ip": "198.51.100.18",
        "dest_ip": "203.0.113.10",
        "user": "jdoe",
        "host": "corebank-01",
        "level": "warning",
    },
    {
        "timestamp": (base_time.replace(minute=45)).isoformat(),
        "event_type": "transaction",
        "action": "transfer_completed",
        "amount": 4200.00,
        "currency": "USD",
        "src_account": "ACCT-7777",
        "dest_account": "ACCT-8888",
        "src_ip": "198.51.100.19",
        "dest_ip": "203.0.113.16",
        "user": "asmith",
        "host": "corebank-02",
        "level": "info",
    },
]

def build_event(template, ts):
    event = dict(template)
    event["timestamp"] = ts.isoformat()
    if "amount" in event:
        event["amount"] = round(event["amount"] * random.uniform(0.7, 1.3), 2)
    if "limit_value" in event:
        event["limit_value"] = round(event["limit_value"] * random.uniform(0.8, 1.2), 2)
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
