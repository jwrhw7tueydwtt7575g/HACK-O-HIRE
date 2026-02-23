#!/usr/bin/env python3
import json
import random
from datetime import datetime, timezone, timedelta

AWS_OUTPUT = "../logs/aws_cloudtrail.jsonl"
AZURE_OUTPUT = "../logs/azure_activity.jsonl"
GCP_OUTPUT = "../logs/gcp_audit.jsonl"

base_time = datetime(2026, 2, 20, 16, 0, 0, tzinfo=timezone.utc)

aws_events = [
    {"event_type": "iam", "action": "iam_policy_change", "src_ip": "198.51.100.210", "user": "secops", "region": "us-east-1", "level": "warning"},
    {"event_type": "login", "action": "console_login", "src_ip": "198.51.100.211", "user": "admin", "region": "us-west-2", "level": "info"},
    {"event_type": "compute", "action": "instance_launch", "src_ip": "198.51.100.212", "user": "ci-bot", "region": "eu-west-1", "level": "info"},
]

azure_events = [
    {"event_type": "iam", "action": "role_assignment", "src_ip": "198.51.100.220", "user": "aad-admin", "region": "westeurope", "level": "warning"},
    {"event_type": "login", "action": "portal_login", "src_ip": "198.51.100.221", "user": "ops", "region": "eastus", "level": "info"},
    {"event_type": "resource", "action": "resource_create", "src_ip": "198.51.100.222", "user": "terraform", "region": "centralus", "level": "info"},
]

gcp_events = [
    {"event_type": "iam", "action": "policy_set", "src_ip": "198.51.100.230", "user": "gcp-admin", "region": "us-central1", "level": "warning"},
    {"event_type": "login", "action": "console_login", "src_ip": "198.51.100.231", "user": "developer", "region": "europe-west1", "level": "info"},
    {"event_type": "compute", "action": "vm_create", "src_ip": "198.51.100.232", "user": "ci-bot", "region": "asia-south1", "level": "info"},
]


def write_events(output_path, templates):
    events = []
    for i in range(50):
        template = random.choice(templates)
        event = dict(template)
        event["timestamp"] = (base_time + timedelta(minutes=i)).isoformat()
        events.append(event)
    with open(output_path, "w", encoding="utf-8") as f:
        for event in events:
            f.write(json.dumps(event) + "\n")
    print(f"Wrote {len(events)} events to {output_path}")


write_events(AWS_OUTPUT, aws_events)
write_events(AZURE_OUTPUT, azure_events)
write_events(GCP_OUTPUT, gcp_events)
