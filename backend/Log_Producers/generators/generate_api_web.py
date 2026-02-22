#!/usr/bin/env python3
import json
from datetime import datetime, timezone

JSON_OUTPUT = "../logs/api_web.jsonl"
CEF_OUTPUT = "../logs/api_web.cef"

base_time = datetime(2026, 2, 20, 9, 0, 0, tzinfo=timezone.utc)

json_events = [
    {
        "timestamp": base_time.isoformat(),
        "event_type": "access",
        "action": "rest_request",
        "method": "GET",
        "path": "/api/v1/accounts",
        "status": 200,
        "src_ip": "203.0.113.20",
        "dest_ip": "192.0.2.10",
        "user": "client-app",
        "user_agent": "Mozilla/5.0",
        "bytes": 1820,
        "level": "info",
    },
    {
        "timestamp": base_time.replace(minute=3).isoformat(),
        "event_type": "auth",
        "action": "login_failed",
        "method": "POST",
        "path": "/login",
        "status": 401,
        "src_ip": "203.0.113.21",
        "dest_ip": "192.0.2.10",
        "user": "unknown",
        "user_agent": "curl/7.88",
        "bytes": 412,
        "level": "warning",
    },
    {
        "timestamp": base_time.replace(minute=6).isoformat(),
        "event_type": "rate_limit",
        "action": "limit_exceeded",
        "method": "GET",
        "path": "/api/v1/transactions",
        "status": 429,
        "src_ip": "203.0.113.22",
        "dest_ip": "192.0.2.10",
        "user": "partner-api",
        "user_agent": "okhttp/4.11",
        "bytes": 128,
        "level": "warning",
    },
    {
        "timestamp": base_time.replace(minute=9).isoformat(),
        "event_type": "attack",
        "action": "sqli_detected",
        "method": "GET",
        "path": "/api/v1/search?q=1%27%20OR%20%271%27=%271",
        "status": 400,
        "src_ip": "203.0.113.23",
        "dest_ip": "192.0.2.10",
        "user": "unknown",
        "user_agent": "sqlmap/1.7",
        "bytes": 980,
        "level": "error",
    },
    {
        "timestamp": base_time.replace(minute=12).isoformat(),
        "event_type": "attack",
        "action": "param_tamper",
        "method": "POST",
        "path": "/api/v1/transfer",
        "status": 422,
        "src_ip": "203.0.113.24",
        "dest_ip": "192.0.2.10",
        "user": "client-app",
        "user_agent": "Mozilla/5.0",
        "bytes": 7210,
        "level": "warning",
        "abnormal_payload_size": True,
    },
    {
        "timestamp": base_time.replace(minute=15).isoformat(),
        "event_type": "auth",
        "action": "bruteforce_suspected",
        "method": "POST",
        "path": "/login",
        "status": 401,
        "src_ip": "203.0.113.25",
        "dest_ip": "192.0.2.10",
        "user": "unknown",
        "user_agent": "hydra",
        "bytes": 350,
        "level": "warning",
    },
    {
        "timestamp": base_time.replace(minute=18).isoformat(),
        "event_type": "access",
        "action": "rest_request",
        "method": "PUT",
        "path": "/api/v1/profile",
        "status": 200,
        "src_ip": "203.0.113.26",
        "dest_ip": "192.0.2.10",
        "user": "asmith",
        "user_agent": "Mozilla/5.0",
        "bytes": 1450,
        "level": "info",
    },
    {
        "timestamp": base_time.replace(minute=21).isoformat(),
        "event_type": "access",
        "action": "rest_request",
        "method": "GET",
        "path": "/api/v1/balance",
        "status": 503,
        "src_ip": "203.0.113.27",
        "dest_ip": "192.0.2.10",
        "user": "partner-api",
        "user_agent": "okhttp/4.11",
        "bytes": 210,
        "level": "error",
    },
    {
        "timestamp": base_time.replace(minute=24).isoformat(),
        "event_type": "attack",
        "action": "payload_size_anomaly",
        "method": "POST",
        "path": "/api/v1/upload",
        "status": 413,
        "src_ip": "203.0.113.28",
        "dest_ip": "192.0.2.10",
        "user": "unknown",
        "user_agent": "python-requests/2.31",
        "bytes": 2500000,
        "level": "warning",
    },
    {
        "timestamp": base_time.replace(minute=27).isoformat(),
        "event_type": "access",
        "action": "rest_request",
        "method": "DELETE",
        "path": "/api/v1/beneficiaries/123",
        "status": 204,
        "src_ip": "203.0.113.29",
        "dest_ip": "192.0.2.10",
        "user": "admin-portal",
        "user_agent": "Mozilla/5.0",
        "bytes": 120,
        "level": "info",
    },
]

cef_events = [
    {
        "timestamp": base_time.replace(minute=1).isoformat(),
        "cef": "CEF:0|BankPortal|WAF|2.1|1001|REST access|3|src=203.0.113.20 dst=192.0.2.10 spt=52314 dpt=443 requestMethod=GET request=/api/v1/accounts msg=REST access success",
    },
    {
        "timestamp": base_time.replace(minute=4).isoformat(),
        "cef": "CEF:0|BankPortal|WAF|2.1|1002|Failed auth|5|src=203.0.113.21 dst=192.0.2.10 spt=52315 dpt=443 requestMethod=POST request=/login msg=Bad credentials",
    },
    {
        "timestamp": base_time.replace(minute=7).isoformat(),
        "cef": "CEF:0|BankPortal|WAF|2.1|1003|Rate limit|6|src=203.0.113.22 dst=192.0.2.10 requestMethod=GET request=/api/v1/transactions msg=Rate limit exceeded",
    },
    {
        "timestamp": base_time.replace(minute=10).isoformat(),
        "cef": "CEF:0|BankPortal|WAF|2.1|1004|SQLi detected|9|src=203.0.113.23 dst=192.0.2.10 requestMethod=GET request=/api/v1/search msg=SQLi pattern detected",
    },
    {
        "timestamp": base_time.replace(minute=13).isoformat(),
        "cef": "CEF:0|BankPortal|WAF|2.1|1005|Param tamper|7|src=203.0.113.24 dst=192.0.2.10 requestMethod=POST request=/api/v1/transfer msg=Parameter tampering",
    },
    {
        "timestamp": base_time.replace(minute=16).isoformat(),
        "cef": "CEF:0|BankPortal|WAF|2.1|1006|Brute force|8|src=203.0.113.25 dst=192.0.2.10 requestMethod=POST request=/login msg=Brute force suspected",
    },
    {
        "timestamp": base_time.replace(minute=19).isoformat(),
        "cef": "CEF:0|BankPortal|WAF|2.1|1007|REST update|3|src=203.0.113.26 dst=192.0.2.10 requestMethod=PUT request=/api/v1/profile msg=Profile updated",
    },
    {
        "timestamp": base_time.replace(minute=22).isoformat(),
        "cef": "CEF:0|BankPortal|WAF|2.1|1008|Service error|6|src=203.0.113.27 dst=192.0.2.10 requestMethod=GET request=/api/v1/balance msg=Service unavailable",
    },
    {
        "timestamp": base_time.replace(minute=25).isoformat(),
        "cef": "CEF:0|BankPortal|WAF|2.1|1009|Payload anomaly|7|src=203.0.113.28 dst=192.0.2.10 requestMethod=POST request=/api/v1/upload msg=Abnormal payload size",
    },
    {
        "timestamp": base_time.replace(minute=28).isoformat(),
        "cef": "CEF:0|BankPortal|WAF|2.1|1010|Admin delete|4|src=203.0.113.29 dst=192.0.2.10 requestMethod=DELETE request=/api/v1/beneficiaries/123 msg=Beneficiary removed",
    },
]

with open(JSON_OUTPUT, "w", encoding="utf-8") as f:
    for event in json_events:
        f.write(json.dumps(event) + "\n")

with open(CEF_OUTPUT, "w", encoding="utf-8") as f:
    for event in cef_events:
        f.write(event["cef"] + "\n")

print(f"Wrote {len(json_events)} JSON events to {JSON_OUTPUT}")
print(f"Wrote {len(cef_events)} CEF events to {CEF_OUTPUT}")
