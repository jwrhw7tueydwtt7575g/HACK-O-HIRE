#!/usr/bin/env python3
from datetime import datetime, timezone, timedelta

OUTPUT_PATH = "../logs/linux_syslog.log"

base_time = datetime(2026, 2, 20, 11, 0, 0, tzinfo=timezone.utc)

def rfc5424(ts, host, app, pid, msg, msgid="ID47"):
    return f"<34>1 {ts.isoformat()} {host} {app} {pid} {msgid} - {msg}"

entries = [
    rfc5424(base_time, "linux-core-01", "sshd", 2412, "Failed password for invalid user admin from 203.0.113.40 port 44210 ssh2"),
    rfc5424(base_time + timedelta(minutes=2), "linux-core-01", "sshd", 2413, "Accepted password for ops from 203.0.113.41 port 44211 ssh2"),
    rfc5424(base_time + timedelta(minutes=4), "linux-core-02", "sudo", 312, "ops : TTY=pts/1 ; PWD=/home/ops ; USER=root ; COMMAND=/bin/cat /etc/shadow"),
    rfc5424(base_time + timedelta(minutes=6), "linux-core-02", "cron", 410, "(root) CMD (/usr/local/bin/backup.sh)"),
    rfc5424(base_time + timedelta(minutes=8), "linux-core-03", "auditd", 510, "ANOM_ABEND auid=1001 uid=0 exe=\"/usr/bin/sudo\" msg='kernel exploit attempt'"),
    rfc5424(base_time + timedelta(minutes=10), "linux-core-03", "sshd", 2414, "Failed password for root from 203.0.113.42 port 55220 ssh2"),
    rfc5424(base_time + timedelta(minutes=12), "linux-core-04", "sudo", 313, "audit : TTY=pts/0 ; PWD=/ ; USER=root ; COMMAND=/bin/chmod 777 /etc/sudoers"),
    rfc5424(base_time + timedelta(minutes=14), "linux-core-04", "cron", 411, "(root) CMD (/usr/bin/apt update)"),
    rfc5424(base_time + timedelta(minutes=16), "linux-core-05", "sshd", 2415, "Accepted publickey for svc-deploy from 203.0.113.43 port 55221 ssh2"),
    rfc5424(base_time + timedelta(minutes=18), "linux-core-05", "auditd", 511, "USER_ACCT pid=2201 uid=0 auid=1002 msg='root login'"),
]

with open(OUTPUT_PATH, "w", encoding="utf-8") as f:
    for line in entries:
        f.write(line + "\n")

print(f"Wrote {len(entries)} syslog lines to {OUTPUT_PATH}")
