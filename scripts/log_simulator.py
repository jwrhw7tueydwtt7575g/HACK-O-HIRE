#!/usr/bin/env python3
"""
Banking Environment Log Simulator
Generates realistic banking logs for SOC testing
"""

import json
import random
import socket
import time
from datetime import datetime, timedelta
from typing import Dict, List
import hashlib
import uuid


class BankingLogSimulator:
    """Simulates heterogeneous banking environment logs"""
    
    def __init__(self, vector_host="localhost", vector_port=5140):
        self.vector_host = vector_host
        self.vector_port = vector_port
        self.sock = None
        
        # Sample data pools
        self.users = [f"user{i:04d}" for i in range(1, 1001)]
        self.admin_users = ["admin001", "admin002", "sysadmin", "dbadmin"]
        self.accounts = [f"ACC{i:010d}" for i in range(1, 10001)]
        self.ips_internal = [f"10.0.{random.randint(1,50)}.{random.randint(1,254)}" for _ in range(100)]
        self.ips_external = [f"{random.randint(1,223)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}" for _ in range(50)]
        self.hostnames = [
            "core-banking-01", "core-banking-02", "api-gateway-01",
            "db-prod-01", "db-prod-02", "web-portal-01", "payment-01",
            "swift-01", "ad-dc-01", "fw-perimeter-01"
        ]
        
    def connect(self):
        """Connect to Vector ingestion endpoint"""
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.connect((self.vector_host, self.vector_port))
        print(f"✅ Connected to Vector at {self.vector_host}:{self.vector_port}")
    
    def send_log(self, log: Dict):
        """Send log to Vector"""
        log_json = json.dumps(log) + "\n"
        self.sock.sendall(log_json.encode('utf-8'))
    
    def generate_core_banking_transaction(self, anomaly=False) -> Dict:
        """Generate core banking transaction log"""
        transaction_types = ["TRANSFER", "WITHDRAWAL", "DEPOSIT", "PAYMENT", "LOAN"]
        
        if anomaly:
            # Suspicious transaction
            amount = random.uniform(50000, 500000)  # Large amount
            status = random.choice(["SUCCESS", "BLOCKED", "FLAGGED"])
        else:
            amount = random.uniform(10, 5000)
            status = "SUCCESS"
        
        return {
            "timestamp": datetime.now().isoformat(),
            "source": "core_banking",
            "event_category": "banking_transaction",
            "transaction_id": str(uuid.uuid4()),
            "transaction_type": random.choice(transaction_types),
            "from_account": random.choice(self.accounts),
            "to_account": random.choice(self.accounts),
            "amount": round(amount, 2),
            "currency": "USD",
            "status": status,
            "user_id": random.choice(self.users if not anomaly else self.admin_users),
            "source_ip": random.choice(self.ips_internal),
            "hostname": "core-banking-01",
            "session_id": hashlib.md5(str(time.time()).encode()).hexdigest()
        }
    
    def generate_windows_security_event(self, anomaly=False) -> Dict:
        """Generate Windows security event (4624/4625/4672)"""
        event_ids = {
            4624: "An account was successfully logged on",
            4625: "An account failed to log on",
            4672: "Special privileges assigned to new logon",
            4768: "A Kerberos authentication ticket (TGT) was requested",
            4769: "A Kerberos service ticket was requested"
        }
        
        if anomaly:
            # Failed login attempts or privileged access
            event_id = random.choice([4625, 4672])
            logon_type = random.choice([10, 3])  # Remote, Network
            failure_reason = "Bad password" if event_id == 4625 else None
        else:
            event_id = 4624
            logon_type = 2  # Interactive
            failure_reason = None
        
        return {
            "timestamp": datetime.now().isoformat(),
            "source": "windows_security",
            "event_category": "authentication",
            "event_id": event_id,
            "event_description": event_ids[event_id],
            "computer_name": random.choice(self.hostnames),
            "user_name": random.choice(self.users if not anomaly else self.admin_users),
            "domain": "BANK",
            "logon_type": logon_type,
            "source_ip": random.choice(self.ips_external if anomaly else self.ips_internal),
            "workstation_name": f"WS{random.randint(1,100):03d}",
            "failure_reason": failure_reason
        }
    
    def generate_active_directory_event(self, anomaly=False) -> Dict:
        """Generate Active Directory event"""
        ad_events = {
            4720: "A user account was created",
            4722: "A user account was enabled",
            4724: "An attempt was made to reset an account's password",
            4732: "A member was added to a security-enabled local group",
            4756: "A member was added to a security-enabled universal group"
        }
        
        event_id = random.choice(list(ad_events.keys()))
        
        return {
            "timestamp": datetime.now().isoformat(),
            "source": "active_directory",
            "event_category": "account_management",
            "event_id": event_id,
            "event_description": ad_events[event_id],
            "dc_name": "ad-dc-01.bank.local",
            "target_user": random.choice(self.users),
            "actor_user": random.choice(self.admin_users),
            "source_ip": random.choice(self.ips_internal),
            "privileged_operation": anomaly
        }
    
    def generate_api_access_log(self, anomaly=False) -> Dict:
        """Generate API/Web access log"""
        endpoints = [
            "/api/v1/accounts/balance",
            "/api/v1/transactions/transfer",
            "/api/v1/user/profile",
            "/api/v1/cards/list",
            "/api/v1/admin/users"  # Privileged endpoint
        ]
        
        methods = ["GET", "POST", "PUT", "DELETE"]
        status_codes = [200, 201, 400, 401, 403, 404, 500]
        
        if anomaly:
            endpoint = "/api/v1/admin/users"
            status = random.choice([401, 403])
            response_time = random.uniform(1000, 3000)
        else:
            endpoint = random.choice(endpoints[:-1])
            status = random.choice([200, 201])
            response_time = random.uniform(50, 500)
        
        return {
            "timestamp": datetime.now().isoformat(),
            "source": "api_gateway",
            "event_category": "api_access",
            "method": random.choice(methods),
            "endpoint": endpoint,
            "status_code": status,
            "response_time_ms": round(response_time, 2),
            "user_id": random.choice(self.users),
            "source_ip": random.choice(self.ips_external),
            "user_agent": "BankingApp/2.1.0 (iOS 17.2)",
            "request_id": str(uuid.uuid4()),
            "hostname": "api-gateway-01"
        }
    
    def generate_database_audit_log(self, anomaly=False) -> Dict:
        """Generate database audit log"""
        operations = ["SELECT", "INSERT", "UPDATE", "DELETE", "CREATE", "DROP", "GRANT"]
        tables = ["customers", "accounts", "transactions", "users", "audit_log"]
        
        if anomaly:
            operation = random.choice(["DROP", "GRANT", "DELETE"])
            table = random.choice(["customers", "accounts", "users"])
            rows_affected = random.randint(100, 10000)
        else:
            operation = random.choice(["SELECT", "INSERT", "UPDATE"])
            table = random.choice(tables)
            rows_affected = random.randint(1, 10)
        
        return {
            "timestamp": datetime.now().isoformat(),
            "source": "database",
            "event_category": "database_audit",
            "operation": operation,
            "table": table,
            "database": "banking_prod",
            "user": random.choice(self.admin_users if anomaly else self.users),
            "source_ip": random.choice(self.ips_internal),
            "hostname": "db-prod-01",
            "rows_affected": rows_affected,
            "query_time_ms": random.uniform(10, 1000),
            "privileged_operation": anomaly
        }
    
    def generate_firewall_log(self, anomaly=False) -> Dict:
        """Generate firewall/IDS log"""
        actions = ["ALLOW", "DENY", "DROP"]
        protocols = ["TCP", "UDP", "ICMP"]
        
        if anomaly:
            action = random.choice(["DENY", "DROP"])
            dst_port = random.choice([22, 23, 3389, 445])  # Common attack ports
            threat_detected = True
        else:
            action = "ALLOW"
            dst_port = random.choice([80, 443, 8080])
            threat_detected = False
        
        return {
            "timestamp": datetime.now().isoformat(),
            "source": "firewall",
            "event_category": "network_security",
            "action": action,
            "protocol": random.choice(protocols),
            "src_ip": random.choice(self.ips_external),
            "dst_ip": random.choice(self.ips_internal),
            "src_port": random.randint(1024, 65535),
            "dst_port": dst_port,
            "bytes_sent": random.randint(100, 10000),
            "packets": random.randint(1, 100),
            "threat_detected": threat_detected,
            "signature": "PORT_SCAN" if threat_detected else None,
            "hostname": "fw-perimeter-01"
        }
    
    def generate_cloud_audit_log(self, anomaly=False) -> Dict:
        """Generate CloudTrail-style audit log"""
        services = ["IAM", "S3", "EC2", "RDS", "Lambda"]
        events = [
            "CreateUser", "DeleteUser", "PutObject", "GetObject",
            "StartInstances", "StopInstances", "ModifyDBInstance"
        ]
        
        if anomaly:
            event_name = random.choice(["DeleteUser", "ModifyDBInstance", "StopInstances"])
            error_code = None if random.random() > 0.5 else "AccessDenied"
        else:
            event_name = random.choice(["GetObject", "DescribeInstances"])
            error_code = None
        
        return {
            "timestamp": datetime.now().isoformat(),
            "source": "cloud_audit",
            "event_category": "cloud_api",
            "event_name": event_name,
            "event_source": f"{random.choice(services).lower()}.amazonaws.com",
            "user_identity": {
                "type": "IAMUser",
                "userName": random.choice(self.admin_users if anomaly else self.users),
                "accountId": "123456789012"
            },
            "source_ip": random.choice(self.ips_external),
            "user_agent": "aws-cli/2.13.0",
            "error_code": error_code,
            "request_id": str(uuid.uuid4())
        }
    
    def generate_mainframe_log(self, anomaly=False) -> Dict:
        """Generate mainframe SMF/RACF log"""
        job_names = ["PAYROLL", "BATCH01", "DBUPDATE", "FILETRNS"]
        racf_events = ["LOGIN", "LOGOUT", "ACCESS", "PERMIT", "ADDUSER"]
        
        return {
            "timestamp": datetime.now().isoformat(),
            "source": "mainframe",
            "event_category": "mainframe_security",
            "smf_type": random.choice([80, 83]),
            "job_name": random.choice(job_names),
            "user_id": random.choice(self.admin_users if anomaly else self.users),
            "racf_event": random.choice(racf_events),
            "resource": f"DATASET.PROD.{'SENSITIVE' if anomaly else 'DATA'}",
            "access_type": random.choice(["READ", "WRITE", "ALTER"]),
            "result": random.choice(["SUCCESS", "DENIED"]),
            "terminal": f"T{random.randint(1,100):03d}",
            "privileged": anomaly
        }
    
    def simulate_normal_traffic(self, duration_seconds=60, logs_per_second=10):
        """Simulate normal banking traffic"""
        print(f"🔄 Simulating normal traffic for {duration_seconds} seconds...")
        
        log_generators = [
            self.generate_core_banking_transaction,
            self.generate_windows_security_event,
            self.generate_api_access_log,
            self.generate_database_audit_log,
            self.generate_firewall_log,
            self.generate_cloud_audit_log,
            self.generate_mainframe_log,
            self.generate_active_directory_event
        ]
        
        end_time = time.time() + duration_seconds
        log_count = 0
        
        while time.time() < end_time:
            for _ in range(logs_per_second):
                generator = random.choice(log_generators)
                log = generator(anomaly=False)
                self.send_log(log)
                log_count += 1
            
            time.sleep(1)
            if log_count % 100 == 0:
                print(f"  Generated {log_count} logs...")
        
        print(f"✅ Generated {log_count} normal logs")
    
    def simulate_attack_scenario(self, scenario="brute_force"):
        """Simulate specific attack scenarios"""
        print(f"⚠️  Simulating attack scenario: {scenario}")
        
        if scenario == "brute_force":
            # Multiple failed login attempts
            for _ in range(20):
                log = self.generate_windows_security_event(anomaly=True)
                self.send_log(log)
                time.sleep(0.5)
        
        elif scenario == "privilege_escalation":
            # Suspicious privilege changes
            for _ in range(5):
                log = self.generate_active_directory_event(anomaly=True)
                self.send_log(log)
                time.sleep(1)
        
        elif scenario == "data_exfiltration":
            # Large database queries + suspicious API calls
            for _ in range(10):
                log = self.generate_database_audit_log(anomaly=True)
                self.send_log(log)
                time.sleep(0.5)
        
        elif scenario == "lateral_movement":
            # Multiple internal connections + firewall anomalies
            for _ in range(15):
                log = self.generate_firewall_log(anomaly=True)
                self.send_log(log)
                time.sleep(0.3)
        
        print(f"✅ Attack scenario complete: {scenario}")
    
    def run_continuous_simulation(self):
        """Run continuous simulation with periodic anomalies"""
        print("🚀 Starting continuous banking log simulation...")
        
        try:
            while True:
                # Normal traffic for 5 minutes
                self.simulate_normal_traffic(duration_seconds=300, logs_per_second=20)
                
                # Inject random attack scenario
                scenario = random.choice([
                    "brute_force", "privilege_escalation",
                    "data_exfiltration", "lateral_movement"
                ])
                self.simulate_attack_scenario(scenario)
                
                # Cooldown
                time.sleep(30)
                
        except KeyboardInterrupt:
            print("\n🛑 Simulation stopped")
    
    def close(self):
        """Close connection"""
        if self.sock:
            self.sock.close()
            print("🔌 Disconnected from Vector")


if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="Banking Environment Log Simulator")
    parser.add_argument("--host", default="localhost", help="Vector host")
    parser.add_argument("--port", type=int, default=5140, help="Vector port")
    parser.add_argument("--mode", choices=["normal", "attack", "continuous"], default="continuous")
    parser.add_argument("--duration", type=int, default=60, help="Duration in seconds")
    parser.add_argument("--scenario", choices=["brute_force", "privilege_escalation", "data_exfiltration", "lateral_movement"])
    
    args = parser.parse_args()
    
    simulator = BankingLogSimulator(vector_host=args.host, vector_port=args.port)
    simulator.connect()
    
    try:
        if args.mode == "normal":
            simulator.simulate_normal_traffic(duration_seconds=args.duration)
        elif args.mode == "attack":
            simulator.simulate_attack_scenario(scenario=args.scenario or "brute_force")
        elif args.mode == "continuous":
            simulator.run_continuous_simulation()
    finally:
        simulator.close()
