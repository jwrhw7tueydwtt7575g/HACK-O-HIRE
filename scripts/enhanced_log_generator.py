#!/usr/bin/env python3
"""
Enhanced Banking Log Data Generator
Supports: Live Stream, File Upload, Batch Generation
"""

import json
import random
import socket
import time
import argparse
import sys
from pathlib import Path
from datetime import datetime, timedelta
from typing import Dict, List, Optional
import hashlib
import uuid
import requests


class EnhancedLogGenerator:
    """
    Advanced log generator with multiple ingestion modes:
    1. Live Stream to Vector TCP/UDP
    2. HTTP POST to Vector API
    3. File generation for batch upload
    4. Kafka streaming (optional)
    """
    
    def __init__(self, mode="stream", output_path=None):
        self.mode = mode
        self.output_path = output_path
        self.socket_connection = None
        
        # Sample data pools
        self.users = [f"user{i:04d}" for i in range(1, 1001)]
        self.admin_users = ["admin001", "admin002", "sysadmin", "dbadmin", "root"]
        self.accounts = [f"ACC{i:010d}" for i in range(1, 10001)]
        self.ips_internal = [f"10.0.{random.randint(1,50)}.{random.randint(1,254)}" for _ in range(100)]
        self.ips_external = self._generate_external_ips()
        self.hostnames = [
            "core-banking-01", "core-banking-02", "api-gateway-01",
            "db-prod-01", "db-prod-02", "web-portal-01", "payment-01",
            "swift-01", "ad-dc-01", "fw-perimeter-01"
        ]
        
        # Attack scenarios data
        self.malicious_ips = [
            "185.220.101.1", "45.33.32.156", "192.42.116.16",
            "103.253.145.28", "91.219.236.197"
        ]
        self.attack_patterns = {
            "sql_injection": ["' OR '1'='1", "UNION SELECT", "DROP TABLE"],
            "xss": ["<script>alert", "javascript:", "onerror="],
            "path_traversal": ["../../../etc/passwd", "..\\..\\windows\\system32"],
            "command_injection": ["; cat /etc/passwd", "| whoami", "&& net user"]
        }
    
    def _generate_external_ips(self) -> List[str]:
        """Generate realistic external IP addresses"""
        ips = []
        # Legitimate IPs
        for _ in range(40):
            ips.append(f"{random.randint(1,223)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}")
        # Known malicious IPs (for testing)
        ips.extend([
            "185.220.101.1", "45.33.32.156", "192.42.116.16",
            "103.253.145.28", "91.219.236.197"
        ])
        return ips
    
    # =========================================================================
    # CONNECTION METHODS
    # =========================================================================
    
    def connect_stream(self, host="localhost", port=5140):
        """Connect to Vector TCP stream"""
        try:
            self.socket_connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket_connection.connect((host, port))
            print(f"✅ Connected to Vector stream at {host}:{port}")
            return True
        except Exception as e:
            print(f"❌ Failed to connect to stream: {e}")
            return False
    
    def send_to_stream(self, log: Dict):
        """Send log to TCP stream"""
        if self.socket_connection:
            try:
                log_json = json.dumps(log) + "\n"
                self.socket_connection.sendall(log_json.encode('utf-8'))
            except Exception as e:
                print(f"Error sending to stream: {e}")
    
    def send_to_http(self, log: Dict, url="http://localhost:8080/api/logs"):
        """Send log via HTTP POST"""
        try:
            response = requests.post(
                url,
                json=log,
                headers={"Content-Type": "application/json"},
                timeout=5
            )
            return response.status_code == 200
        except Exception as e:
            print(f"Error sending to HTTP: {e}")
            return False
    
    def write_to_file(self, log: Dict):
        """Write log to file"""
        if self.output_path:
            with open(self.output_path, 'a') as f:
                f.write(json.dumps(log) + "\n")
    
    def send_log(self, log: Dict, **kwargs):
        """Universal log sender based on mode"""
        if self.mode == "stream":
            self.send_to_stream(log)
        elif self.mode == "http":
            url = kwargs.get('url', 'http://localhost:8080/api/logs')
            self.send_to_http(log, url)
        elif self.mode == "file":
            self.write_to_file(log)
        elif self.mode == "both":
            self.send_to_stream(log)
            self.write_to_file(log)
    
    # =========================================================================
    # LOG GENERATORS (Enhanced with more realistic data)
    # =========================================================================
    
    def generate_core_banking_transaction(self, anomaly=False) -> Dict:
        """Generate core banking transaction log"""
        transaction_types = ["TRANSFER", "WITHDRAWAL", "DEPOSIT", "PAYMENT", "LOAN", "INVESTMENT"]
        
        if anomaly:
            amount = random.uniform(50000, 500000)
            status = random.choice(["SUCCESS", "BLOCKED", "FLAGGED", "UNDER_REVIEW"])
            after_hours = True
        else:
            amount = random.uniform(10, 5000)
            status = "SUCCESS"
            after_hours = False
        
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
            "session_id": hashlib.md5(str(time.time()).encode()).hexdigest(),
            "after_hours": after_hours,
            "location": random.choice(["NY", "CA", "TX", "FL", "IL"]),
            "channel": random.choice(["web", "mobile", "atm", "branch", "api"])
        }
    
    def generate_windows_security_event(self, anomaly=False) -> Dict:
        """Generate Windows security event"""
        event_ids = {
            4624: "Successful logon",
            4625: "Failed logon",
            4672: "Special privileges assigned",
            4768: "Kerberos TGT requested",
            4769: "Kerberos service ticket requested",
            4771: "Kerberos pre-authentication failed"
        }
        
        if anomaly:
            event_id = random.choice([4625, 4672, 4771])
            logon_type = random.choice([10, 3])  # Remote, Network
            failure_reason = "Bad password" if event_id in [4625, 4771] else None
            source_ip = random.choice(self.malicious_ips)
        else:
            event_id = random.choice([4624, 4768, 4769])
            logon_type = 2  # Interactive
            failure_reason = None
            source_ip = random.choice(self.ips_internal)
        
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
            "source_ip": source_ip,
            "workstation_name": f"WS{random.randint(1,100):03d}",
            "failure_reason": failure_reason,
            "process_name": random.choice(["explorer.exe", "powershell.exe", "cmd.exe", "winlogon.exe"])
        }
    
    def generate_api_access_log(self, anomaly=False) -> Dict:
        """Generate API access log with potential attacks"""
        endpoints = [
            "/api/v1/accounts/balance",
            "/api/v1/transactions/transfer",
            "/api/v1/user/profile",
            "/api/v1/cards/list",
            "/api/v1/admin/users",
            "/api/v1/reports/download"
        ]
        
        if anomaly:
            endpoint = random.choice(["/api/v1/admin/users", "/api/v1/reports/download"])
            status = random.choice([401, 403, 500])
            response_time = random.uniform(1000, 5000)
            # Inject attack patterns
            if random.random() > 0.5:
                attack_type = random.choice(list(self.attack_patterns.keys()))
                endpoint += "?" + random.choice(self.attack_patterns[attack_type])
        else:
            endpoint = random.choice(endpoints[:-2])
            status = random.choice([200, 201])
            response_time = random.uniform(50, 500)
        
        return {
            "timestamp": datetime.now().isoformat(),
            "source": "api_gateway",
            "event_category": "api_access",
            "method": random.choice(["GET", "POST", "PUT", "DELETE"]),
            "endpoint": endpoint,
            "status_code": status,
            "response_time_ms": round(response_time, 2),
            "user_id": random.choice(self.users),
            "source_ip": random.choice(self.ips_external if anomaly else self.ips_internal),
            "user_agent": random.choice([
                "BankingApp/2.1.0 (iOS 17.2)",
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
                "curl/7.68.0",
                "python-requests/2.28.0"
            ]),
            "request_id": str(uuid.uuid4()),
            "hostname": "api-gateway-01",
            "bytes_sent": random.randint(100, 50000),
            "bytes_received": random.randint(50, 5000)
        }
    
    def generate_database_audit_log(self, anomaly=False) -> Dict:
        """Generate database audit log"""
        operations = ["SELECT", "INSERT", "UPDATE", "DELETE", "CREATE", "DROP", "GRANT", "REVOKE"]
        tables = ["customers", "accounts", "transactions", "users", "audit_log", "session_tokens"]
        
        if anomaly:
            operation = random.choice(["DROP", "GRANT", "DELETE", "TRUNCATE"])
            table = random.choice(["customers", "accounts", "users"])
            rows_affected = random.randint(100, 10000)
            query_contains_sensitive = True
        else:
            operation = random.choice(["SELECT", "INSERT", "UPDATE"])
            table = random.choice(tables)
            rows_affected = random.randint(1, 10)
            query_contains_sensitive = False
        
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
            "privileged_operation": anomaly,
            "query_contains_sensitive": query_contains_sensitive,
            "connection_id": random.randint(1000, 9999)
        }
    
    def generate_firewall_log(self, anomaly=False) -> Dict:
        """Generate firewall log with threat detection"""
        if anomaly:
            action = random.choice(["DENY", "DROP"])
            dst_port = random.choice([22, 23, 3389, 445, 1433, 3306])
            threat_detected = True
            signature = random.choice([
                "PORT_SCAN", "SQL_INJECTION_ATTEMPT", "BRUTE_FORCE",
                "DDoS_ATTEMPT", "MALWARE_C2_COMMUNICATION"
            ])
            src_ip = random.choice(self.malicious_ips)
        else:
            action = "ALLOW"
            dst_port = random.choice([80, 443, 8080, 8443])
            threat_detected = False
            signature = None
            src_ip = random.choice(self.ips_external)
        
        return {
            "timestamp": datetime.now().isoformat(),
            "source": "firewall",
            "event_category": "network_security",
            "action": action,
            "protocol": random.choice(["TCP", "UDP", "ICMP"]),
            "src_ip": src_ip,
            "dst_ip": random.choice(self.ips_internal),
            "src_port": random.randint(1024, 65535),
            "dst_port": dst_port,
            "bytes_sent": random.randint(100, 100000),
            "packets": random.randint(1, 1000),
            "threat_detected": threat_detected,
            "signature": signature,
            "hostname": "fw-perimeter-01",
            "rule_id": f"FW-{random.randint(1000, 9999)}",
            "severity": "high" if threat_detected else "low"
        }
    
    # =========================================================================
    # BATCH GENERATION METHODS
    # =========================================================================
    
    def generate_batch(self, count=1000, anomaly_rate=0.1, output_file=None):
        """Generate batch of logs and save to file"""
        print(f"📦 Generating {count} logs with {anomaly_rate*100}% anomaly rate...")
        
        output_path = output_file or f"banking_logs_{datetime.now().strftime('%Y%m%d_%H%M%S')}.jsonl"
        
        generators = [
            self.generate_core_banking_transaction,
            self.generate_windows_security_event,
            self.generate_api_access_log,
            self.generate_database_audit_log,
            self.generate_firewall_log
        ]
        
        with open(output_path, 'w') as f:
            for i in range(count):
                generator = random.choice(generators)
                is_anomaly = random.random() < anomaly_rate
                log = generator(anomaly=is_anomaly)
                f.write(json.dumps(log) + "\n")
                
                if (i + 1) % 100 == 0:
                    print(f"  Generated {i + 1}/{count} logs...")
        
        print(f"✅ Batch generation complete: {output_path}")
        return output_path
    
    def stream_from_file(self, input_file, rate=10, loop=False):
        """Stream logs from file to Vector"""
        print(f"📤 Streaming logs from {input_file} at {rate} logs/sec...")
        
        if not self.socket_connection:
            print("❌ Not connected to stream. Call connect_stream() first.")
            return
        
        while True:
            try:
                with open(input_file, 'r') as f:
                    for line in f:
                        log = json.loads(line.strip())
                        self.send_to_stream(log)
                        time.sleep(1.0 / rate)
                
                if not loop:
                    break
                
                print("🔄 Restarting file stream...")
                
            except KeyboardInterrupt:
                print("\n⏹️  Stream stopped")
                break
            except Exception as e:
                print(f"❌ Error streaming: {e}")
                break
    
    # =========================================================================
    # SCENARIO-BASED GENERATION
    # =========================================================================
    
    def simulate_brute_force_attack(self, duration=60):
        """Simulate brute force attack scenario"""
        print(f"⚠️  Simulating brute force attack for {duration} seconds...")
        
        target_user = random.choice(self.admin_users)
        attacker_ip = random.choice(self.malicious_ips)
        
        end_time = time.time() + duration
        attempt = 0
        
        while time.time() < end_time:
            log = {
                "timestamp": datetime.now().isoformat(),
                "source": "windows_security",
                "event_category": "authentication",
                "event_id": 4625,
                "event_description": "Failed logon",
                "user_name": target_user,
                "source_ip": attacker_ip,
                "logon_type": 3,
                "failure_reason": "Bad password",
                "attempt_number": attempt
            }
            
            self.send_log(log)
            attempt += 1
            time.sleep(0.5)
        
        print(f"✅ Brute force simulation complete: {attempt} attempts")
    
    def simulate_data_exfiltration(self, duration=60):
        """Simulate data exfiltration scenario"""
        print(f"⚠️  Simulating data exfiltration for {duration} seconds...")
        
        malicious_user = random.choice(self.admin_users)
        target_tables = ["customers", "accounts", "transactions"]
        
        end_time = time.time() + duration
        
        while time.time() < end_time:
            for table in target_tables:
                log = {
                    "timestamp": datetime.now().isoformat(),
                    "source": "database",
                    "event_category": "database_audit",
                    "operation": "SELECT",
                    "table": table,
                    "user": malicious_user,
                    "rows_affected": random.randint(10000, 50000),
                    "query_time_ms": random.uniform(5000, 15000),
                    "privileged_operation": True,
                    "query_contains_sensitive": True,
                    "after_hours": True
                }
                
                self.send_log(log)
                time.sleep(2)
        
        print("✅ Data exfiltration simulation complete")
    
    def close(self):
        """Close connections"""
        if self.socket_connection:
            self.socket_connection.close()
            print("🔌 Disconnected from stream")


# =============================================================================
# FILE UPLOADER FOR BATCH INGESTION
# =============================================================================

class LogFileUploader:
    """Upload log files to Vector HTTP endpoint"""
    
    def __init__(self, vector_url="http://localhost:8080/api/logs"):
        self.vector_url = vector_url
    
    def upload_file(self, file_path, batch_size=100):
        """Upload log file in batches"""
        print(f"📤 Uploading {file_path} to Vector...")
        
        total_sent = 0
        batch = []
        
        try:
            with open(file_path, 'r') as f:
                for line in f:
                    log = json.loads(line.strip())
                    batch.append(log)
                    
                    if len(batch) >= batch_size:
                        self._send_batch(batch)
                        total_sent += len(batch)
                        batch = []
                        print(f"  Sent {total_sent} logs...")
                
                # Send remaining logs
                if batch:
                    self._send_batch(batch)
                    total_sent += len(batch)
            
            print(f"✅ Upload complete: {total_sent} logs sent")
            
        except Exception as e:
            print(f"❌ Upload failed: {e}")
    
    def _send_batch(self, batch):
        """Send batch of logs"""
        try:
            response = requests.post(
                self.vector_url,
                json=batch,
                headers={"Content-Type": "application/json"},
                timeout=30
            )
            
            if response.status_code != 200:
                print(f"⚠️  Batch upload warning: HTTP {response.status_code}")
                
        except Exception as e:
            print(f"❌ Batch upload error: {e}")


# =============================================================================
# COMMAND LINE INTERFACE
# =============================================================================

def main():
    parser = argparse.ArgumentParser(
        description="Enhanced Banking Log Generator with Multiple Ingestion Modes"
    )
    
    parser.add_argument(
        '--mode',
        choices=['stream', 'http', 'file', 'both', 'upload'],
        default='stream',
        help='Ingestion mode'
    )
    
    parser.add_argument(
        '--host',
        default='localhost',
        help='Vector host (for stream mode)'
    )
    
    parser.add_argument(
        '--port',
        type=int,
        default=5140,
        help='Vector port (for stream mode)'
    )
    
    parser.add_argument(
        '--url',
        default='http://localhost:8080/api/logs',
        help='Vector HTTP endpoint'
    )
    
    parser.add_argument(
        '--action',
        choices=['generate', 'stream-file', 'scenario', 'batch'],
        default='generate',
        help='Action to perform'
    )
    
    parser.add_argument(
        '--scenario',
        choices=['brute_force', 'data_exfiltration', 'normal'],
        default='normal',
        help='Attack scenario to simulate'
    )
    
    parser.add_argument(
        '--duration',
        type=int,
        default=60,
        help='Duration in seconds'
    )
    
    parser.add_argument(
        '--rate',
        type=int,
        default=10,
        help='Logs per second'
    )
    
    parser.add_argument(
        '--count',
        type=int,
        default=1000,
        help='Number of logs for batch generation'
    )
    
    parser.add_argument(
        '--input-file',
        help='Input file for streaming or uploading'
    )
    
    parser.add_argument(
        '--output-file',
        help='Output file for batch generation'
    )
    
    parser.add_argument(
        '--anomaly-rate',
        type=float,
        default=0.1,
        help='Anomaly rate (0.0 to 1.0)'
    )
    
    args = parser.parse_args()
    
    # Execute based on action
    if args.action == 'batch':
        # Batch generation
        generator = EnhancedLogGenerator(mode='file', output_path=args.output_file)
        generator.generate_batch(
            count=args.count,
            anomaly_rate=args.anomaly_rate,
            output_file=args.output_file
        )
    
    elif args.action == 'stream-file':
        # Stream from file
        generator = EnhancedLogGenerator(mode=args.mode)
        
        if args.mode == 'stream':
            if generator.connect_stream(args.host, args.port):
                generator.stream_from_file(args.input_file, rate=args.rate)
        elif args.mode == 'http':
            generator.stream_from_file(args.input_file, rate=args.rate)
        
        generator.close()
    
    elif args.action == 'scenario':
        # Run attack scenario
        generator = EnhancedLogGenerator(mode=args.mode)
        
        if args.mode == 'stream' and not generator.connect_stream(args.host, args.port):
            print("Failed to connect")
            sys.exit(1)
        
        if args.scenario == 'brute_force':
            generator.simulate_brute_force_attack(duration=args.duration)
        elif args.scenario == 'data_exfiltration':
            generator.simulate_data_exfiltration(duration=args.duration)
        
        generator.close()
    
    elif args.mode == 'upload':
        # Upload file
        uploader = LogFileUploader(vector_url=args.url)
        uploader.upload_file(args.input_file or 'banking_logs.jsonl')
    
    else:
        # Continuous generation
        generator = EnhancedLogGenerator(mode=args.mode, output_path=args.output_file)
        
        if args.mode in ['stream', 'both']:
            if not generator.connect_stream(args.host, args.port):
                print("Failed to connect")
                sys.exit(1)
        
        print(f"🚀 Starting continuous log generation...")
        print(f"   Mode: {args.mode}")
        print(f"   Rate: {args.rate} logs/sec")
        print(f"   Press Ctrl+C to stop")
        
        generators = [
            generator.generate_core_banking_transaction,
            generator.generate_windows_security_event,
            generator.generate_api_access_log,
            generator.generate_database_audit_log,
            generator.generate_firewall_log
        ]
        
        try:
            count = 0
            while True:
                gen_func = random.choice(generators)
                is_anomaly = random.random() < args.anomaly_rate
                log = gen_func(anomaly=is_anomaly)
                generator.send_log(log, url=args.url)
                
                count += 1
                if count % 100 == 0:
                    print(f"  Generated {count} logs...")
                
                time.sleep(1.0 / args.rate)
                
        except KeyboardInterrupt:
            print(f"\n✅ Stopped after generating {count} logs")
        
        generator.close()


if __name__ == "__main__":
    main()
