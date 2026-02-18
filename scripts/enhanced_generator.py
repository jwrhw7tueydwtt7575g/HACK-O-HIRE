#!/usr/bin/env python3
"""
Enhanced Log Generator with Multiple Ingestion Modes
Supports: live streaming, file upload, batch processing, historical data
"""

import json
import socket
import time
import argparse
import os
import sys
from pathlib import Path
from datetime import datetime, timedelta
import random
import requests


class EnhancedLogGenerator:
    """Enhanced log generator with multiple modes"""
    
    def __init__(self, vector_host="localhost", vector_port=5140):
        self.vector_host = vector_host
        self.vector_port = vector_port
        self.vector_http_port = 8080
        self.sock = None
        
        # Banking transaction templates
        self.transaction_types = ['TRANSFER', 'WITHDRAWAL', 'DEPOSIT', 'PAYMENT', 'LOAN_DISBURSEMENT']
        self.accounts = [f'ACCT{str(i).zfill(10)}' for i in range(1000, 2000)]
        
    def connect(self):
        """Connect to Vector TCP socket"""
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.connect((self.vector_host, self.vector_port))
            print(f"✅ Connected to Vector at {self.vector_host}:{self.vector_port}")
        except Exception as e:
            print(f"❌ Failed to connect: {e}")
            sys.exit(1)
    
    def close(self):
        """Close socket connection"""
        if self.sock:
            self.sock.close()
    
    def send_log(self, log: dict):
        """Send log via TCP"""
        try:
            message = json.dumps(log) + '\n'
            self.sock.sendall(message.encode('utf-8'))
        except Exception as e:
            print(f"Error sending log: {e}")
    
    def generate_banking_transaction(self, anomaly=False):
        """Generate core banking transaction log"""
        amount = random.uniform(10, 100000) if not anomaly else random.uniform(500000, 10000000)
        
        return {
            "timestamp": datetime.now().isoformat(),
            "log_type": "core_banking",
            "transaction_id": f"TXN{random.randint(100000, 999999)}",
            "transaction_type": random.choice(self.transaction_types),
            "source_account": random.choice(self.accounts),
            "destination_account": random.choice(self.accounts),
            "amount": round(amount, 2),
            "currency": "USD",
            "status": "SUCCESS" if not anomaly else random.choice(["SUCCESS", "FAILED", "FLAGGED"]),
            "branch_code": f"BR{random.randint(100, 999)}",
            "teller_id": f"TLR{random.randint(1000, 9999)}",
            "anomaly_flag": anomaly
        }
    
    def generate_windows_event(self, anomaly=False):
        """Generate Windows security event"""
        event_ids = {
            False: [4624, 4672, 4648],  # Normal: logon, special privileges, explicit credentials
            True: [4625, 4740, 4768]     # Anomaly: failed logon, account locked, Kerberos
        }
        
        return {
            "timestamp": datetime.now().isoformat(),
            "log_type": "windows_security",
            "event_id": random.choice(event_ids[anomaly]),
            "hostname": f"WIN-SRV-{random.randint(1, 50):02d}",
            "username": f"user{random.randint(1, 100)}",
            "source_ip": f"10.0.{random.randint(1, 255)}.{random.randint(1, 255)}",
            "logon_type": random.choice([2, 3, 10]),
            "process": "lsass.exe" if not anomaly else random.choice(["mimikatz.exe", "powershell.exe"]),
            "anomaly_flag": anomaly
        }
    
    def generate_api_log(self, anomaly=False):
        """Generate API access log"""
        endpoints = ['/api/accounts', '/api/transactions', '/api/customers', '/api/reports']
        status_codes = [200, 201, 400, 404, 500, 503] if anomaly else [200, 201, 204]
        
        return {
            "timestamp": datetime.now().isoformat(),
            "log_type": "api_access",
            "method": random.choice(['GET', 'POST', 'PUT', 'DELETE']),
            "endpoint": random.choice(endpoints),
            "status_code": random.choice(status_codes),
            "response_time_ms": random.randint(10, 5000) if anomaly else random.randint(10, 500),
            "client_ip": f"192.168.{random.randint(1, 255)}.{random.randint(1, 255)}",
            "user_agent": "BankingApp/1.0",
            "anomaly_flag": anomaly
        }
    
    def generate_database_log(self, anomaly=False):
        """Generate database audit log"""
        operations = ['SELECT', 'INSERT', 'UPDATE'] if not anomaly else ['DROP', 'TRUNCATE', 'DELETE']
        
        return {
            "timestamp": datetime.now().isoformat(),
            "log_type": "database_audit",
            "operation": random.choice(operations),
            "table": random.choice(['accounts', 'transactions', 'customers', 'audit_log']),
            "user": f"dbuser{random.randint(1, 20)}",
            "rows_affected": random.randint(1, 1000) if anomaly else random.randint(1, 100),
            "duration_ms": random.randint(10, 5000),
            "source_ip": f"10.10.{random.randint(1, 255)}.{random.randint(1, 255)}",
            "anomaly_flag": anomaly
        }
    
    def generate_firewall_log(self, anomaly=False):
        """Generate firewall log"""
        return {
            "timestamp": datetime.now().isoformat(),
            "log_type": "firewall",
            "action": "DENY" if anomaly else random.choice(["ALLOW", "ALLOW"]),
            "source_ip": f"203.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}",
            "dest_ip": f"10.0.{random.randint(1, 255)}.{random.randint(1, 255)}",
            "source_port": random.randint(1024, 65535),
            "dest_port": random.choice([22, 80, 443, 3306, 1433]),
            "protocol": random.choice(['TCP', 'UDP']),
            "bytes_sent": random.randint(100, 100000),
            "threat_detected": anomaly,
            "anomaly_flag": anomaly
        }
    
    def generate_cloud_log(self, anomaly=False):
        """Generate cloud audit log"""
        actions = ['AssumeRole', 'CreateAccessKey'] if anomaly else ['GetObject', 'PutObject', 'ListBuckets']
        
        return {
            "timestamp": datetime.now().isoformat(),
            "log_type": "cloud_audit",
            "event_name": random.choice(actions),
            "service": random.choice(['IAM', 'S3', 'EC2', 'RDS']),
            "user": f"clouduser{random.randint(1, 50)}",
            "source_ip": f"54.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}",
            "resource_arn": f"arn:aws:s3:::banking-prod-{random.randint(1, 10)}",
            "response": "Success" if not anomaly else random.choice(["Success", "AccessDenied"]),
            "anomaly_flag": anomaly
        }
    
    def generate_mainframe_log(self, anomaly=False):
        """Generate mainframe SMF log"""
        return {
            "timestamp": datetime.now().isoformat(),
            "log_type": "mainframe",
            "smf_type": random.choice([14, 15, 30, 80]),
            "job_name": f"JOB{random.randint(1000, 9999)}",
            "user_id": f"MVS{random.randint(100, 999)}",
            "cpu_time": random.randint(1, 1000),
            "io_operations": random.randint(10, 10000) if anomaly else random.randint(10, 1000),
            "dataset_accessed": f"PROD.BANKING.DATA{random.randint(1, 50)}",
            "return_code": 0 if not anomaly else random.choice([4, 8, 12]),
            "anomaly_flag": anomaly
        }
    
    def generate_ad_event(self, anomaly=False):
        """Generate Active Directory event"""
        event_ids = {
            False: [4728, 4732, 4756],  # Normal: group member add
            True: [4720, 4722, 4724]     # Anomaly: user created, enabled, password reset
        }
        
        return {
            "timestamp": datetime.now().isoformat(),
            "log_type": "active_directory",
            "event_id": random.choice(event_ids[anomaly]),
            "domain": "BANKING.LOCAL",
            "target_user": f"ADUser{random.randint(1, 500)}",
            "source_user": f"Admin{random.randint(1, 10)}",
            "group": random.choice(['Domain Admins', 'Enterprise Admins', 'Users']),
            "dc_hostname": f"DC{random.randint(1, 5):02d}",
            "anomaly_flag": anomaly
        }
    
    def generate_batch_file(self, filename: str, num_logs: int = 1000, 
                           include_anomalies: bool = True):
        """Generate batch log file"""
        print(f"🔄 Generating {num_logs} logs to {filename}...")
        
        logs = []
        anomaly_rate = 0.05 if include_anomalies else 0  # 5% anomalies
        
        log_generators = [
            self.generate_banking_transaction,
            self.generate_windows_event,
            self.generate_api_log,
            self.generate_database_log,
            self.generate_firewall_log,
            self.generate_cloud_log,
            self.generate_mainframe_log,
            self.generate_ad_event
        ]
        
        for i in range(num_logs):
            generator = random.choice(log_generators)
            anomaly = random.random() < anomaly_rate
            log = generator(anomaly=anomaly)
            logs.append(log)
            
            if (i + 1) % 100 == 0:
                print(f"  Generated {i + 1}/{num_logs} logs...")
        
        # Write to file
        with open(filename, 'w') as f:
            for log in logs:
                f.write(json.dumps(log) + '\n')
        
        print(f"✅ Generated {num_logs} logs to {filename}")
        print(f"   File size: {os.path.getsize(filename) / 1024 / 1024:.2f} MB")
        
        return filename
    
    def generate_historical_dataset(self, output_dir: str, days: int = 30,
                                   logs_per_day: int = 10000):
        """Generate historical dataset spanning multiple days"""
        print(f"🔄 Generating {days} days of historical data...")
        
        os.makedirs(output_dir, exist_ok=True)
        
        end_date = datetime.now()
        
        for day in range(days):
            date = end_date - timedelta(days=days - day - 1)
            date_str = date.strftime('%Y-%m-%d')
            filename = f"{output_dir}/banking-logs-{date_str}.ndjson"
            
            print(f"  Generating data for {date_str}...")
            
            logs = []
            for _ in range(logs_per_day):
                # Generate timestamp for that day
                hour = random.randint(0, 23)
                minute = random.randint(0, 59)
                second = random.randint(0, 59)
                
                timestamp = date.replace(hour=hour, minute=minute, second=second)
                
                # Generate log
                generator = random.choice([
                    self.generate_banking_transaction,
                    self.generate_windows_event,
                    self.generate_api_log,
                    self.generate_database_log,
                ])
                
                log = generator(anomaly=False)
                log['timestamp'] = timestamp.isoformat()
                logs.append(log)
            
            # Write daily file
            with open(filename, 'w') as f:
                for log in logs:
                    f.write(json.dumps(log) + '\n')
            
            print(f"    ✅ {filename}: {len(logs)} logs")
        
        print(f"✅ Generated {days} days of historical data in {output_dir}/")
    
    def upload_file_to_vector(self, filename: str):
        """Upload log file to Vector via HTTP"""
        print(f"📤 Uploading {filename} to Vector...")
        
        if not os.path.exists(filename):
            print(f"❌ File not found: {filename}")
            return False
        
        # Read and send logs line by line
        sent_count = 0
        error_count = 0
        
        with open(filename, 'r') as f:
            for line_num, line in enumerate(f, 1):
                try:
                    log = json.loads(line.strip())
                    
                    # Send to Vector HTTP endpoint
                    response = requests.post(
                        f"http://{self.vector_host}:{self.vector_http_port}/api/logs",
                        json=log,
                        timeout=5
                    )
                    
                    if response.status_code in [200, 201, 202]:
                        sent_count += 1
                    else:
                        error_count += 1
                    
                    if line_num % 100 == 0:
                        print(f"  Uploaded {line_num} logs... (errors: {error_count})")
                    
                    # Small delay to avoid overwhelming the system
                    time.sleep(0.01)
                    
                except json.JSONDecodeError:
                    print(f"  ⚠️  Invalid JSON at line {line_num}")
                    error_count += 1
                except Exception as e:
                    print(f"  ⚠️  Error at line {line_num}: {e}")
                    error_count += 1
        
        print(f"✅ Upload complete: {sent_count} sent, {error_count} errors")
        return True
    
    def stream_realtime(self, duration_seconds: int = 300, rate: int = 50):
        """Stream logs in real-time"""
        print(f"🔄 Streaming logs for {duration_seconds} seconds at {rate} logs/sec...")
        
        self.connect()
        
        try:
            end_time = time.time() + duration_seconds
            log_count = 0
            
            log_generators = [
                self.generate_banking_transaction,
                self.generate_windows_event,
                self.generate_api_log,
                self.generate_database_log,
            ]
            
            while time.time() < end_time:
                start = time.time()
                
                for _ in range(rate):
                    generator = random.choice(log_generators)
                    log = generator(anomaly=random.random() < 0.05)
                    self.send_log(log)
                    log_count += 1
                
                # Sleep to maintain rate
                elapsed = time.time() - start
                sleep_time = max(0, 1.0 - elapsed)
                time.sleep(sleep_time)
                
                if log_count % (rate * 10) == 0:
                    print(f"  Streamed {log_count} logs...")
            
            print(f"✅ Streamed {log_count} logs")
            
        finally:
            self.close()
    
    def generate_attack_dataset(self, output_dir: str):
        """Generate dataset with various attack scenarios"""
        print(f"🔄 Generating attack scenario dataset...")
        
        os.makedirs(output_dir, exist_ok=True)
        
        scenarios = [
            ('brute_force', 100, self.generate_windows_event),
            ('privilege_escalation', 50, self.generate_ad_event),
            ('data_exfiltration', 75, self.generate_database_log),
            ('lateral_movement', 80, self.generate_firewall_log),
        ]
        
        for scenario_name, num_logs, generator in scenarios:
            filename = f"{output_dir}/attack-{scenario_name}.ndjson"
            print(f"  Generating {scenario_name}...")
            
            logs = []
            for _ in range(num_logs):
                log = generator(anomaly=True)
                logs.append(log)
            
            # Write to file
            with open(filename, 'w') as f:
                for log in logs:
                    f.write(json.dumps(log) + '\n')
            
            print(f"    ✅ {filename}: {len(logs)} logs")
        
        print(f"✅ Generated attack scenarios in {output_dir}/")


def main():
    parser = argparse.ArgumentParser(description="Enhanced Banking Log Generator")
    
    parser.add_argument('--host', default='localhost', help='Vector host')
    parser.add_argument('--port', type=int, default=5140, help='Vector TCP port')
    
    subparsers = parser.add_subparsers(dest='mode', help='Generation mode')
    
    # Live streaming mode
    stream_parser = subparsers.add_parser('stream', help='Stream logs in real-time')
    stream_parser.add_argument('--duration', type=int, default=300, help='Duration in seconds')
    stream_parser.add_argument('--rate', type=int, default=50, help='Logs per second')
    
    # Batch file generation
    batch_parser = subparsers.add_parser('batch', help='Generate batch log file')
    batch_parser.add_argument('--output', required=True, help='Output filename')
    batch_parser.add_argument('--count', type=int, default=1000, help='Number of logs')
    batch_parser.add_argument('--anomalies', action='store_true', help='Include anomalies')
    
    # Historical dataset
    historical_parser = subparsers.add_parser('historical', help='Generate historical dataset')
    historical_parser.add_argument('--output-dir', required=True, help='Output directory')
    historical_parser.add_argument('--days', type=int, default=30, help='Number of days')
    historical_parser.add_argument('--logs-per-day', type=int, default=10000, help='Logs per day')
    
    # Upload file
    upload_parser = subparsers.add_parser('upload', help='Upload log file to Vector')
    upload_parser.add_argument('--file', required=True, help='Log file to upload')
    
    # Attack scenarios
    attack_parser = subparsers.add_parser('attacks', help='Generate attack scenarios')
    attack_parser.add_argument('--output-dir', required=True, help='Output directory')
    
    args = parser.parse_args()
    
    if not args.mode:
        parser.print_help()
        return
    
    generator = EnhancedLogGenerator(args.host, args.port)
    
    if args.mode == 'stream':
        generator.stream_realtime(args.duration, args.rate)
    
    elif args.mode == 'batch':
        generator.generate_batch_file(args.output, args.count, args.anomalies)
    
    elif args.mode == 'historical':
        generator.generate_historical_dataset(args.output_dir, args.days, args.logs_per_day)
    
    elif args.mode == 'upload':
        generator.upload_file_to_vector(args.file)
    
    elif args.mode == 'attacks':
        generator.generate_attack_dataset(args.output_dir)


if __name__ == "__main__":
    main()
