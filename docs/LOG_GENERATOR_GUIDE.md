# 📊 Enhanced Log Generator - Complete Guide

## Overview

The Enhanced Log Generator provides **multiple ingestion modes** for feeding logs into the Banking SOC pipeline:

1. **Live Stream** → Direct TCP/UDP streaming to Vector
2. **HTTP API** → RESTful POST to Vector HTTP endpoint  
3. **File Generation** → Create batch files for later upload
4. **File Upload** → Upload existing log files to Vector
5. **Hybrid Mode** → Stream + File simultaneously

---

## 🚀 Quick Start

### Mode 1: Live Stream (Real-time)

```bash
# Stream logs in real-time to Vector TCP endpoint
python scripts/enhanced_log_generator.py \
  --mode stream \
  --host localhost \
  --port 5140 \
  --rate 20 \
  --anomaly-rate 0.15

# What it does:
# - Generates 20 logs/second
# - 15% anomaly rate (attacks/suspicious activity)
# - Sends directly to Vector via TCP
```

### Mode 2: HTTP POST

```bash
# Send logs via HTTP API
python scripts/enhanced_log_generator.py \
  --mode http \
  --url http://localhost:8080/api/logs \
  --rate 10 \
  --duration 300

# What it does:
# - Generates 10 logs/second for 5 minutes
# - POSTs to Vector HTTP endpoint
# - Ideal for distributed log sources
```

### Mode 3: Batch File Generation

```bash
# Generate a batch file with 10,000 logs
python scripts/enhanced_log_generator.py \
  --action batch \
  --count 10000 \
  --output-file banking_logs_batch1.jsonl \
  --anomaly-rate 0.2

# What it does:
# - Creates JSONL file with 10,000 logs
# - 20% contain anomalies/attacks
# - File ready for upload or analysis
```

### Mode 4: Upload Existing File

```bash
# Upload pre-generated log file
python scripts/enhanced_log_generator.py \
  --mode upload \
  --input-file banking_logs_batch1.jsonl \
  --url http://localhost:8080/api/logs

# What it does:
# - Reads logs from file
# - Uploads in batches to Vector
# - Shows progress
```

### Mode 5: Stream from File

```bash
# Stream logs from file at controlled rate
python scripts/enhanced_log_generator.py \
  --action stream-file \
  --mode stream \
  --input-file banking_logs_batch1.jsonl \
  --rate 50 \
  --host localhost \
  --port 5140

# What it does:
# - Reads from file
# - Streams at 50 logs/sec
# - Simulates real-time traffic
```

---

## 🎯 Attack Scenario Simulation

### Brute Force Attack

```bash
# Simulate brute force password attack
python scripts/enhanced_log_generator.py \
  --action scenario \
  --scenario brute_force \
  --mode stream \
  --duration 120

# Generates:
# - Multiple failed login attempts (Event ID 4625)
# - From same malicious IP
# - Against admin accounts
# - Should trigger Wazuh alerts
```

### Data Exfiltration

```bash
# Simulate data exfiltration attempt
python scripts/enhanced_log_generator.py \
  --action scenario \
  --scenario data_exfiltration \
  --mode stream \
  --duration 180

# Generates:
# - Large database SELECT queries
# - Accessing sensitive tables
# - High row counts (10K-50K rows)
# - After-hours activity
# - Should trigger UEBA alerts
```

---

## 📋 Complete Command Reference

### Parameters

| Parameter | Options | Default | Description |
|-----------|---------|---------|-------------|
| `--mode` | stream, http, file, both, upload | stream | Ingestion mode |
| `--host` | hostname/IP | localhost | Vector host |
| `--port` | port number | 5140 | Vector TCP port |
| `--url` | URL | http://localhost:8080/api/logs | Vector HTTP endpoint |
| `--action` | generate, stream-file, scenario, batch | generate | Action to perform |
| `--scenario` | brute_force, data_exfiltration, normal | normal | Attack scenario |
| `--duration` | seconds | 60 | Duration for scenarios |
| `--rate` | logs/sec | 10 | Generation rate |
| `--count` | number | 1000 | Logs for batch generation |
| `--input-file` | filepath | - | Input file path |
| `--output-file` | filepath | auto-generated | Output file path |
| `--anomaly-rate` | 0.0-1.0 | 0.1 | Percentage of anomalies (10%) |

---

## 📊 Log Types Generated

The generator creates **8 types of banking logs**:

### 1. Core Banking Transactions
```json
{
  "source": "core_banking",
  "event_category": "banking_transaction",
  "transaction_type": "TRANSFER",
  "amount": 1234.56,
  "from_account": "ACC0001234567",
  "to_account": "ACC0009876543",
  "status": "SUCCESS"
}
```

### 2. Windows Security Events
```json
{
  "source": "windows_security",
  "event_id": 4625,
  "event_description": "Failed logon",
  "user_name": "admin001",
  "source_ip": "185.220.101.1",
  "failure_reason": "Bad password"
}
```

### 3. API Access Logs
```json
{
  "source": "api_gateway",
  "event_category": "api_access",
  "endpoint": "/api/v1/accounts/balance",
  "status_code": 200,
  "response_time_ms": 125.43
}
```

### 4. Database Audit Logs
```json
{
  "source": "database",
  "operation": "SELECT",
  "table": "customers",
  "rows_affected": 45000,
  "privileged_operation": true
}
```

### 5. Firewall Logs
```json
{
  "source": "firewall",
  "action": "DENY",
  "src_ip": "185.220.101.1",
  "dst_port": 3389,
  "threat_detected": true,
  "signature": "BRUTE_FORCE"
}
```

---

## 🔄 Complete Data Flow

```
┌─────────────────────────────────────────────────────────────┐
│  OPTION 1: Live Stream                                      │
│  Enhanced Generator → TCP:5140 → Vector → Wazuh/OpenSearch  │
└─────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────┐
│  OPTION 2: HTTP API                                         │
│  Enhanced Generator → HTTP:8080 → Vector → Wazuh/OpenSearch │
└─────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────┐
│  OPTION 3: File Upload                                      │
│  Generate Batch → JSONL File → Upload → Vector → Processing│
└─────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────┐
│  OPTION 4: File Stream                                      │
│  JSONL File → Stream at Rate → Vector → Processing          │
└─────────────────────────────────────────────────────────────┘
```

---

## 💡 Use Cases

### Testing & Development
```bash
# Generate test dataset
python scripts/enhanced_log_generator.py \
  --action batch \
  --count 50000 \
  --output-file test_dataset.jsonl \
  --anomaly-rate 0.25
```

### Load Testing
```bash
# High-volume stress test
python scripts/enhanced_log_generator.py \
  --mode stream \
  --rate 500 \
  --duration 600
```

### Forensic Analysis
```bash
# Generate historical logs with timestamps
python scripts/enhanced_log_generator.py \
  --action batch \
  --count 100000 \
  --output-file historical_logs.jsonl
```

### Training ML Models
```bash
# Generate balanced dataset for UEBA training
python scripts/enhanced_log_generator.py \
  --action batch \
  --count 100000 \
  --anomaly-rate 0.15 \
  --output-file ueba_training_data.jsonl
```

### Demo & Presentations
```bash
# Live demonstration with visible attacks
python scripts/enhanced_log_generator.py \
  --mode stream \
  --rate 5 \
  --anomaly-rate 0.4
```

---

## 🔧 Integration with Docker Compose

### Update docker-compose.yml

```yaml
services:
  log-generator:
    build:
      context: ./scripts
      dockerfile: Dockerfile.generator
    container_name: enhanced-log-generator
    networks:
      - zone1_production
      - log_transit
    environment:
      VECTOR_HOST: vector-ingest
      VECTOR_PORT: 5140
      VECTOR_HTTP: http://vector-ingest:8080/api/logs
      GENERATION_MODE: stream
      LOGS_PER_SECOND: 50
      ANOMALY_RATE: 0.15
    volumes:
      - ./data/generated-logs:/app/output
    command: >
      python enhanced_log_generator.py
      --mode stream
      --host vector-ingest
      --port 5140
      --rate 50
      --anomaly-rate 0.15
```

---

## 📈 Monitoring Generation

### Check Generation Stats
```bash
# View logs being generated
docker-compose logs -f log-generator

# Should show:
# Generated 100 logs...
# Generated 200 logs...
```

### Verify in Vector
```bash
# Check Vector is receiving logs
curl http://localhost:8686/metrics | grep logs_received
```

### View in OpenSearch
```bash
# Query OpenSearch for recent logs
curl -X GET "http://localhost:9200/banking-soc-logs-*/_search?size=10&sort=@timestamp:desc"
```

---

## 🎓 Examples

### Example 1: Development Testing
```bash
# Generate small test batch
python scripts/enhanced_log_generator.py \
  --action batch \
  --count 1000 \
  --output-file dev_test.jsonl

# Upload to pipeline
python scripts/enhanced_log_generator.py \
  --mode upload \
  --input-file dev_test.jsonl
```

### Example 2: Continuous Background Generation
```bash
# Run in background with tmux/screen
tmux new -s log-generator
python scripts/enhanced_log_generator.py \
  --mode stream \
  --rate 25 \
  --anomaly-rate 0.12
# Ctrl+B, D to detach
```

### Example 3: Multiple Generators (Distributed)
```bash
# Terminal 1: Normal traffic
python scripts/enhanced_log_generator.py \
  --mode stream --port 5140 --rate 30 --anomaly-rate 0.05

# Terminal 2: Attack simulation
python scripts/enhanced_log_generator.py \
  --action scenario --scenario brute_force --duration 300

# Terminal 3: File upload
python scripts/enhanced_log_generator.py \
  --mode upload --input-file historical.jsonl
```

---

## ⚡ Performance Tips

1. **For High Volume**: Use `--mode stream` (faster than HTTP)
2. **For Reliability**: Use `--mode file` then upload
3. **For Testing**: Use `--action batch` to generate reproducible datasets
4. **For Demos**: Use lower `--rate` (5-10) with high `--anomaly-rate` (0.3-0.5)

---

## 🔍 Troubleshooting

### Connection Refused
```bash
# Check Vector is running
docker-compose ps vector-ingest

# Check port is accessible
telnet localhost 5140
```

### Logs Not Appearing
```bash
# Check Vector pipeline
docker-compose logs vector-ingest | grep error

# Verify OpenSearch index
curl http://localhost:9200/_cat/indices | grep banking-soc
```

### Slow Performance
```bash
# Reduce generation rate
--rate 10

# Use file mode instead of stream
--mode file
```

---

## 📦 Dependencies

```bash
# Install required packages
pip install requests

# No other dependencies needed!
```

---

## 🎉 Summary

You now have **5 different ways** to ingest logs into the Banking SOC platform:

✅ **Live Stream** - Real-time TCP streaming
✅ **HTTP API** - RESTful POST requests
✅ **Batch Files** - Generate JSONL files
✅ **File Upload** - Upload existing logs
✅ **File Stream** - Replay files at controlled rate

**All modes support**:
- Configurable anomaly rates
- Attack scenario simulation
- Multiple log types (8 different sources)
- Realistic banking data
- Performance tuning

**Start generating logs now**:
```bash
python scripts/enhanced_log_generator.py --mode stream --rate 20
```
