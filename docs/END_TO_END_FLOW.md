# End-to-End Data Flow - Enterprise Banking SOC

## Overview
This document maps the complete data flow from log generation through all processing layers to automated response, including API endpoints, data structures, and integration points.

---

## 🔄 Complete Flow Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         ZONE 1: PRODUCTION SIMULATION                       │
│  ┌──────────────────────────────────────────────────────────────────────┐  │
│  │  Log Simulator (banking-log-simulator)                               │  │
│  │  • Script: enhanced_log_generator.py                                 │  │
│  │  • Generates 8 log types: Banking, API, DB, Windows, AD, FW, Cloud   │  │
│  │  • Rate: 50 events/second                                            │  │
│  │  • Protocol: TCP Socket → vector-ingest:5140                         │  │
│  └──────────────────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────────────┘
                                   ↓
┌─────────────────────────────────────────────────────────────────────────────┐
│                          LOG TRANSIT ZONE (DMZ)                             │
│  ┌──────────────────────────────────────────────────────────────────────┐  │
│  │  4.1 Vector ETL (vector-ingest)                                      │  │
│  │  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━  │  │
│  │  Config: /etc/vector/vector.toml                                     │  │
│  │                                                                       │  │
│  │  SOURCES (Listeners):                                                │  │
│  │    • TCP Socket: 0.0.0.0:5140 (core banking)                         │  │
│  │    • UDP Socket: 0.0.0.0:514 (syslog)                                │  │
│  │    • HTTP Server: 0.0.0.0:8080/api/logs                              │  │
│  │    • File: /var/log/banking/*.log                                    │  │
│  │    • Journald: Linux system logs                                     │  │
│  │    • Windows Event Log: Security, PowerShell                         │  │
│  │                                                                       │  │
│  │  TRANSFORMS (Processing Pipeline):                                   │  │
│  │    1. normalize_* → Parse and standardize each log type              │  │
│  │    2. aggregate_and_sign → Add universal SOC fields                  │  │
│  │       - event_fingerprint (SHA256)                                   │  │
│  │       - message_signature (HMAC)                                     │  │
│  │       - business_unit, compliance_frameworks                         │  │
│  │    3. deduplicate → 5-minute window deduplication                    │  │
│  │                                                                       │  │
│  │  SINKS (Outputs):                                                    │  │
│  │    ✓ to_wazuh → wazuh-manager:1514 (TCP, JSON)                       │  │
│  │    ✓ to_opensearch → opensearch:9200/banking-soc-logs-*             │  │
│  │    ✓ local_backup → /var/log/vector/banking-soc-backup-*.ndjson     │  │
│  │    ✓ metrics_export → :9598/metrics (Prometheus)                     │  │
│  └──────────────────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────────────┘
                     ↓                                    ↓
┌─────────────────────────────────────────────────────────────────────────────┐
│                          ZONE 2: SOC ANALYTICS                              │
│                                                                             │
│  ┌────────────────────────────────────────────────────────────────────┐    │
│  │  4.2 Wazuh SIEM Layer (wazuh-manager)                             │    │
│  │  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━  │    │
│  │  Port: 1514 (Agent/Vector ingestion), 55000 (API)                 │    │
│  │                                                                     │    │
│  │  DECODERS:                                                         │    │
│  │    • /var/ossec/etc/decoders/*.xml                                 │    │
│  │    • banking-soc-json decoder (custom)                             │    │
│  │                                                                     │    │
│  │  RULES:                                                            │    │
│  │    • /var/ossec/etc/rules/banking-rules.xml (100000-100099)        │    │
│  │    • /var/ossec/etc/rules/banking-correlation-rules.xml (100100+)  │    │
│  │    • MITRE ATT&CK tagging embedded                                 │    │
│  │                                                                     │    │
│  │  ALERT PROCESSING:                                                 │    │
│  │    1. Parse incoming JSON events                                   │    │
│  │    2. Apply 275+ detection rules                                   │    │
│  │    3. Severity assignment (0-15)                                   │    │
│  │    4. MITRE technique tagging                                      │    │
│  │    5. Initial incident object creation                             │    │
│  │                                                                     │    │
│  │  OUTPUT:                                                           │    │
│  │    → wazuh-alerts-* index in OpenSearch                            │    │
│  │    → Initial incident → banking-soc-incidents (status=new)         │    │
│  └────────────────────────────────────────────────────────────────────┘    │
│                                                                             │
│  ┌────────────────────────────────────────────────────────────────────┐    │
│  │  4.3 OpenSearch Storage Layer (opensearch)                        │    │
│  │  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━  │    │
│  │  Endpoint: http://opensearch:9200                                  │    │
│  │  Credentials: admin / Admin123!@#                                  │    │
│  │                                                                     │    │
│  │  INDICES:                                                          │    │
│  │    • banking-soc-logs-YYYY-MM-DD (raw events from Vector)          │    │
│  │    • wazuh-alerts-* (Wazuh detections)                             │    │
│  │    • banking-soc-incidents (new incidents from Wazuh)              │    │
│  │    • banking-soc-incidents-enriched (post-AI processing)           │    │
│  │    • banking-soc-playbooks (LLM-generated response plans)          │    │
│  │                                                                     │    │
│  │  INDEX TEMPLATES:                                                  │    │
│  │    → banking-index-templates.json                                  │    │
│  │    → Field mappings: 50+ normalized fields                         │    │
│  │    → ISM policies for hot/warm/cold tier management                │    │
│  └────────────────────────────────────────────────────────────────────┘    │
│                                    ↓                                        │
│  ┌────────────────────────────────────────────────────────────────────┐    │
│  │  4.4 AI Intelligence Layer (ai-intelligence-ueba)                 │    │
│  │  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━  │    │
│  │  API: http://localhost:8001                                        │    │
│  │  Service: ai-intelligence/src/main.py                              │    │
│  │                                                                     │    │
│  │  INITIALIZATION:                                                   │    │
│  │    1. Connect to OpenSearch (http://opensearch:9200)               │    │
│  │    2. Connect to Redis (redis:6379, db=1)                          │    │
│  │    3. Connect to Neo4j (bolt://neo4j:7687)                         │    │
│  │    4. Initialize ML models:                                        │    │
│  │       - Isolation Forest                                           │    │
│  │       - AutoEncoder Neural Network                                 │    │
│  │       - HBOS (Histogram-Based Outlier Score)                       │    │
│  │                                                                     │    │
│  │  PROCESSING LOOP (60s polling):                                    │    │
│  │    Query: banking-soc-incidents WHERE status=new                   │    │
│  │    For each incident:                                              │    │
│  │      1. Build user/entity behavioral baseline (30-day window)      │    │
│  │      2. Run anomaly detection (all 3 models)                       │    │
│  │      3. Calculate risk score (0-100)                               │    │
│  │      4. Compute confidence score (0.0-1.0)                         │    │
│  │      5. Reconstruct attack chain (Neo4j graph)                     │    │
│  │      6. Update incident status → enriching                         │    │
│  │                                                                     │    │
│  │  DATA STRUCTURES:                                                  │    │
│  │    • UserBaseline: login_times, geo_patterns, resource_access      │    │
│  │    • EntityBaseline: network_connections, process_behavior         │    │
│  │    • AnomalyScore: isolation_score, reconstruction_error, hbos     │    │
│  │    • RiskScore: weighted_sum(anomaly, severity, asset_criticality) │    │
│  │                                                                     │    │
│  │  OUTPUT:                                                           │    │
│  │    → Updated incident with risk_score, confidence, anomaly_flags   │    │
│  │    → Passes to Enrichment Layer                                    │    │
│  └────────────────────────────────────────────────────────────────────┘    │
│                                    ↓                                        │
│  ┌────────────────────────────────────────────────────────────────────┐    │
│  │  4.5 Intelligence Enrichment Layer (enrichment-llm)               │    │
│  │  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━  │    │
│  │  API: http://localhost:8002                                        │    │
│  │  Service: enrichment/src/main.py                                   │    │
│  │                                                                     │    │
│  │  INITIALIZATION:                                                   │    │
│  │    1. Connect to OpenSearch                                        │    │
│  │    2. Connect to Redis (caching)                                   │    │
│  │    3. Initialize threat intel feeds:                               │    │
│  │       - NVD CVE database (API key required)                        │    │
│  │       - CISA KEV list                                              │    │
│  │       - OpenCTI / MISP (if configured)                             │    │
│  │    4. Load asset criticality database (assets.json)                │    │
│  │    5. Initialize LLM backend (GPT-4o / Claude / LLaMA)             │    │
│  │                                                                     │    │
│  │  PROCESSING LOOP (30s polling):                                    │    │
│  │    Query: banking-soc-incidents WHERE status=enriching             │    │
│  │    For each incident:                                              │    │
│  │                                                                     │    │
│  │      A. INTELLIGENCE ENRICHMENT:                                   │    │
│  │         • CVE Matching:                                            │    │
│  │           - Extract software versions from affected assets         │    │
│  │           - Query NVD API for matching CVEs                        │    │
│  │           - Add CVSS scores, exploit availability                  │    │
│  │         • CISA KEV Check:                                          │    │
│  │           - Cross-reference CVEs against Known Exploited list      │    │
│  │         • Threat Intel IOC Matching:                               │    │
│  │           - Check IPs, domains, hashes, URLs                       │    │
│  │           - Tag with threat actor associations                     │    │
│  │         • Asset Criticality:                                       │    │
│  │           - Lookup asset tier (1-10 scale)                         │    │
│  │           - Business impact: payment rails, customer-facing, etc.  │    │
│  │         • MITRE ATT&CK Full Context:                               │    │
│  │           - Tactic, technique, sub-technique mapping               │    │
│  │           - Known threat group associations                        │    │
│  │                                                                     │    │
│  │      B. LLM PLAYBOOK GENERATION (5 specialized prompts):           │    │
│  │         1. incident_analysis.txt                                   │    │
│  │            → Threat classification, attack chain, impact           │    │
│  │         2. playbook_generation.txt                                 │    │
│  │            → 4-phase response plan (Contain, Investigate, etc.)    │    │
│  │         3. executive_summary.txt                                   │    │
│  │            → Business-focused summary (500 words max)              │    │
│  │         4. technical_details.txt                                   │    │
│  │            → Timeline, IOCs, forensic artifacts                    │    │
│  │         5. soar_actions.txt                                        │    │
│  │            → Structured JSON action specifications                 │    │
│  │                                                                     │    │
│  │  OUTPUT:                                                           │    │
│  │    → banking-soc-incidents-enriched                                │    │
│  │    → banking-soc-playbooks (status=pending_approval)               │    │
│  └────────────────────────────────────────────────────────────────────┘    │
│                                    ↓                                        │
│  ┌────────────────────────────────────────────────────────────────────┐    │
│  │  4.7 SOAR Automation Layer (soar-automation)                      │    │
│  │  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━  │    │
│  │  API: http://localhost:8003                                        │    │
│  │  Service: soar-automation/src/main.py                              │    │
│  │  Database: PostgreSQL (soar_db)                                    │    │
│  │                                                                     │    │
│  │  PROCESSING LOOP (60s polling):                                    │    │
│  │    Query: banking-soc-playbooks WHERE status=approved              │    │
│  │    For each playbook:                                              │    │
│  │                                                                     │    │
│  │      SEVERITY-BASED AUTOMATION:                                    │    │
│  │        LOW (1-3):     Manual review required, no auto-execute      │    │
│  │        MEDIUM (4-6):  Execute with pre-approval workflow           │    │
│  │        HIGH (7-9):    Auto-execute, notify post-action             │    │
│  │        CRITICAL (10+): Auto-execute + crisis team alert            │    │
│  │                                                                     │    │
│  │      ACTION TYPES:                                                 │    │
│  │        • disable_account → AD/IAM API                              │    │
│  │        • isolate_host → EDR/Network API                            │    │
│  │        • block_ip → Firewall API                                   │    │
│  │        • reset_password → IAM API                                  │    │
│  │        • revoke_token → OAuth2 API                                 │    │
│  │        • network_segment_isolation → SDN Controller                │    │
│  │                                                                     │    │
│  │      EXECUTION FLOW:                                               │    │
│  │        1. Parse SOAR action JSON                                   │    │
│  │        2. Validate action against policy                           │    │
│  │        3. Execute via integration adapter                          │    │
│  │        4. Log action to PostgreSQL (audit trail)                   │    │
│  │        5. Update playbook status → executed                        │    │
│  │        6. Generate rollback plan (if applicable)                   │    │
│  │                                                                     │    │
│  │  ROLLBACK SUPPORT:                                                 │    │
│  │    • Stores pre-action state in PostgreSQL                         │    │
│  │    • Automated recovery on failure                                 │    │
│  │    • Manual rollback via API endpoint                              │    │
│  │                                                                     │    │
│  │  FEEDBACK LOOP:                                                    │    │
│  │    • Collect execution metrics (success rate, MTTR)                │    │
│  │    • Feed back to AI Intelligence for model retraining             │    │
│  │    • Update Wazuh rules for false positive suppression             │    │
│  └────────────────────────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────────────────────────┘
                                    ↓
┌─────────────────────────────────────────────────────────────────────────────┐
│                         FRONTEND DASHBOARD                                  │
│  ┌──────────────────────────────────────────────────────────────────────┐  │
│  │  Next.js Dashboard (http://localhost:3000)                           │  │
│  │  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━  │  │
│  │                                                                       │  │
│  │  API INTEGRATIONS:                                                   │  │
│  │    • AI Intelligence: http://localhost:8001/api/v1                   │  │
│  │      - GET /incidents (real-time incident feed)                      │  │
│  │      - GET /metrics (UEBA model performance)                         │  │
│  │    • Enrichment: http://localhost:8002/api/v1                        │  │
│  │      - GET /playbooks                                                │  │
│  │      - POST /enrich (manual enrichment trigger)                      │  │
│  │    • SOAR: http://localhost:8003/api/v1                              │  │
│  │      - GET /actions (execution status)                               │  │
│  │      - POST /approve (playbook approval)                             │  │
│  │      - POST /rollback (manual rollback)                              │  │
│  │    • OpenSearch: http://localhost:9200                               │  │
│  │      - Query logs, alerts, incidents                                 │  │
│  │    • Wazuh API: https://localhost:55000                              │  │
│  │      - GET /security/users/authenticate                              │  │
│  │      - GET /alerts (raw alerts)                                      │  │
│  │                                                                       │  │
│  │  COMPONENTS:                                                         │  │
│  │    • lib/api-client.ts → Axios wrapper with SOC service endpoints    │  │
│  │    • hooks/usePipeline.ts → Real-time pipeline status                │  │
│  │    • hooks/useServiceHealth.ts → Service health monitoring           │  │
│  └──────────────────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 📊 Data Structure Evolution

### 1. Raw Log Event (Vector Input)
```json
{
  "timestamp": "2026-02-18T10:30:45Z",
  "message": "Login attempt from user:john.smith account:CHK0012345 amount:50000.00",
  "host": "banking-api-01",
  "source_ip": "192.168.1.100"
}
```

### 2. Normalized Event (Vector Output → Wazuh/OpenSearch)
```json
{
  "@timestamp": "2026-02-18T10:30:45Z",
  "event_category": "banking_transaction",
  "zone": "zone1_production",
  "log_source": "core_banking_apps",
  "user_id": "john.smith",
  "account_id": "CHK0012345",
  "transaction_amount": 50000.00,
  "source_ip": "192.168.1.100",
  "source_country": "US",
  "risk_flags": ["large_transfer"],
  "event_fingerprint": "a8b2c3d4...",
  "business_unit": "enterprise_banking",
  "compliance_frameworks": ["PCI_DSS", "SOX", "BASEL_III"]
}
```

### 3. Wazuh Alert (Wazuh Output)
```json
{
  "rule": {
    "id": "100020",
    "level": 10,
    "description": "Banking SOC: Large wire transfer above threshold",
    "mitre": {"id": "T1537"}
  },
  "agent": {"name": "banking-api-01"},
  "data": { /* normalized event */ },
  "timestamp": "2026-02-18T10:30:46Z",
  "severity": "high"
}
```

### 4. Initial Incident (AI Intelligence Input)
```json
{
  "incident_id": "INC-2026-02-18-001",
  "status": "new",
  "wazuh_alert_id": "1708254646.123456",
  "rule_id": "100020",
  "severity": 10,
  "user_id": "john.smith",
  "source_ip": "192.168.1.100",
  "mitre_technique": "T1537",
  "timestamp": "2026-02-18T10:30:46Z"
}
```

### 5. Enriched Incident (Enrichment Output)
```json
{
  "incident_id": "INC-2026-02-18-001",
  "status": "enriched",
  "risk_score": 85.3,
  "confidence": 0.92,
  "anomaly_flags": ["unusual_transaction_amount", "off_hours_activity"],
  "cve_matches": [],
  "threat_intel": {
    "ip_reputation": "clean",
    "known_threats": []
  },
  "asset_criticality": 9,
  "business_impact": "payment_processing_system",
  "mitre_full_context": {
    "tactic": "Impact",
    "technique": "T1537",
    "sub_technique": "Transfer Data to Cloud Account"
  }
}
```

### 6. LLM-Generated Playbook (Enrichment → SOAR)
```json
{
  "playbook_id": "PB-2026-02-18-001",
  "incident_id": "INC-2026-02-18-001",
  "status": "pending_approval",
  "priority": "HIGH",
  "response_plan": {
    "phase_1_contain": "Freeze account CHK0012345, revoke active sessions",
    "phase_2_investigate": "Query transaction history, IP geolocation analysis",
    "phase_3_remediate": "Contact user, verify legitimacy, enable MFA",
    "phase_4_recover": "Unfreeze account if verified, monitor for 48h"
  },
  "soar_actions": [
    {
      "action_type": "disable_account",
      "target": "john.smith",
      "reason": "Suspicious large transfer",
      "severity": "HIGH",
      "auto_execute": true
    },
    {
      "action_type": "revoke_token",
      "target": "session_id_12345",
      "severity": "HIGH",
      "auto_execute": true
    }
  ],
  "executive_summary": "Suspicious $50,000 wire transfer from john.smith...",
  "llm_confidence": 0.95
}
```

---

## 🔧 Key Integration Points

### Vector → Wazuh Connection
- **Protocol**: TCP Socket
- **Endpoint**: `wazuh-manager:1514`
- **Format**: JSON (one event per line)
- **Fix Applied**: Changed `wazuh.manager` to `wazuh-manager` (docker service name)

### Vector → OpenSearch Connection
- **Protocol**: HTTP/Elasticsearch API
- **Endpoint**: `http://opensearch:9200`
- **Index**: `banking-soc-logs-YYYY-MM-DD`
- **Auth**: Basic (admin / Admin123!@#)
- **Fix Applied**: Changed HTTPS to HTTP (no TLS in internal docker network)

### Wazuh → OpenSearch Connection
- **Integration**: Filebeat (built into Wazuh container)
- **Index**: `wazuh-alerts-*`
- **Config**: Wazuh manager env vars (`INDEXER_URL`, `INDEXER_USERNAME`, `INDEXER_PASSWORD`)

### AI Intelligence ↔ OpenSearch
- **Client**: opensearchpy AsyncOpenSearch
- **Queries**: 
  - Poll `banking-soc-incidents` WHERE `status=new` every 60s
  - Write to `banking-soc-incidents-enriched`
- **Fix Applied**: Changed connection to HTTP, disabled SSL

### Enrichment ↔ OpenSearch
- **Client**: opensearchpy AsyncOpenSearch
- **Queries**:
  - Poll `banking-soc-incidents` WHERE `status=enriching` every 30s
  - Write to `banking-soc-playbooks`
- **Fix Applied**: Changed connection to HTTP, corrected index_document signature

### SOAR ↔ OpenSearch
- **Queries**:
  - Poll `banking-soc-playbooks` WHERE `status=approved` every 60s
  - Update execution status
- **Database**: PostgreSQL for action state persistence

### Frontend ↔ Backend Services
- **API Gateway**: Next.js API routes or direct service calls
- **Endpoints**:
  - `http://localhost:8001` (AI Intelligence)
  - `http://localhost:8002` (Enrichment/LLM)
  - `http://localhost:8003` (SOAR)
- **Fix Applied**: Added SOC_SERVICES configuration object

---

## 🚀 Deployment & Validation

### 1. Start All Services
```bash
cd "/home/vivek/Desktop/Enterprise Banking Autonomus SOC"
docker-compose up -d
```

### 2. Verify Vector Ingestion
```bash
# Check Vector is receiving logs
curl http://localhost:8686/metrics | grep component_received_events_total

# Expected output: counter incrementing
```

### 3. Verify Wazuh Alert Generation
```bash
# Check Wazuh alerts in OpenSearch
curl -u admin:Admin123!@# http://localhost:9200/wazuh-alerts-*/_count

# Expected: {"count": N}
```

### 4. Verify AI Intelligence Processing
```bash
# Check incidents index
curl -u admin:Admin123!@# http://localhost:9200/banking-soc-incidents/_count

# Check service health
curl http://localhost:8001/health
```

### 5. Verify Enrichment Processing
```bash
# Check enriched incidents
curl -u admin:Admin123!@# http://localhost:9200/banking-soc-incidents-enriched/_count

# Check playbooks
curl -u admin:Admin123!@# http://localhost:9200/banking-soc-playbooks/_count
```

### 6. Verify SOAR Execution
```bash
# Check SOAR action logs in PostgreSQL
docker exec postgres-db psql -U soar_user -d soar_db \
  -c "SELECT COUNT(*) FROM soar_actions;"
```

### 7. Access Frontend
```bash
# Open browser
open http://localhost:3000/dashboard
```

---

## 🐛 Common Issues & Fixes

### Issue 1: Vector can't connect to Wazuh
**Symptom**: Vector logs show "connection refused" to wazuh.manager:1514
**Fix**: Changed hostname from `wazuh.manager` to `wazuh-manager` in vector.toml ✅

### Issue 2: OpenSearch SSL verification failures
**Symptom**: Python services fail with SSL certificate errors
**Fix**: Changed all OpenSearch clients from `https://` to `http://` for internal docker network ✅

### Issue 3: Enrichment service can't index documents
**Symptom**: TypeError on opensearch.index_document()
**Fix**: Corrected method signature to `index_document(index, doc_id, document)` ✅

### Issue 4: Log simulator not starting
**Symptom**: docker-compose can't find Dockerfile.simulator
**Fix**: Changed dockerfile reference from `Dockerfile.simulator` to `Dockerfile.generator` ✅

### Issue 5: Frontend can't reach backend services
**Symptom**: API calls timeout or return connection errors
**Fix**: Added SOC_SERVICES endpoint configuration to api-client.ts ✅

---

## 📈 Performance Metrics

| Stage | Expected Throughput | Latency (p95) |
|-------|---------------------|---------------|
| Vector Ingestion | 1000+ eps | < 50ms |
| Wazuh Detection | 500+ eps | < 100ms |
| OpenSearch Indexing | 2000+ eps | < 200ms |
| AI Intelligence | 10-20 incidents/min | 3-5s |
| Enrichment + LLM | 5-10 playbooks/min | 10-15s |
| SOAR Execution | 20-30 actions/min | 2-5s |

---

## 🔐 Security Considerations

1. **TLS in Production**: Enable TLS for all inter-service communication
2. **Credential Rotation**: Implement secret rotation for all service accounts
3. **Network Segmentation**: Use docker network policies to restrict access
4. **Audit Logging**: All SOAR actions logged to immutable PostgreSQL with signatures
5. **Approval Workflows**: High-severity actions require human approval

---

## 📚 Related Documentation

- [FLOW_VALIDATION.md](../FLOW_VALIDATION.md) - Detailed validation procedures
- [INTEGRATION_VALIDATION.md](../INTEGRATION_VALIDATION.md) - Integration test cases
- [README.md](../README.md) - Main project documentation
- [DEPLOYMENT_SUMMARY.md](../DEPLOYMENT_SUMMARY.md) - Deployment checklist
