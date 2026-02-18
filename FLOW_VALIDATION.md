# Complete Data Flow Validation

## End-to-End Pipeline Overview

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                          ZONE 1: PRODUCTION SIMULATION                      │
│  ┌──────────────────────────────────────────────────────────────────────┐  │
│  │  Log Generators (8 Types)                                            │  │
│  │  • Core Banking Transactions                                         │  │
│  │  • Windows Security Events (4624/4625/4672)                          │  │
│  │  • Active Directory (4768-4771)                                      │  │
│  │  • API Access Logs (REST endpoints)                                  │  │
│  │  • Database Audit (SQL operations)                                   │  │
│  │  • Firewall/IDS (allow/deny, threats)                                │  │
│  │  • Cloud Audit (CloudTrail-style)                                    │  │
│  │  • Mainframe (SMF/RACF)                                              │  │
│  └──────────────────────────────────────────────────────────────────────┘  │
│                                   ▼                                          │
│                        TCP:5140 / UDP:514 / HTTP:8080                       │
└─────────────────────────────────────────────────────────────────────────────┘
                                   ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                         LOG TRANSIT ZONE (DMZ)                              │
│  ┌──────────────────────────────────────────────────────────────────────┐  │
│  │  Vector ETL Pipeline                                                 │  │
│  │  • Ingest: TCP/UDP/HTTP/File                                         │  │
│  │  • Transform: Parse JSON, normalize, GeoIP, asset tagging            │  │
│  │  • Deduplicate (5-minute window)                                     │  │
│  │  • Output to multiple sinks:                                         │  │
│  │    - OpenSearch (banking-soc-logs-*)                                 │  │
│  │    - Wazuh Manager (SIEM)                                            │  │
│  │    - Local Backup (compliance)                                       │  │
│  │    - Prometheus Metrics (:9598)                                      │  │
│  └──────────────────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────────────┘
                                   ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                          ZONE 2: SOC ANALYTICAL                             │
│                                                                             │
│  ┌────────────────────┐         ┌────────────────────┐                     │
│  │  Wazuh Manager     │         │  OpenSearch        │                     │
│  │  • Rule Engine     │────────▶│  • banking-soc-    │                     │
│  │  • Alert Triage    │         │    logs-*          │                     │
│  │  • MITRE Mapping   │         │  • Alert indexing  │                     │
│  └────────────────────┘         └────────────────────┘                     │
│                                           ▼                                 │
│  ┌─────────────────────────────────────────────────────────────────────┐  │
│  │  AI Intelligence Layer (UEBA)                                       │  │
│  │  • User Baseline Modeling (30-day)                                  │  │
│  │  • Isolation Forest (Anomaly Detection)                             │  │
│  │  • AutoEncoder (Deep Learning)                                      │  │
│  │  • HBOS (Histogram-based)                                           │  │
│  │  • Neo4j Graph Analytics (Attack Chains)                            │  │
│  │                                                                      │  │
│  │  Polls: banking-soc-logs-* every 60s                                │  │
│  │  Creates: Incidents → banking-soc-incidents (status=new)            │  │
│  └─────────────────────────────────────────────────────────────────────┘  │
│                                           ▼                                 │
│  ┌─────────────────────────────────────────────────────────────────────┐  │
│  │  Enrichment Service                                                 │  │
│  │  ┌───────────────────────────────────────────────────────────────┐  │  │
│  │  │  Intelligence Enrichment                                      │  │  │
│  │  │  • CVE/NVD Lookup (CVSS, exploit availability)                │  │  │
│  │  │  • CISA KEV List (Known Exploited Vulnerabilities)            │  │  │
│  │  │  • Threat Intel IOC Matching (IP/domain/hash/URL)             │  │  │
│  │  │  • Asset Criticality Scoring (1-10 scale)                     │  │  │
│  │  │  • MITRE ATT&CK Context                                       │  │  │
│  │  │  • Risk Score Calculation (multi-factor)                      │  │  │
│  │  └───────────────────────────────────────────────────────────────┘  │  │
│  │                               ▼                                      │  │
│  │  ┌───────────────────────────────────────────────────────────────┐  │  │
│  │  │  LLM Playbook Generation                                      │  │  │
│  │  │  • Backends: GPT-4o / Claude / LLaMA 3 / Mistral             │  │  │
│  │  │  • 5 Specialized Prompts:                                     │  │  │
│  │  │    1. Incident Analysis (threat, attack chain, impact)        │  │  │
│  │  │    2. Playbook Generation (4-phase response)                  │  │  │
│  │  │    3. Executive Summary (board-level, 500w max)               │  │  │
│  │  │    4. Technical Details (timeline, IOCs, forensics)           │  │  │
│  │  │    5. SOAR Actions (JSON action specification)                │  │  │
│  │  │  • Confidence Scoring (0.0-1.0)                               │  │  │
│  │  │  • Priority Calculation (CRITICAL/HIGH/MEDIUM/LOW)            │  │  │
│  │  └───────────────────────────────────────────────────────────────┘  │  │
│  │                                                                      │  │
│  │  Polls: banking-soc-incidents (status=new) every 30s                │  │
│  │  Updates: status → ENRICHING → ENRICHED → ANALYZING                 │  │
│  │  Indexes:                                                            │  │
│  │    - banking-soc-incidents-enriched (enrichment data)               │  │
│  │    - banking-soc-playbooks (LLM-generated response plans)           │  │
│  └─────────────────────────────────────────────────────────────────────┘  │
│                                           ▼                                 │
│  ┌─────────────────────────────────────────────────────────────────────┐  │
│  │  SOAR Automation Engine                                             │  │
│  │  • Severity-Based Automation Policies:                              │  │
│  │    - LOW: Manual review required                                    │  │
│  │    - MEDIUM: Execute with pre-approval                              │  │
│  │    - HIGH: Auto-execute, notify post-action                         │  │
│  │    - CRITICAL: Auto-execute + crisis team alert                     │  │
│  │  • Action Types:                                                    │  │
│  │    - disable_account, isolate_host, block_ip                        │  │
│  │    - reset_password, revoke_token                                   │  │
│  │    - network_segment_isolation                                      │  │
│  │  • Rollback Support (automated recovery)                            │  │
│  │  • PostgreSQL State Persistence                                     │  │
│  │                                                                      │  │
│  │  Polls: banking-soc-playbooks (status=approved) every 60s           │  │
│  │  Executes: SOAR actions → Updates execution status                  │  │
│  └─────────────────────────────────────────────────────────────────────┘  │
│                                           ▼                                 │
│  ┌─────────────────────────────────────────────────────────────────────┐  │
│  │  Feedback Loop Service                                              │  │
│  │  • Model Retraining (UEBA baselines)                                │  │
│  │  • False Positive Suppression                                       │  │
│  │  • Rule Optimization (Wazuh custom rules)                           │  │
│  │  • Performance Metrics Collection:                                  │  │
│  │    - Mean Time to Detect (MTTD)                                     │  │
│  │    - Mean Time to Respond (MTTR)                                    │  │
│  │    - False Positive Rate                                            │  │
│  │    - Action Success Rate                                            │  │
│  │  • Redis Caching for Quick Lookups                                  │  │
│  └─────────────────────────────────────────────────────────────────────┘  │
│                                                                             │
│  ┌────────────────────┐         ┌────────────────────┐                     │
│  │  Prometheus        │────────▶│  Grafana           │                     │
│  │  • Metrics Storage │         │  • Dashboards      │                     │
│  │  • Time Series DB  │         │  • Visualization   │                     │
│  └────────────────────┘         └────────────────────┘                     │
└─────────────────────────────────────────────────────────────────────────────┘
```

## Data Flow Validation Checklist

### 1. Log Ingestion (Zone 1 → Transit)

**Vector Input Sources:**
- ✅ TCP Socket: `0.0.0.0:5140` (Syslog)
- ✅ UDP Socket: `0.0.0.0:514` (Syslog)
- ✅ HTTP Server: `0.0.0.0:8080/api/logs` (JSON)
- ✅ File Source: `/var/log/banking/*.log`
- ✅ Journald: System logs

**Expected Behavior:**
```bash
# Test TCP ingestion
echo '{"timestamp":"2024-01-01T00:00:00Z","message":"test"}' | nc localhost 5140

# Test HTTP ingestion
curl -X POST http://localhost:8080/api/logs \
  -H "Content-Type: application/json" \
  -d '{"timestamp":"2024-01-01T00:00:00Z","message":"test"}'

# Check Vector metrics
curl http://localhost:8686/metrics | grep component_received_events_total
```

**Validation Points:**
- [ ] Logs arrive at Vector (check metrics on `:8686/metrics`)
- [ ] JSON parsing successful (no parse errors)
- [ ] All 8 log types recognized
- [ ] Anomaly flags preserved

### 2. Vector Processing (Transit Zone)

**Transforms Applied:**
1. **parse_json**: Extracts structured fields
2. **normalize_banking_logs**: Standardizes field names
3. **geoip_enrichment**: Adds location data for IPs
4. **asset_tagging**: Matches to asset inventory
5. **deduplication**: 5-minute window, fingerprint-based
6. **health_metrics**: Calculates pipeline latency

**Expected Behavior:**
```bash
# Check transform metrics
curl http://localhost:8686/metrics | grep component_errors_total

# Verify processed events
curl http://localhost:8686/metrics | grep vector_processed_events_total
```

**Validation Points:**
- [ ] No parse errors (`component_errors_total` = 0)
- [ ] Deduplication working (compare in vs out events)
- [ ] GeoIP enrichment adding `geoip.country_code`
- [ ] Asset tags matching from `assets.json`

### 3. Vector Output Sinks (Transit → Zone 2)

**Configured Sinks:**

**a) to_opensearch**
```toml
endpoint = "https://opensearch:9200"
index = "banking-soc-logs-%Y.%m.%d"
auth.strategy = "basic"
auth.user = "admin"
auth.password = "${OPENSEARCH_PASSWORD}"
```
**Validation:**
```bash
curl -k -u admin:Admin123\!@# \
  https://localhost:9200/banking-soc-logs-*/_count

# Should show increasing doc count
```

**b) to_wazuh**
```toml
endpoint = "wazuh-manager:1514"
mode = "tcp"
encoding.codec = "json"
```
**Validation:**
```bash
# Check Wazuh logs
docker exec wazuh-manager tail -f /var/ossec/logs/archives/archives.json
```

**c) local_backup**
```toml
path = "/var/log/vector/backup-%Y-%m-%d.log"
encoding.codec = "ndjson"
```
**Validation:**
```bash
# Check backup files exist
docker exec vector-ingest ls -lh /var/log/vector/
```

**d) security_alerts** (High-risk events)
```toml
endpoint = "http://enrichment:8002/api/alerts"
method = "post"
encoding.codec = "json"
```

**e) metrics_export**
```toml
type = "prometheus_exporter"
address = "0.0.0.0:9598"
```
**Validation:**
```bash
curl http://localhost:9598/metrics
```

### 4. Wazuh Processing (Zone 2)

**Alert Generation:**
- Rules: `/var/ossec/ruleset/rules/*.xml`
- Custom Rules: `/var/ossec/etc/rules/local_rules.xml`
- Alert Index: `wazuh-alerts-*`

**Expected Behavior:**
```bash
# Check Wazuh API
curl -k -u wazuh:wazuh https://localhost:55000/security/user/authenticate

# Check alerts
curl -k -u admin:Admin123\!@# \
  https://localhost:9200/wazuh-alerts-*/_count
```

**Validation Points:**
- [ ] Wazuh receiving logs from Vector
- [ ] Rules triggering alerts
- [ ] MITRE ATT&CK techniques mapped
- [ ] Alerts indexed to OpenSearch

### 5. OpenSearch Indexing

**Indices Created:**
```
banking-soc-logs-YYYY.MM.DD       # Raw logs
banking-soc-incidents             # Detected incidents
banking-soc-incidents-enriched    # CVE/threat intel enriched
banking-soc-playbooks             # LLM-generated playbooks
banking-soc-actions               # SOAR execution history
wazuh-alerts-*                    # Wazuh alerts
```

**Index Templates:**
```bash
# Check index templates
curl -k -u admin:Admin123\!@# \
  https://localhost:9200/_index_template/banking-soc-*

# Check index stats
curl -k -u admin:Admin123\!@# \
  https://localhost:9200/_cat/indices/banking-soc-*?v
```

**Validation Points:**
- [ ] Indices auto-created with correct mappings
- [ ] ILM policies applied (hot → warm → cold)
- [ ] Doc count increasing for logs
- [ ] Incident index receiving from AI Intelligence

### 6. AI Intelligence (UEBA)

**Service:** `ai-intelligence:8001`

**Processing Flow:**
1. Poll OpenSearch `banking-soc-logs-*` every 60s
2. Build user baselines (30-day window)
3. Run ML models:
   - Isolation Forest (anomaly detection)
   - AutoEncoder (deep learning)
   - HBOS (histogram-based)
4. Query Neo4j for attack chain patterns
5. Create incidents with confidence scores
6. Index to `banking-soc-incidents` with `status=new`

**Expected Behavior:**
```bash
# Check service health
curl http://localhost:8001/health

# Check incident creation
curl -k -u admin:Admin123\!@# \
  https://localhost:9200/banking-soc-incidents/_search?size=10

# Check Neo4j connections
docker exec neo4j cypher-shell -u neo4j -p neo4j123 \
  "MATCH (n) RETURN count(n);"
```

**Validation Points:**
- [ ] Service polling OpenSearch successfully
- [ ] Baselines built for users/entities
- [ ] ML models trained (Isolation Forest fitted)
- [ ] Incidents created with confidence > 0.7
- [ ] Neo4j graph populated with attack paths
- [ ] Redis caching model state

### 7. Enrichment Service

**Service:** `enrichment:8002`

**Intelligence Enrichment:**
1. Poll `banking-soc-incidents` where `status=new` every 30s
2. Update status → `ENRICHING`
3. For each incident:
   - CVE/NVD lookup for vulnerabilities
   - CISA KEV check for exploited CVEs
   - Threat intel IOC matching (feeds: abuse.ch, OTX, etc.)
   - Asset criticality from `assets.json`
   - MITRE ATT&CK context expansion
   - Risk score calculation (0-100)
4. Update status → `ENRICHED`
5. Index to `banking-soc-incidents-enriched`

**LLM Playbook Generation:**
1. Take enriched incident
2. Select LLM backend (GPT-4o/Claude/LLaMA)
3. Generate 5 responses using specialized prompts:
   - Incident Analysis
   - Playbook (4-phase: immediate/investigate/remediate/recover)
   - Executive Summary
   - Technical Details
   - SOAR Actions (JSON)
4. Calculate confidence score
5. Determine priority (CRITICAL/HIGH/MEDIUM/LOW)
6. Index to `banking-soc-playbooks` with `status=pending_approval`

**Expected Behavior:**
```bash
# Check service health
curl http://localhost:8002/health

# Check enrichment stats
curl http://localhost:8002/api/stats

# Verify CVE enrichment
curl -k -u admin:Admin123\!@# \
  https://localhost:9200/banking-soc-incidents-enriched/_search \
  -d '{"query":{"exists":{"field":"cve_matches"}}}'

# Verify playbook generation
curl -k -u admin:Admin123\!@# \
  https://localhost:9200/banking-soc-playbooks/_count
```

**Validation Points:**
- [ ] Service polling incidents successfully
- [ ] CVE API returning matches (nvd.nist.gov)
- [ ] CISA KEV list loaded (JSON feed)
- [ ] Threat intel IOC regex extracting IPs/domains/hashes
- [ ] Asset criticality scores applied
- [ ] Risk scores calculated (considering CVE CVSS, IOC confidence, asset criticality)
- [ ] LLM API calls succeeding (check API key env vars)
- [ ] Playbooks generated with valid JSON actions
- [ ] Enriched incidents indexed correctly

### 8. SOAR Automation

**Service:** `soar-automation:8003`

**Orchestration Flow:**
1. Poll `banking-soc-playbooks` where `status=approved` every 60s
2. Parse SOAR actions from playbook
3. Apply automation policy based on severity:
   - **LOW**: Manual only (notify ops team)
   - **MEDIUM**: Execute with pre-approval workflow
   - **HIGH**: Auto-execute, notify post-action
   - **CRITICAL**: Auto-execute + escalate to crisis team
4. Execute actions:
   - `disable_account`: AD user disable via LDAP
   - `isolate_host`: Network ACL via firewall API
   - `block_ip`: Add to deny list
   - `reset_password`: Force password change
   - `revoke_token`: Invalidate session tokens
5. Record execution to PostgreSQL
6. Update playbook status → `executed`
7. Index execution history to `banking-soc-actions`

**Expected Behavior:**
```bash
# Check service health
curl http://localhost:8003/health

# Check automation policies
curl http://localhost:8003/api/policies

# Check execution history
curl -k -u admin:Admin123\!@# \
  https://localhost:9200/banking-soc-actions/_search?size=10

# Check PostgreSQL state
docker exec -it postgres psql -U soar -d soar_db -c \
  "SELECT action_id, status, executed_at FROM action_executions ORDER BY executed_at DESC LIMIT 10;"
```

**Validation Points:**
- [ ] Service polling playbooks successfully
- [ ] Automation policies enforced by severity
- [ ] Actions executed (check target systems)
- [ ] Rollback available for critical actions
- [ ] Execution state persisted to PostgreSQL
- [ ] Action history indexed to OpenSearch

### 9. Feedback Loop

**Service:** `soar-automation` (integrated module)

**Continuous Improvement:**
1. Collect performance metrics:
   - Mean Time to Detect (MTTD)
   - Mean Time to Respond (MTTR)
   - False Positive Rate
   - Action Success Rate
2. Identify false positives from analyst feedback
3. Update UEBA baselines with new patterns
4. Optimize Wazuh rules
5. Retrain ML models with new data
6. Cache optimizations in Redis

**Expected Behavior:**
```bash
# Check metrics
curl http://localhost:8003/api/metrics

# Check false positive suppressions
docker exec redis redis-cli GET "fp_suppressions"

# Check model retraining schedule
curl http://localhost:8001/api/model_status
```

**Validation Points:**
- [ ] Metrics collected and tracked
- [ ] False positives identified and suppressed
- [ ] UEBA baselines updating (30-day rolling window)
- [ ] Models retrained on schedule (weekly)

### 10. Monitoring & Visualization

**Prometheus:** `http://localhost:9090`
- Metrics from all services
- Vector pipeline stats
- OpenSearch cluster health
- Service availability

**Grafana:** `http://localhost:3000`
- Pre-built dashboards:
  - SOC Overview
  - Incident Timeline
  - UEBA Anomalies
  - Threat Intelligence
  - SOAR Execution

**Expected Behavior:**
```bash
# Check Prometheus targets
curl http://localhost:9090/api/v1/targets

# Check Grafana health
curl http://localhost:3000/api/health
```

**Validation Points:**
- [ ] All Prometheus targets UP
- [ ] Grafana dashboards loading
- [ ] Metrics flowing from all services
- [ ] Alerts configured in Grafana

## Quick Validation Commands

### Run Complete Validation Suite

```bash
# Install dependencies
pip3 install requests urllib3

# Run validation script
python3 scripts/validate_flow.py
```

### Manual Flow Testing

```bash
# 1. Generate test logs
python3 scripts/enhanced_generator.py stream --duration 60 --rate 10

# 2. Check Vector ingestion
curl http://localhost:8686/metrics | grep component_received_events_total

# 3. Verify OpenSearch indexing
curl -k -u admin:Admin123\!@# https://localhost:9200/banking-soc-logs-*/_count

# 4. Check Wazuh alerts
curl -k -u admin:Admin123\!@# https://localhost:9200/wazuh-alerts-*/_count

# 5. Verify incident detection
curl -k -u admin:Admin123\!@# https://localhost:9200/banking-soc-incidents/_count

# 6. Check enrichment
curl -k -u admin:Admin123\!@# https://localhost:9200/banking-soc-incidents-enriched/_count

# 7. Verify playbook generation
curl -k -u admin:Admin123\!@# https://localhost:9200/banking-soc-playbooks/_count

# 8. Check SOAR execution
curl -k -u admin:Admin123\!@# https://localhost:9200/banking-soc-actions/_count
```

### Enhanced Log Generation Modes

```bash
# Mode 1: Real-time streaming (default)
python3 scripts/enhanced_generator.py stream --duration 300 --rate 50

# Mode 2: Generate batch file
python3 scripts/enhanced_generator.py batch --output /tmp/logs.ndjson --count 10000 --anomalies

# Mode 3: Upload file to pipeline
python3 scripts/enhanced_generator.py upload --file /tmp/logs.ndjson

# Mode 4: Generate historical dataset (30 days)
python3 scripts/enhanced_generator.py historical --output-dir /tmp/historical --days 30 --logs-per-day 10000

# Mode 5: Generate attack scenarios
python3 scripts/enhanced_generator.py attacks --output-dir /tmp/attacks
```

## Troubleshooting

### No logs in OpenSearch
```bash
# Check Vector status
docker logs vector-ingest --tail 100

# Verify Vector is sending
curl http://localhost:8686/metrics | grep component_sent_events_total

# Check OpenSearch health
curl -k -u admin:Admin123\!@# https://localhost:9200/_cluster/health
```

### Incidents not enriching
```bash
# Check enrichment service logs
docker logs enrichment --tail 100

# Verify incident polling
curl http://localhost:8002/api/stats

# Check OpenSearch incidents
curl -k -u admin:Admin123\!@# https://localhost:9200/banking-soc-incidents/_search
```

### Playbooks not generating
```bash
# Check LLM API keys
docker exec enrichment env | grep -E 'OPENAI|ANTHROPIC|HUGGING'

# Check LLM service logs
docker logs enrichment --tail 100 | grep -i llm

# Test LLM endpoint
curl http://localhost:8002/api/llm/test
```

### SOAR not executing
```bash
# Check SOAR service
docker logs soar-automation --tail 100

# Check PostgreSQL connection
docker exec soar-automation python3 -c "import asyncpg; print('OK')"

# Verify playbook status
curl -k -u admin:Admin123\!@# \
  https://localhost:9200/banking-soc-playbooks/_search \
  -d '{"query":{"term":{"status":"approved"}}}'
```

## Expected Metrics

### Healthy System (after 1 hour of operation)

| Metric | Expected Value |
|--------|----------------|
| Logs ingested | 50,000+ |
| Wazuh alerts | 500+ |
| Incidents detected | 50-100 |
| Incidents enriched | 50-100 |
| Playbooks generated | 50-100 |
| SOAR actions executed | 10-50 |
| False positive rate | < 5% |
| MTTD | < 5 minutes |
| MTTR | < 15 minutes |
| Pipeline latency | < 2 seconds |
| OpenSearch cluster | Green/Yellow |
| All services | Healthy |

## Compliance & Audit

### Log Retention
- **Hot tier**: Last 7 days (SSD, fast access)
- **Warm tier**: 8-30 days (Standard disk)
- **Cold tier**: 31-365 days (Archive storage)
- **Frozen tier**: 365+ days (Glacier-equivalent)

### Audit Trail
- All SOAR actions logged to PostgreSQL
- Enrichment decisions recorded in OpenSearch
- ML model versions tracked in Redis
- Analyst actions captured via API

## Next Steps

1. **Run validation script**: `python3 scripts/validate_flow.py`
2. **Review results**: Check all integration points
3. **Fix issues**: Address any failed checks
4. **Load test**: Generate high-volume logs
5. **Tune performance**: Optimize based on metrics
6. **Document findings**: Update runbook

---
**Validation Status**: ⏳ Pending execution
**Last Updated**: 2024-01-15
**Version**: 1.0
