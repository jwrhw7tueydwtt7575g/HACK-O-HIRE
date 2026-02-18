# Enterprise Banking Autonomous SOC Platform

**Production-Grade, AI-Powered Security Operations Center for Banking Infrastructure**

![Version](https://img.shields.io/badge/version-1.0.0-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Docker](https://img.shields.io/badge/docker-compose-2496ED?logo=docker)
![Python](https://img.shields.io/badge/python-3.11-3776AB?logo=python)

## 🏦 Overview

A comprehensive, containerized Security Operations Center (SOC) platform designed specifically for enterprise banking environments. This system implements strict zone separation (Production vs. Analytics), advanced behavioral analytics (UEBA), automated threat intelligence enrichment, LLM-powered playbook generation, and intelligent SOAR automation.

### Key Features

- **🔒 Zone Separation**: Strict network segregation between banking production (Zone 1) and SOC analytics (Zone 2)
- **📊 UEBA Analytics**: Machine learning-based user and entity behavior anomaly detection
- **🧠 LLM Playbook Generation**: Automated incident response playbooks using GPT-4o/Claude/LLaMA
- **🔍 Threat Intelligence**: Real-time CVE/NVD, CISA KEV, and IOC enrichment
- **⚡ SOAR Automation**: Severity-based automated response with rollback support
- **📈 Attack Chain Reconstruction**: Neo4j graph analytics for attack path visualization
- **🎯 MITRE ATT&CK Mapping**: Automated technique identification and tactic classification
- **🔄 Continuous Learning**: Feedback loop for model retraining and rule optimization

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                     ZONE 1: BANKING PRODUCTION                  │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │  Log Simulators (Core Banking, API, DB, Windows, AD,     │   │
│  │  Firewall, Cloud, Mainframe)                             │   │
│  └────────────────────────┬─────────────────────────────────┘   │
│                           │ Outbound-Only (TLS)                 │
└───────────────────────────┼─────────────────────────────────────┘
                            │
┌───────────────────────────┼─────────────────────────────────────┐
│                     LOG TRANSIT ZONE                            │
│  ┌────────────────────────▼─────────────────────────────────┐   │
│  │  Vector ETL: Normalize, Enrich, Deduplicate, Route      │   │
│  └────────────┬──────────────────────┬────────────────────┘   │
└───────────────┼──────────────────────┼────────────────────────┘
                │                      │
┌───────────────┼──────────────────────┼────────────────────────┐
│               │  ZONE 2: SOC ANALYTICS│                        │
│  ┌────────────▼───────┐   ┌──────────▼──────────┐             │
│  │  Wazuh Manager     │   │  OpenSearch         │             │
│  │  - Rule Detection  │   │  - Log Storage      │             │
│  │  - MITRE Tagging   │   │  - Hot/Warm/Cold    │             │
│  │  - Incident Gen    │   │  - Dashboards       │             │
│  └──────┬─────────────┘   └─────────┬───────────┘             │
│         │                           │                          │
│  ┌──────▼───────────────────────────▼───────────┐             │
│  │  AI Intelligence Layer (UEBA)                │             │
│  │  - Isolation Forest, AutoEncoder, HBOS       │             │
│  │  - User/Entity Baselines                     │             │
│  │  - Neo4j Graph Analytics                     │             │
│  │  - Risk Scoring (0-100)                      │             │
│  └──────┬───────────────────────────────────────┘             │
│         │                                                      │
│  ┌──────▼───────────────────────────────────────┐             │
│  │  Intelligence Enrichment Layer               │             │
│  │  - CVE/NVD Lookup                            │             │
│  │  - CISA KEV Check                            │             │
│  │  - Threat Intel IOC Matching                 │             │
│  │  - Asset Criticality Weighting               │             │
│  └──────┬───────────────────────────────────────┘             │
│         │                                                      │
│  ┌──────▼───────────────────────────────────────┐             │
│  │  LLM Playbook Generation                     │             │
│  │  - Incident Analysis                         │             │
│  │  - Response Playbooks                        │             │
│  │  - Executive Summaries                       │             │
│  │  - SOAR JSON Actions                         │             │
│  └──────┬───────────────────────────────────────┘             │
│         │                                                      │
│  ┌──────▼───────────────────────────────────────┐             │
│  │  SOAR Automation Engine                      │             │
│  │  - Automated Response Actions                │             │
│  │  - Rollback Support                          │             │
│  │  - Audit Logging                             │             │
│  │  - Approval Workflows                        │             │
│  └──────┬───────────────────────────────────────┘             │
│         │                                                      │
│  ┌──────▼───────────────────────────────────────┐             │
│  │  Feedback Loop                               │             │
│  │  - Model Retraining                          │             │
│  │  - Rule Optimization                         │             │
│  │  - False Positive Suppression                │             │
│  └──────────────────────────────────────────────┘             │
└─────────────────────────────────────────────────────────────────┘
```

## 📋 Prerequisites

- **Docker**: v20.10+
- **Docker Compose**: v2.20+
- **System Resources**:
  - CPU: 16+ cores recommended
  - RAM: 32GB minimum, 64GB recommended
  - Disk: 500GB+ SSD storage
  - Network: 1Gbps

## 🚀 Quick Start

### ✅ Pre-Flight Check
Before deploying, ensure all integration fixes have been applied. See [FIXES_APPLIED.md](FIXES_APPLIED.md) for details.

**Quick validation:**
```bash
./scripts/validate_end_to_end.sh
```

### 1. Clone and Configure

```bash
# Clone repository
git clone <repository-url>
cd "Enterprise Banking Autonomus SOC"

# Create environment file
cp .env.template .env

# Edit .env with your API keys and passwords
nano .env
```

### 2. Generate TLS Certificates (Optional but Recommended)

```bash
# Generate self-signed certificates for development
./scripts/generate-certs.sh

# For production, use your organization's CA certificates
```

### 3. Deploy the Platform

```bash
# Start all services
docker-compose up -d

# Check service health
docker-compose ps

# View logs
docker-compose logs -f
```

### 4. Initialize Services

```bash
# Setup OpenSearch indices
docker-compose exec opensearch bash -c "
  curl -X PUT 'localhost:9200/_index_template/banking-soc-logs' \
  -H 'Content-Type: application/json' \
  -d @/usr/share/opensearch/config/index-templates.json
"

# Initialize SOAR database
docker-compose exec postgres psql -U soar_user -d soar_db -f /docker-entrypoint-initdb.d/init.sql

# Verify Wazuh Manager
docker-compose exec wazuh-manager /var/ossec/bin/wazuh-control status
```

### 5. Start Log Simulation

```bash
# Start continuous log generation
docker-compose exec log-simulator python /app/log_simulator.py \
  --mode continuous \
  --host vector-ingest \
  --port 5140

# Or simulate specific attack scenarios
docker-compose exec log-simulator python /app/log_simulator.py \
  --mode attack \
  --scenario brute_force
```

## 🎯 Access Points

| Service | URL | Default Credentials |
|---------|-----|---------------------|
| **OpenSearch Dashboards** | http://localhost:5601 | admin / BankingSOC2024!Admin |
| **Grafana** | http://localhost:3000 | admin / Grafana2024!Admin |
| **Wazuh API** | https://localhost:55000 | wazuh-api / WazuhAPI2024!Secure |
| **AI Intelligence API** | http://localhost:8001 | N/A (Internal) |
| **Enrichment API** | http://localhost:8002 | N/A (Internal) |
| **SOAR API** | http://localhost:8003 | N/A (Internal) |
| **Neo4j Browser** | http://localhost:7474 | neo4j / Neo4jGraph2024! |
| **Prometheus** | http://localhost:9090 | N/A |

## 📊 Data Flow

### Log Ingestion Pipeline

1. **Zone 1 Log Simulators** → Generate realistic banking logs
2. **Vector ETL** → Normalize, enrich, deduplicate
3. **Wazuh Manager** → Rule-based detection, MITRE tagging
4. **OpenSearch** → Store raw logs and alerts

### Incident Processing Pipeline

1. **Wazuh** creates initial incident objects
2. **AI Intelligence (UEBA)** performs behavioral analysis
3. **Enrichment Layer** adds CVE/NVD, threat intel, asset context
4. **LLM Service** generates playbooks and summaries
5. **SOAR Engine** executes automated responses
6. **Feedback Loop** retrains models and optimizes rules

## 🔗 End-to-End Flow (4.1–4.7)

### 4.1 Ingestion Layer (Vector ETL & Normalisation)
- Collects and buffers raw logs from all Zone 1 export channels.
- Normalises heterogeneous events into a unified JSON schema for ML/LLM consumption.
- Lightweight enrichment: GeoIP resolution, asset tagging, business unit mapping.
- Noise filtering and deduplication to reduce alert fatigue.
- Routes clean events to Wazuh (detection) and OpenSearch (persistence/analytics).
- **Technology**: Vector (Rust-based, high-throughput ETL pipeline)
- **Output**: Clean, structured, normalised events — ML-ready JSON with consistent field naming.

### 4.2 Wazuh SIEM Layer (Detection & Initial Correlation)
- Decodes and parses normalised events (JSON, Sysmon XML, CEF, etc.).
- Applies rule-based detection: signatures, thresholds, correlation rules.
- Groups events into candidate incidents and assigns severity.
- Tags alerts with MITRE ATT&CK tactics/techniques.
- Produces an initial incident object for downstream AI processing.
- **Output**: Wazuh alerts forwarded to OpenSearch and an Initial Incident Object passed to AI Intelligence.

### 4.3 OpenSearch Storage Layer (Repository & Analytics)
- Persists raw events, Wazuh alerts, enriched incidents, and ML outputs.
- Hot/Warm/Cold retention tiers for performance and compliance.
- Full-text search and aggregations for threat hunting and forensics.
- Native ML integration for anomaly detection and baselining.
- Dashboards for SOC analyst visibility.

### 4.4 AI Intelligence Layer (UEBA & Behavioural Modelling)
- Builds behavioural baselines for users and entities (logins, access, transactions, device activity).
- Continuously updates baselines to accommodate legitimate drift.
- Detects anomalies using Isolation Forest, AutoEncoder, HBOS, and graph analytics (Neo4j).
- Outputs risk scores, confidence, attack-chain reconstruction, and refined incident objects.

### 4.5 Intelligence Enrichment Layer
- CVE matching against NVD and software inventories on affected assets.
- Exploit availability lookup (ExploitDB, CISA KEV).
- Asset criticality weighting by business impact.
- Threat intel tagging via STIX/TAXII, OpenCTI, MISP IOC matching.
- Full MITRE ATT&CK context mapping.
- **Output**: Enriched Incident Object with risk score, confidence, CVE data, exploit status, asset criticality, threat intel matches, and business unit context.

### 4.6 LLM Playbook Generation Layer
- Converts the Enriched Incident Object into actionable guidance.
- Produces: response plan, analyst summary, executive summary, and SOAR JSON actions.
- Supports on‑prem LLaMA 3 / Mistral and cloud GPT‑4o for burst capacity.
- Fine-tuning pipeline keeps responses aligned with banking policies.

### 4.7 SOAR / Automated Response Layer
- Executes playbooks based on incident severity with guardrails.
- Balances automation speed with human oversight for critical actions.
- Records execution status and audit trails for compliance.

## 🔧 Configuration

### LLM Configuration

The platform supports multiple LLM backends:

**Cloud Mode (Recommended for Production)**:
```yaml
llm:
  mode: "cloud"
  openai_api_key: "${OPENAI_API_KEY}"  # For GPT-4o
  anthropic_api_key: "${ANTHROPIC_API_KEY}"  # For Claude
```

**On-Premises Mode** (Requires GPU):
```yaml
llm:
  mode: "on_premises"
  local_model: "meta-llama/Llama-2-13b-chat-hf"
  model_cache_dir: "/models"
```

**Hybrid Mode**:
```yaml
llm:
  mode: "hybrid"  # Uses cloud for fast response, local as fallback
```

### UEBA Model Configuration

```yaml
model_config:
  isolation_forest:
    contamination: 0.1
    n_estimators: 100
  baseline_window_days: 30
  update_interval_hours: 6
  risk_threshold_high: 0.8
  risk_threshold_medium: 0.6
```

### Asset Criticality Mapping

Edit `enrichment/config/assets.json` to define your organization's assets:

```json
{
  "core-banking-01": {
    "asset_id": "core-banking-01",
    "asset_name": "Core Banking Primary Server",
    "business_unit": "core_banking",
    "criticality_score": 10,
    "owner": "ops@bank.com",
    "ip_addresses": ["10.0.1.10"],
    "hostnames": ["core-banking-01.internal"]
  }
}
```

## 🧪 Testing

### Unit Tests
```bash
# Run all tests
docker-compose exec enrichment pytest /app/tests/

# Run specific test suite
docker-compose exec ai-intelligence pytest /app/tests/test_ueba.py
```

### Integration Tests
```bash
# Test complete incident processing flow
python scripts/test_e2e_incident_flow.py

# Simulate attack scenarios
python scripts/log_simulator.py --mode attack --scenario privilege_escalation
```

### Performance Testing
```bash
# Load test with high volume logs
python scripts/log_simulator.py --mode continuous --logs-per-second 500
```

## 📈 Monitoring

### Metrics Endpoints

- **Vector**: `http://localhost:8686/metrics`
- **AI Intelligence**: `http://localhost:8001/metrics`
- **Enrichment**: `http://localhost:8002/metrics`
- **SOAR**: `http://localhost:8003/metrics`
- **Prometheus**: `http://localhost:9090`

### Health Checks

```bash
# Check all services
docker-compose ps

# Individual health checks
curl http://localhost:8001/health  # AI Intelligence
curl http://localhost:8002/health  # Enrichment
curl http://localhost:8003/health  # SOAR
```

### Log Aggregation

All service logs are available via Docker:

```bash
# View all logs
docker-compose logs -f

# Specific service
docker-compose logs -f enrichment

# Last 100 lines
docker-compose logs --tail=100 ai-intelligence
```

## 🔒 Security Considerations

### Network Isolation

- **Zone 1** (Production): Internal network with outbound-only log export
- **Log Transit**: Isolated bridge network for Vector ETL
- **Zone 2** (SOC): Internal analytics network with controlled external access

### Credential Management

- Store secrets in `.env` file (never commit to git)
- Use Docker secrets for production deployments
- Rotate credentials regularly (90 days recommended)
- Enable MFA for all administrative accounts

### TLS/SSL

For production:
```bash
# Generate production certificates
openssl req -x509 -nodes -days 365 -newkey rsa:4096 \
  -keyout certs/key.pem -out certs/cert.pem

# Update docker-compose.yml with certificate volumes
```

### Compliance

The platform supports:
- **PCI-DSS**: Payment card data security
- **SOX**: Financial reporting controls
- **Basel III**: Operational risk management
- **GDPR/CCPA**: Data privacy regulations

## 🐛 Troubleshooting

### Common Issues

**OpenSearch won't start**:
```bash
# Increase vm.max_map_count
sudo sysctl -w vm.max_map_count=262144
echo "vm.max_map_count=262144" | sudo tee -a /etc/sysctl.conf
```

**Out of memory errors**:
```bash
# Increase Docker memory limit in Docker Desktop or daemon.json
{
  "memory": "16g"
}
```

**Wazuh agents not connecting**:
```bash
# Check firewall rules
sudo ufw allow 1514/tcp
sudo ufw allow 1515/tcp
```

**LLM API rate limits**:
```yaml
# Reduce concurrent requests in enrichment config
max_concurrent_enrichments: 2
```

## 📚 Documentation

- **[Architecture Guide](docs/ARCHITECTURE.md)**: Detailed system design
- **[API Reference](docs/API.md)**: Complete API documentation
- **[Deployment Guide](docs/DEPLOYMENT.md)**: Production deployment instructions
- **[Incident Response Runbook](docs/RUNBOOK.md)**: Operational procedures
- **[Development Guide](docs/DEVELOPMENT.md)**: Contributing guidelines

## 🤝 Contributing

We welcome contributions! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## 📄 License

This project is licensed under the MIT License - see [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- **Wazuh**: Open-source SIEM and XDR platform
- **OpenSearch**: Distributed search and analytics engine
- **Vector**: High-performance observability data pipeline
- **Neo4j**: Graph database for attack chain analysis
- **OpenAI/Anthropic**: LLM providers for playbook generation

## 📞 Support

For issues, questions, or feature requests:
- **GitHub Issues**: [Create an issue](https://github.com/your-org/banking-soc/issues)
- **Email**: security-ops@yourbank.com
- **Slack**: #security-operations

---

**⚠️ IMPORTANT SECURITY NOTICE**: This platform handles sensitive security data. Ensure proper access controls, network segmentation, and regular security audits in production environments.

**Built with ❤️ for Enterprise Banking Security**
