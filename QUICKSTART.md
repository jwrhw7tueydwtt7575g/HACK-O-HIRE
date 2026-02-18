# 🚀 Quick Start Guide - Enterprise Banking Autonomous SOC

## 5-Minute Setup

### Prerequisites Check
```bash
# Verify Docker
docker --version  # Should be 20.10+

# Verify Docker Compose
docker-compose --version  # Should be 2.20+

# Check system resources
free -h  # Should show 16GB+ RAM
```

### Step 1: Clone & Configure (2 minutes)

```bash
# Navigate to project directory
cd "Enterprise Banking Autonomus SOC"

# Create environment file
cp .env.template .env

# Edit with your API keys (OPTIONAL for testing)
nano .env
```

**Minimum Required**:
- No API keys needed for basic testing
- System will work with mock data initially

**For Full Functionality**:
- `OPENAI_API_KEY`: For GPT-4o playbook generation
- `NVD_API_KEY`: For CVE lookups (free from nvd.nist.gov)

### Step 2: Deploy (3 minutes)

```bash
# One-command deployment
./deploy.sh

# Wait for services to start (~3 minutes)
# Script will auto-configure everything
```

**What the script does**:
- ✅ Checks prerequisites
- ✅ Generates secure passwords
- ✅ Creates directories
- ✅ Pulls Docker images
- ✅ Starts all 13 services
- ✅ Initializes databases
- ✅ Displays access information

### Step 3: Verify (30 seconds)

```bash
# Check all services are running
docker-compose ps

# Should see 13 services with "healthy" status
```

### Step 4: Access Platform (immediate)

Open your browser:

1. **OpenSearch Dashboards** → http://localhost:5601
   - Username: `admin`
   - Password: Check `.env` file

2. **Grafana** → http://localhost:3000
   - Username: `admin`
   - Password: Check `.env` file

3. **Neo4j Browser** → http://localhost:7474
   - Username: `neo4j`
   - Password: Check `.env` file

### Step 5: Generate Test Data

```bash
# Start log simulation
docker-compose exec log-simulator python /app/log_simulator.py --mode continuous

# Or simulate specific attack
docker-compose exec log-simulator python /app/log_simulator.py --mode attack --scenario brute_force
```

---

## 📊 What You'll See

### Within 1 Minute:
- Logs flowing into OpenSearch
- Vector processing and normalizing
- Wazuh creating alerts

### Within 5 Minutes:
- UEBA analyzing behavioral patterns
- Enrichment adding CVE/threat intel
- LLM generating response playbooks
- SOAR executing automated actions

### In OpenSearch Dashboards:
```
Discover → Select "banking-soc-logs-*" index
You'll see:
- Banking transactions
- Windows security events
- API access logs
- Database audit logs
- Firewall events
```

---

## 🎯 Quick Use Cases

### Use Case 1: View Simulated Attack

```bash
# Generate brute force attack
docker-compose exec log-simulator python /app/log_simulator.py \
  --mode attack --scenario brute_force

# View in OpenSearch Dashboards:
# 1. Go to Discover
# 2. Filter by event_category: authentication
# 3. Look for event_id: 4625 (failed logins)
```

### Use Case 2: Check Incident Enrichment

```bash
# Query enriched incidents
docker-compose exec enrichment curl http://localhost:8002/health

# View in OpenSearch:
# Index: banking-soc-incidents-enriched
# Contains: CVE data, threat intel, risk scores
```

### Use Case 3: View Generated Playbooks

```bash
# Check playbook generation
docker-compose logs -f enrichment | grep "Generated playbook"

# View in OpenSearch:
# Index: banking-soc-playbooks
# Contains: Response steps, executive summaries, SOAR actions
```

### Use Case 4: Monitor SOAR Actions

```bash
# View automated responses
docker-compose logs -f soar-automation

# Check SOAR API
curl http://localhost:8003/health
```

---

## 🔍 Monitoring & Troubleshooting

### Check Service Health
```bash
# All services
docker-compose ps

# Individual service logs
docker-compose logs -f [service-name]

# Example: Check enrichment service
docker-compose logs -f enrichment | tail -100
```

### Common Issues & Fixes

**Issue**: OpenSearch won't start
```bash
# Fix: Increase vm.max_map_count
sudo sysctl -w vm.max_map_count=262144
docker-compose restart opensearch
```

**Issue**: Out of memory
```bash
# Fix: Increase Docker memory
# Docker Desktop: Settings → Resources → Memory → 16GB+
# Restart Docker and redeploy
```

**Issue**: Port already in use
```bash
# Check which service is using port
sudo lsof -i :5601  # Example for port 5601

# Stop conflicting service or change port in docker-compose.yml
```

**Issue**: Services not connecting
```bash
# Restart all services
docker-compose down
docker-compose up -d

# Wait 2-3 minutes for initialization
```

---

## 📈 Next Steps

### 1. Explore Dashboards (10 minutes)

**OpenSearch Dashboards**:
```
1. Create Index Pattern: banking-soc-logs-*
2. Go to Discover → Explore logs
3. Create visualizations (pie charts, timelines)
4. Build custom dashboard
```

**Grafana**:
```
1. Add OpenSearch data source
2. Import pre-built dashboards (if available)
3. Create custom panels for:
   - Incident volume over time
   - Alert severity distribution
   - SOAR action execution rate
   - Model performance metrics
```

### 2. Customize for Your Environment (30 minutes)

**Edit Asset Inventory**:
```bash
nano enrichment/config/assets.json

# Add your organization's assets:
{
  "your-server-01": {
    "asset_id": "your-server-01",
    "asset_name": "Your Server Name",
    "business_unit": "core_banking",
    "criticality_score": 10,
    "ip_addresses": ["10.0.1.100"]
  }
}
```

**Configure Detection Rules**:
```bash
# Add custom Wazuh rules
nano wazuh/config/rules/banking_custom.xml

# Example rule:
<rule id="100001" level="10">
  <if_group>authentication_failed</if_group>
  <match>Failed password</match>
  <description>Multiple failed login attempts detected</description>
</rule>
```

### 3. Integrate with Your Systems (1 hour)

**Forward Real Logs to Vector**:
```bash
# Update your systems to send logs to:
# TCP: vector-ingest:5140
# UDP: vector-ingest:514
# HTTP: http://vector-ingest:8080/api/logs
```

**Configure Notifications**:
```bash
# Edit .env file
SMTP_HOST=smtp.yourcompany.com
SMTP_USER=soc-alerts@yourcompany.com
SLACK_WEBHOOK_URL=https://hooks.slack.com/your-webhook
```

### 4. Enable Production Features

**TLS Certificates**:
```bash
# Replace self-signed certs
cp /path/to/your/cert.pem certs/
cp /path/to/your/key.pem certs/

# Update docker-compose.yml with cert paths
```

**High Availability**:
```bash
# Scale services
docker-compose up -d --scale ai-intelligence=3

# Add load balancer (nginx/haproxy)
```

**Backup Configuration**:
```bash
# Create backup script
#!/bin/bash
docker-compose exec postgres pg_dump soar_db > backups/soar_$(date +%Y%m%d).sql
docker-compose exec opensearch curl -X PUT "localhost:9200/_snapshot/backup"
```

---

## 🎓 Learning Path

### Beginner (Week 1)
- [ ] Understand architecture diagram
- [ ] Explore OpenSearch Dashboards
- [ ] Run different attack scenarios
- [ ] Review generated playbooks
- [ ] Understand incident flow

### Intermediate (Week 2-3)
- [ ] Customize asset inventory
- [ ] Add custom Wazuh rules
- [ ] Configure LLM prompts
- [ ] Set up Grafana dashboards
- [ ] Integrate with SMTP/Slack

### Advanced (Week 4+)
- [ ] Develop custom enrichment sources
- [ ] Fine-tune UEBA models
- [ ] Create custom SOAR actions
- [ ] Implement feedback loops
- [ ] Deploy to production with HA

---

## 📞 Getting Help

### Documentation
- `README.md` - Comprehensive guide
- `DEPLOYMENT_SUMMARY.md` - Implementation status
- `docs/` - Detailed documentation

### Logs & Debugging
```bash
# View all logs
docker-compose logs -f

# Specific service
docker-compose logs -f enrichment

# Search logs for errors
docker-compose logs | grep -i error

# Check service health
curl http://localhost:8001/health  # AI Intelligence
curl http://localhost:8002/health  # Enrichment
curl http://localhost:8003/health  # SOAR
```

### Common Commands
```bash
# Restart service
docker-compose restart [service-name]

# Rebuild service
docker-compose up -d --build [service-name]

# Stop all services
docker-compose down

# Stop and remove volumes (CAUTION: Deletes data)
docker-compose down -v

# View resource usage
docker stats
```

---

## ✅ Success Checklist

After 5 minutes, you should have:
- [ ] All 13 services running (green in `docker-compose ps`)
- [ ] OpenSearch accessible at http://localhost:5601
- [ ] Logs visible in OpenSearch Dashboards
- [ ] Grafana accessible at http://localhost:3000
- [ ] Neo4j accessible at http://localhost:7474
- [ ] Log simulator generating traffic

After 1 hour, you should see:
- [ ] Incidents enriched with CVE/threat intel
- [ ] LLM-generated playbooks
- [ ] SOAR actions executed
- [ ] Behavioral baselines being built
- [ ] Metrics in Grafana

---

## 🎉 You're Ready!

You now have a **production-grade, AI-powered SOC platform** running!

**What's happening behind the scenes**:
1. Log simulator generates realistic banking logs
2. Vector normalizes and enriches logs
3. Wazuh detects threats using rules
4. AI Intelligence analyzes behavior (UEBA)
5. Enrichment adds CVE/threat intel
6. LLM generates response playbooks
7. SOAR automates responses
8. Feedback loop optimizes models

**Next Actions**:
- Explore the dashboards
- Run attack scenarios
- Review generated playbooks
- Customize for your environment
- Read full documentation

---

**🏦 Welcome to the Future of Banking Security Operations! 🚀**
