# Corrected Commands for Enterprise Banking SOC
## (Properly escaped for zsh)

## ✅ OpenSearch is now running WITHOUT authentication
### Security plugin is disabled for development

---

## Quick Status Checks

```bash
# 1. Check OpenSearch health (NO AUTH NEEDED!)
curl -s 'http://localhost:9200/_cluster/health' | jq '.'

# 2. Check running services
docker compose ps

# 3. Check specific service logs
docker compose logs -f opensearch
docker compose logs -f vector-ingest
docker compose logs -f wazuh-manager

# 4. Check Vector metrics
curl -s 'http://localhost:8686/health'

# 5. List OpenSearch indices
curl -s 'http://localhost:9200/_cat/indices?v'

# 6. Count documents in indices
curl -s 'http://localhost:9200/banking-soc-logs-*/_count'
curl -s 'http://localhost:9200/wazuh-alerts-*/_count'
curl -s 'http://localhost:9200/banking-soc-incidents/_count'
```

---

## Start All Services

```bash
# Start core services
docker compose up -d opensearch redis postgres neo4j

# Wait for OpenSearch to be ready (30-45 seconds)
sleep 45 && curl 'http://localhost:9200/_cluster/health'

# Start Vector for log ingestion
docker compose up -d vector-ingest

# Start Wazuh for detection
docker compose up -d wazuh-manager

# Start log simulator
docker compose up -d log-simulator

# Optional: Start AI services (requires more RAM)
docker compose up -d ai-intelligence enrichment soar-automation
```

---

## Validation Commands

```bash
# Run full end-to-end validation
./scripts/validate_end_to_end.sh

# Or use helper script for common operations
./scripts/helper_commands.sh
```

---

## Important Changes Made

1. **OpenSearch**: Security plugin is now DISABLED (`DISABLE_SECURITY_PLUGIN=true`)
2. **No Authentication Required**: All OpenSearch queries work without `-u admin:password`
3. **Memory**: Reduced to 2GB (was 4GB) for better compatibility
4. **Volumes**: Removed custom config volume mounts that were causing issues

---

## Testing Data Flow

```bash
# 1. Check if Vector is forwarding logs to OpenSearch
curl 'http://localhost:9200/banking-soc-logs-*/_count'

# 2. View recent logs
curl 'http://localhost:9200/banking-soc-logs-*/_search?size=1&sort=@timestamp:desc' | jq '.'

# 3. Check Wazuh alerts
curl 'http://localhost:9200/wazuh-alerts-*/_count'

# 4. View Vector throughput metrics
curl 'http://localhost:8686/metrics' | grep events_processed_total
```

---

## Stopping Services

```bash
# Stop all services
docker compose down

# Stop and remove all data (complete reset)
docker compose down -v
```

---

## Next Steps

1. ✅ OpenSearch is running (green status)
2. ⏳ Start Vector and Wazuh
3. ⏳ Start log simulator
4. ⏳ Verify logs are flowing through the pipeline
5. ⏳ Start AI services (optional)

Run these commands to continue:

```bash
# Start remaining services
docker compose up -d vector-ingest wazuh-manager log-simulator

# Watch logs
docker compose logs -f vector-ingest wazuh-manager

# After 1-2 minutes, check data flow
curl 'http://localhost:9200/_cat/indices?v'
```
