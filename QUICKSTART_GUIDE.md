# Quick Start Guide - Enterprise Banking SOC

## Prerequisites
- Docker with Compose v2 (`docker compose` command)
- At least 16GB RAM, 32GB recommended
- 100GB+ free disk space

## Important: Use `docker compose` not `docker-compose`

This project requires Docker Compose v2. Use the command **`docker compose`** (two words) instead of `docker-compose`.

## Quick Start (Minimal Setup)

### 1. Start Core Services Only

For initial testing, start only the essential services:

```bash
cd "/home/vivek/Desktop/Enterprise Banking Autonomus SOC"

# Start only OpenSearch, Redis, and supporting services
docker compose up -d opensearch redis postgres neo4j
```

Wait 2-3 minutes for OpenSearch to initialize, then check status:

```bash
# Check if OpenSearch is ready
curl -u admin:Admin123!@# http://localhost:9200/_cluster/health

# Expected output: {"cluster_name":"banking-soc-cluster","status":"green"...}
```

### 2. Start Vector (Log Ingestion)

```bash
docker compose up -d vector-ingest
```

Verify Vector is running:

```bash
curl http://localhost:8686/health
```

### 3. Start Wazuh (Detection Engine)

```bash
docker compose up -d wazuh-manager
```

Wait ~30 seconds for Wazuh to start, then verify:

```bash
docker compose logs wazuh-manager | grep "Started"
```

### 4. Start AI Services (Optional - Requires More Resources)

```bash
# Only start if you have 32GB+ RAM
docker compose up -d ai-intelligence enrichment soar-automation
```

### 5. Start Log Generator

```bash
docker compose up -d log-simulator
```

## Validation

### Check Running Services

```bash
docker compose ps
```

### Check Logs

```bash
# View all logs
docker compose logs -f

# View specific service logs
docker compose logs -f vector-ingest
docker compose logs -f wazuh-manager
docker compose logs -f opensearch
```

### Check Data Flow

```bash
# Check if logs are being indexed in OpenSearch
curl -u admin:Admin123!@# "http://localhost:9200/banking-soc-logs-*/_count"

# Check if Wazuh alerts are being generated
curl -u admin:Admin123!@# "http://localhost:9200/wazuh-alerts-*/_count"
```

## Access Points

| Service | URL | Credentials |
|---------|-----|-------------|
| OpenSearch API | http://localhost:9200 | admin / Admin123!@# |
| OpenSearch Dashboards | http://localhost:5601 | (same as above) |
| Vector Metrics | http://localhost:8686/metrics | none |
| Wazuh API | https://localhost:55000 | wazuh-api / WazuhAPI123! |

## Troubleshooting

### Build is Taking Too Long

The Python-based services (AI Intelligence, Enrichment, SOAR) install many dependencies. First build can take 5-10 minutes.

To speed up:
```bash
# Build only essential services first
docker compose build vector-ingest wazuh-manager log-simulator

# Start those
docker compose up -d vector-ingest wazuh-manager log-simulator opensearch redis

# Build others in background while testing
docker compose build ai-intelligence enrichment soar-automation &
```

### Out of Memory Errors

Reduce resource allocation:
```bash
# Edit docker-compose.yml, change OpenSearch memory:
# - "OPENSEARCH_JAVA_OPTS=-Xms2g -Xmx2g"  # Instead of 4g

# Or start only essential services (no AI/ML)
docker compose up -d opensearch vector-ingest wazuh-manager log-simulator
```

### Services Not Starting

Check logs:
```bash
docker compose logs vector-ingest
docker compose logs wazuh-manager
docker compose logs opensearch
```

Common issues:
- **OpenSearch**: Needs `vm.max_map_count=262144` on Linux
  ```bash
  sudo sysctl -w vm.max_map_count=262144
  ```
- **Wazuh**: May take 30-60s to fully initialize
- **Vector**: Check if config file is valid:
  ```bash
  docker compose run --rm vector-ingest vector validate --config /etc/vector/vector.toml
  ```

## Stopping Services

```bash
# Stop all services
docker compose down

# Stop and remove volumes (clean slate)
docker compose down -v
```

## Next Steps

Once services are running:

1. **View OpenSearch Dashboards**: http://localhost:5601
2. **Generate Test Logs**: Already running via log-simulator
3. **Monitor Metrics**: http://localhost:9090 (Prometheus) or http://localhost:3000 (Grafana)
4. **Review Documentation**:
   - [FIXES_APPLIED.md](FIXES_APPLIED.md) - All bug fixes and corrections
   - [docs/END_TO_END_FLOW.md](docs/END_TO_END_FLOW.md) - Complete data flow documentation
   - [FLOW_VALIDATION.md](FLOW_VALIDATION.md) - Validation procedures

## Full System Start

To start everything at once (requires 32GB+ RAM):

```bash
docker compose up -d --build
```

Monitor startup:

```bash
# Watch logs from all services
docker compose logs -f

# Or watch specific services
docker compose logs -f vector-ingest wazuh-manager ai-intelligence
```

Wait 3-5 minutes for all services to initialize, then run validation:

```bash
./scripts/validate_end_to_end.sh
```
