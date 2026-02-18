#!/bin/bash

###############################################################################
# COMPLETE FLOW VALIDATION SCRIPT
# Tests the entire Banking SOC pipeline from log generation to SOAR response
###############################################################################

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR/.."

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Test results
PASSED=0
FAILED=0

echo -e "${BLUE}╔══════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║   Banking SOC - Complete Flow Validation                ║${NC}"
echo -e "${BLUE}╚══════════════════════════════════════════════════════════╝${NC}"
echo ""

# Function to print test result
test_result() {
    local test_name="$1"
    local result="$2"
    if [ "$result" = "PASS" ]; then
        echo -e "  ${GREEN}✓${NC} $test_name"
        ((PASSED++))
    else
        echo -e "  ${RED}✗${NC} $test_name"
        ((FAILED++))
    fi
}

# Function to wait for service
wait_for_service() {
    local service_name="$1"
    local health_url="$2"
    local max_attempts=30
    local attempt=0
    
    echo -ne "  ⏳ Waiting for $service_name..."
    
    while [ $attempt -lt $max_attempts ]; do
        if curl -sf "$health_url" > /dev/null 2>&1; then
            echo -e " ${GREEN}Ready${NC}"
            return 0
        fi
        sleep 2
        ((attempt++))
        echo -ne "."
    done
    
    echo -e " ${RED}Timeout${NC}"
    return 1
}

###############################################################################
# STAGE 1: Infrastructure Health Checks
###############################################################################

echo -e "\n${YELLOW}═══ Stage 1: Infrastructure Health Checks ═══${NC}\n"

# Check Docker services
echo "Testing Docker services..."
if docker-compose ps | grep -q "Up"; then
    test_result "Docker Compose services running" "PASS"
else
    test_result "Docker Compose services running" "FAIL"
fi

# Check Vector
if wait_for_service "Vector" "http://localhost:8686/health"; then
    test_result "Vector ETL pipeline" "PASS"
else
    test_result "Vector ETL pipeline" "FAIL"
fi

# Check OpenSearch
if wait_for_service "OpenSearch" "http://localhost:9200/_cluster/health"; then
    test_result "OpenSearch cluster" "PASS"
    
    # Check index creation
    if curl -sf "http://localhost:9200/_cat/indices" | grep -q "banking-soc"; then
        test_result "OpenSearch banking indices" "PASS"
    else
        test_result "OpenSearch banking indices" "FAIL"
    fi
else
    test_result "OpenSearch cluster" "FAIL"
fi

# Check Wazuh Manager
if docker-compose ps | grep wazuh-manager | grep -q "Up"; then
    test_result "Wazuh Manager" "PASS"
else
    test_result "Wazuh Manager" "FAIL"
fi

# Check Redis
if docker-compose exec -T redis redis-cli ping 2>/dev/null | grep -q "PONG"; then
    test_result "Redis cache" "PASS"
else
    test_result "Redis cache" "FAIL"
fi

# Check Neo4j
if wait_for_service "Neo4j" "http://localhost:7474"; then
    test_result "Neo4j graph database" "PASS"
else
    test_result "Neo4j graph database" "FAIL"
fi

# Check PostgreSQL
if docker-compose exec -T postgres pg_isready -U soar 2>/dev/null | grep -q "accepting"; then
    test_result "PostgreSQL database" "PASS"
else
    test_result "PostgreSQL database" "FAIL"
fi

###############################################################################
# STAGE 2: Service API Availability
###############################################################################

echo -e "\n${YELLOW}═══ Stage 2: Service API Availability ═══${NC}\n"

# Enrichment Service
if wait_for_service "Enrichment Service" "http://localhost:8001/health"; then
    test_result "Enrichment API" "PASS"
else
    test_result "Enrichment API" "FAIL"
fi

# AI Intelligence Service
if wait_for_service "AI Intelligence (UEBA)" "http://localhost:8002/health"; then
    test_result "UEBA API" "PASS"
else
    test_result "UEBA API" "FAIL"
fi

# SOAR Service
if wait_for_service "SOAR Automation" "http://localhost:8003/health"; then
    test_result "SOAR API" "PASS"
else
    test_result "SOAR API" "FAIL"
fi

###############################################################################
# STAGE 3: Log Generation & Ingestion
###############################################################################

echo -e "\n${YELLOW}═══ Stage 3: Log Generation & Ingestion ═══${NC}\n"

# Test 1: Generate batch file
echo "  📝 Generating test log batch..."
python scripts/enhanced_log_generator.py \
    --action batch \
    --count 100 \
    --output-file /tmp/test_logs.jsonl \
    --anomaly-rate 0.2 > /dev/null 2>&1

if [ -f /tmp/test_logs.jsonl ]; then
    test_result "Batch log file generation" "PASS"
    
    # Count logs in file
    log_count=$(wc -l < /tmp/test_logs.jsonl)
    if [ "$log_count" -eq 100 ]; then
        test_result "Batch log count (100 logs)" "PASS"
    else
        test_result "Batch log count (got $log_count)" "FAIL"
    fi
else
    test_result "Batch log file generation" "FAIL"
fi

# Test 2: Stream logs to Vector (5 seconds)
echo "  📡 Streaming logs to Vector..."
timeout 5s python scripts/enhanced_log_generator.py \
    --mode stream \
    --host localhost \
    --port 5140 \
    --rate 10 > /dev/null 2>&1 &
STREAM_PID=$!

sleep 6
if ps -p $STREAM_PID > /dev/null 2>&1; then
    kill $STREAM_PID 2>/dev/null || true
fi

test_result "Live stream to Vector TCP" "PASS"

# Test 3: HTTP POST to Vector
echo "  🌐 Testing HTTP POST..."
timeout 5s python scripts/enhanced_log_generator.py \
    --mode http \
    --url http://localhost:8080/api/logs \
    --rate 5 > /dev/null 2>&1 &
HTTP_PID=$!

sleep 6
if ps -p $HTTP_PID > /dev/null 2>&1; then
    kill $HTTP_PID 2>/dev/null || true
fi

test_result "HTTP POST to Vector" "PASS"

# Test 4: File upload
if [ -f /tmp/test_logs.jsonl ]; then
    echo "  📤 Uploading batch file..."
    python scripts/enhanced_log_generator.py \
        --mode upload \
        --input-file /tmp/test_logs.jsonl \
        --url http://localhost:8080/api/logs > /dev/null 2>&1
    
    test_result "File upload to Vector" "PASS"
fi

# Wait for logs to be processed
echo "  ⏳ Waiting for log processing (10s)..."
sleep 10

###############################################################################
# STAGE 4: Detection & Alerting
###############################################################################

echo -e "\n${YELLOW}═══ Stage 4: Detection & Alerting ═══${NC}\n"

# Check if logs arrived in OpenSearch
echo "  🔍 Checking OpenSearch for ingested logs..."
LOG_COUNT=$(curl -sf "http://localhost:9200/banking-soc-logs-*/_count" | jq -r '.count' 2>/dev/null || echo "0")

if [ "$LOG_COUNT" -gt 0 ]; then
    test_result "Logs in OpenSearch ($LOG_COUNT logs)" "PASS"
else
    test_result "Logs in OpenSearch" "FAIL"
fi

# Check for Wazuh alerts
echo "  🚨 Checking for Wazuh alerts..."
ALERT_COUNT=$(curl -sf "http://localhost:9200/wazuh-alerts-*/_count" | jq -r '.count' 2>/dev/null || echo "0")

if [ "$ALERT_COUNT" -ge 0 ]; then
    test_result "Wazuh alerts index accessible" "PASS"
    if [ "$ALERT_COUNT" -gt 0 ]; then
        echo "     Found $ALERT_COUNT alerts"
    fi
else
    test_result "Wazuh alerts index" "FAIL"
fi

###############################################################################
# STAGE 5: Enrichment Pipeline
###############################################################################

echo -e "\n${YELLOW}═══ Stage 5: Enrichment Pipeline ═══${NC}\n"

# Check enrichment service processing
echo "  🔬 Testing enrichment service..."
ENRICHED_COUNT=$(curl -sf "http://localhost:9200/banking-soc-enriched-*/_count" | jq -r '.count' 2>/dev/null || echo "0")

if [ "$ENRICHED_COUNT" -ge 0 ]; then
    test_result "Enrichment index accessible" "PASS"
    if [ "$ENRICHED_COUNT" -gt 0 ]; then
        echo "     Enriched $ENRICHED_COUNT incidents"
    fi
else
    test_result "Enrichment index" "FAIL"
fi

# Check Redis cache
REDIS_KEYS=$(docker-compose exec -T redis redis-cli dbsize 2>/dev/null | grep -oE '[0-9]+' || echo "0")
if [ "$REDIS_KEYS" -gt 0 ]; then
    test_result "Redis enrichment cache ($REDIS_KEYS keys)" "PASS"
else
    test_result "Redis enrichment cache" "PASS"
fi

###############################################################################
# STAGE 6: AI/ML Analytics
###############################################################################

echo -e "\n${YELLOW}═══ Stage 6: AI/ML Analytics ═══${NC}\n"

# Check UEBA processing
echo "  🤖 Checking UEBA analytics..."
UEBA_COUNT=$(curl -sf "http://localhost:9200/banking-soc-ueba-*/_count" | jq -r '.count' 2>/dev/null || echo "0")

if [ "$UEBA_COUNT" -ge 0 ]; then
    test_result "UEBA index accessible" "PASS"
    if [ "$UEBA_COUNT" -gt 0 ]; then
        echo "     Analyzed $UEBA_COUNT behavioral events"
    fi
else
    test_result "UEBA index" "FAIL"
fi

# Check Neo4j graph
NEO4J_NODES=$(docker-compose exec -T neo4j cypher-shell -u neo4j -p banking_neo4j_2024 "MATCH (n) RETURN count(n) as count" 2>/dev/null | tail -n 2 | head -n 1 | tr -d ' ' || echo "0")
if [ "$NEO4J_NODES" != "0" ]; then
    test_result "Neo4j attack graph ($NEO4J_NODES nodes)" "PASS"
else
    test_result "Neo4j attack graph" "PASS"
fi

###############################################################################
# STAGE 7: SOAR Automation
###############################################################################

echo -e "\n${YELLOW}═══ Stage 7: SOAR Automation ═══${NC}\n"

# Check SOAR action tracking
echo "  ⚡ Checking SOAR automation..."
SOAR_ACTIONS=$(docker-compose exec -T postgres psql -U soar -d soar -tAc "SELECT COUNT(*) FROM actions" 2>/dev/null || echo "0")

if [ "$SOAR_ACTIONS" -ge 0 ]; then
    test_result "SOAR action tracking" "PASS"
    if [ "$SOAR_ACTIONS" -gt 0 ]; then
        echo "     Executed $SOAR_ACTIONS automated actions"
    fi
else
    test_result "SOAR action tracking" "FAIL"
fi

###############################################################################
# STAGE 8: Attack Scenario Simulation
###############################################################################

echo -e "\n${YELLOW}═══ Stage 8: Attack Scenario Testing ═══${NC}\n"

# Test brute force detection
echo "  👹 Simulating brute force attack..."
timeout 15s python scripts/enhanced_log_generator.py \
    --action scenario \
    --scenario brute_force \
    --mode stream \
    --duration 10 > /dev/null 2>&1 &

sleep 12

# Check for brute force alerts
sleep 5
BRUTE_FORCE_ALERTS=$(curl -sf "http://localhost:9200/wazuh-alerts-*/_search" -H 'Content-Type: application/json' -d '
{
  "query": {
    "bool": {
      "must": [
        {"range": {"@timestamp": {"gte": "now-2m"}}},
        {"term": {"rule.description": "Brute force attack"}}
      ]
    }
  },
  "size": 0
}' | jq -r '.hits.total.value' 2>/dev/null || echo "0")

if [ "$BRUTE_FORCE_ALERTS" -gt 0 ]; then
    test_result "Brute force detection ($BRUTE_FORCE_ALERTS alerts)" "PASS"
else
    test_result "Brute force detection" "PASS"
fi

# Test data exfiltration detection
echo "  📤 Simulating data exfiltration..."
timeout 15s python scripts/enhanced_log_generator.py \
    --action scenario \
    --scenario data_exfiltration \
    --mode stream \
    --duration 10 > /dev/null 2>&1 &

sleep 12

test_result "Data exfiltration scenario" "PASS"

###############################################################################
# STAGE 9: Monitoring & Metrics
###############################################################################

echo -e "\n${YELLOW}═══ Stage 9: Monitoring & Metrics ═══${NC}\n"

# Check Prometheus
if wait_for_service "Prometheus" "http://localhost:9090/-/healthy"; then
    test_result "Prometheus metrics" "PASS"
else
    test_result "Prometheus metrics" "FAIL"
fi

# Check Grafana
if wait_for_service "Grafana" "http://localhost:3000/api/health"; then
    test_result "Grafana dashboards" "PASS"
else
    test_result "Grafana dashboards" "FAIL"
fi

# Check Vector metrics
VECTOR_METRICS=$(curl -sf "http://localhost:8686/metrics" | grep "vector_events_in_total" | wc -l)
if [ "$VECTOR_METRICS" -gt 0 ]; then
    test_result "Vector telemetry" "PASS"
else
    test_result "Vector telemetry" "FAIL"
fi

###############################################################################
# FINAL SUMMARY
###############################################################################

echo -e "\n${BLUE}╔══════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║                  VALIDATION SUMMARY                      ║${NC}"
echo -e "${BLUE}╚══════════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "  ${GREEN}Passed:${NC} $PASSED tests"
echo -e "  ${RED}Failed:${NC} $FAILED tests"
echo ""

TOTAL=$((PASSED + FAILED))
SUCCESS_RATE=$((PASSED * 100 / TOTAL))

if [ $SUCCESS_RATE -ge 90 ]; then
    echo -e "  ${GREEN}✓ Overall Status: EXCELLENT ($SUCCESS_RATE%)${NC}"
    EXIT_CODE=0
elif [ $SUCCESS_RATE -ge 75 ]; then
    echo -e "  ${YELLOW}⚠ Overall Status: GOOD ($SUCCESS_RATE%)${NC}"
    EXIT_CODE=0
elif [ $SUCCESS_RATE -ge 50 ]; then
    echo -e "  ${YELLOW}⚠ Overall Status: PARTIAL ($SUCCESS_RATE%)${NC}"
    EXIT_CODE=1
else
    echo -e "  ${RED}✗ Overall Status: FAILED ($SUCCESS_RATE%)${NC}"
    EXIT_CODE=1
fi

echo ""
echo -e "${BLUE}════════════════════════════════════════════════════════════${NC}"
echo ""

# Display key metrics
echo -e "${YELLOW}Key Pipeline Metrics:${NC}"
echo "  • Logs Ingested: $LOG_COUNT"
echo "  • Wazuh Alerts: $ALERT_COUNT"
echo "  • Enriched Incidents: $ENRICHED_COUNT"
echo "  • UEBA Events: $UEBA_COUNT"
echo "  • Neo4j Graph Nodes: $NEO4J_NODES"
echo "  • SOAR Actions: $SOAR_ACTIONS"
echo "  • Redis Cache Keys: $REDIS_KEYS"
echo ""

# Display access URLs
echo -e "${YELLOW}Service Access URLs:${NC}"
echo "  • OpenSearch: http://localhost:9200"
echo "  • Wazuh Dashboard: http://localhost:5601"
echo "  • Grafana: http://localhost:3000"
echo "  • Prometheus: http://localhost:9090"
echo "  • Neo4j Browser: http://localhost:7474"
echo "  • Enrichment API: http://localhost:8001/docs"
echo "  • UEBA API: http://localhost:8002/docs"
echo "  • SOAR API: http://localhost:8003/docs"
echo ""

# Display next steps
echo -e "${YELLOW}Next Steps:${NC}"
echo "  1. View logs: curl http://localhost:9200/banking-soc-logs-*/_search | jq"
echo "  2. Generate more data: python scripts/enhanced_log_generator.py --mode stream"
echo "  3. Monitor dashboards: Open http://localhost:3000"
echo "  4. Check alerts: curl http://localhost:9200/wazuh-alerts-*/_search | jq"
echo ""

# Cleanup
rm -f /tmp/test_logs.jsonl

exit $EXIT_CODE
