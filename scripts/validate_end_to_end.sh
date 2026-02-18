#!/bin/bash

# End-to-End Flow Validation Script
# Enterprise Banking SOC - Complete Pipeline Test

set -e

echo "=========================================="
echo "SOC End-to-End Flow Validation"
echo "=========================================="
echo ""

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Configuration
OPENSEARCH_URL="http://localhost:9200"
OPENSEARCH_USER="admin"
OPENSEARCH_PASS="Admin123!@#"
VECTOR_METRICS_URL="http://localhost:8686/metrics"
AI_INTELLIGENCE_URL="http://localhost:8001"
ENRICHMENT_URL="http://localhost:8002"
SOAR_URL="http://localhost:8003"

# Test counter
PASSED=0
FAILED=0

# Test function
test_endpoint() {
    local name=$1
    local url=$2
    local expected_code=${3:-200}
    
    echo -n "Testing $name... "
    
    if [ "$name" == "OpenSearch" ]; then
        response=$(curl -s -o /dev/null -w "%{http_code}" -u "$OPENSEARCH_USER:$OPENSEARCH_PASS" "$url")
    else
        response=$(curl -s -o /dev/null -w "%{http_code}" "$url" 2>/dev/null || echo "000")
    fi
    
    if [ "$response" == "$expected_code" ]; then
        echo -e "${GREEN}✓ PASS${NC} (HTTP $response)"
        ((PASSED++))
    else
        echo -e "${RED}✗ FAIL${NC} (HTTP $response, expected $expected_code)"
        ((FAILED++))
    fi
}

echo "1. LAYER 1: INGESTION (Vector ETL)"
echo "----------------------------------------"
test_endpoint "Vector Metrics API" "$VECTOR_METRICS_URL"
echo ""

echo "2. LAYER 2: SIEM (Wazuh)"
echo "----------------------------------------"
echo -n "Testing Wazuh Manager... "
if docker ps | grep -q "wazuh-manager"; then
    echo -e "${GREEN}✓ PASS${NC} (Container running)"
    ((PASSED++))
else
    echo -e "${RED}✗ FAIL${NC} (Container not running)"
    ((FAILED++))
fi
echo ""

echo "3. LAYER 3: STORAGE (OpenSearch)"
echo "----------------------------------------"
test_endpoint "OpenSearch" "$OPENSEARCH_URL"
test_endpoint "OpenSearch Cluster Health" "$OPENSEARCH_URL/_cluster/health"

# Check indices
echo -n "Checking banking-soc-logs index... "
response=$(curl -s -u "$OPENSEARCH_USER:$OPENSEARCH_PASS" "$OPENSEARCH_URL/banking-soc-logs-*/_count" 2>/dev/null)
if echo "$response" | grep -q "count"; then
    count=$(echo "$response" | grep -o '"count":[0-9]*' | grep -o '[0-9]*')
    echo -e "${GREEN}✓ PASS${NC} (${count} documents)"
    ((PASSED++))
else
    echo -e "${YELLOW}⚠ WARN${NC} (Index may not exist yet)"
fi

echo -n "Checking wazuh-alerts index... "
response=$(curl -s -u "$OPENSEARCH_USER:$OPENSEARCH_PASS" "$OPENSEARCH_URL/wazuh-alerts-*/_count" 2>/dev/null)
if echo "$response" | grep -q "count"; then
    count=$(echo "$response" | grep -o '"count":[0-9]*' | grep -o '[0-9]*')
    echo -e "${GREEN}✓ PASS${NC} (${count} alerts)"
    ((PASSED++))
else
    echo -e "${YELLOW}⚠ WARN${NC} (Index may not exist yet)"
fi

echo -n "Checking incidents index... "
response=$(curl -s -u "$OPENSEARCH_USER:$OPENSEARCH_PASS" "$OPENSEARCH_URL/banking-soc-incidents/_count" 2>/dev/null)
if echo "$response" | grep -q "count"; then
    count=$(echo "$response" | grep -o '"count":[0-9]*' | grep -o '[0-9]*')
    echo -e "${GREEN}✓ PASS${NC} (${count} incidents)"
    ((PASSED++))
else
    echo -e "${YELLOW}⚠ WARN${NC} (Index may not exist yet)"
fi
echo ""

echo "4. LAYER 4: AI INTELLIGENCE (UEBA)"
echo "----------------------------------------"
test_endpoint "AI Intelligence API" "$AI_INTELLIGENCE_URL/health" 200 || test_endpoint "AI Intelligence API (alt)" "$AI_INTELLIGENCE_URL" 200
echo ""

echo "5. LAYER 5: ENRICHMENT (CVE/NVD + LLM)"
echo "----------------------------------------"
test_endpoint "Enrichment API" "$ENRICHMENT_URL/health" 200 || test_endpoint "Enrichment API (alt)" "$ENRICHMENT_URL" 200
echo ""

echo "6. LAYER 6: SOAR AUTOMATION"
echo "----------------------------------------"
test_endpoint "SOAR API" "$SOAR_URL/health" 200 || test_endpoint "SOAR API (alt)" "$SOAR_URL/api/v1/actions" 200
echo ""

echo "7. SUPPORTING SERVICES"
echo "----------------------------------------"
echo -n "Testing Redis... "
if docker exec redis-cache redis-cli ping 2>/dev/null | grep -q "PONG"; then
    echo -e "${GREEN}✓ PASS${NC}"
    ((PASSED++))
else
    echo -e "${RED}✗ FAIL${NC}"
    ((FAILED++))
fi

echo -n "Testing Neo4j... "
if docker ps | grep -q "neo4j-graph"; then
    echo -e "${GREEN}✓ PASS${NC} (Container running)"
    ((PASSED++))
else
    echo -e "${RED}✗ FAIL${NC}"
    ((FAILED++))
fi

echo -n "Testing PostgreSQL... "
if docker exec postgres-db pg_isready -U soar_user 2>/dev/null | grep -q "accepting"; then
    echo -e "${GREEN}✓ PASS${NC}"
    ((PASSED++))
else
    echo -e "${RED}✗ FAIL${NC}"
    ((FAILED++))
fi
echo ""

echo "8. DATA FLOW VALIDATION"
echo "----------------------------------------"

# Check if Vector is receiving events
echo -n "Checking Vector ingestion rate... "
metrics=$(curl -s "$VECTOR_METRICS_URL" 2>/dev/null || echo "")
if echo "$metrics" | grep -q "component_received_events_total"; then
    echo -e "${GREEN}✓ PASS${NC} (Vector receiving events)"
    ((PASSED++))
else
    echo -e "${YELLOW}⚠ WARN${NC} (No events received yet)"
fi

# Check OpenSearch write operations
echo -n "Checking OpenSearch index operations... "
stats=$(curl -s -u "$OPENSEARCH_USER:$OPENSEARCH_PASS" "$OPENSEARCH_URL/_stats/indexing" 2>/dev/null)
if echo "$stats" | grep -q "index_total"; then
    echo -e "${GREEN}✓ PASS${NC} (Indexing active)"
    ((PASSED++))
else
    echo -e "${RED}✗ FAIL${NC} (No indexing activity)"
    ((FAILED++))
fi
echo ""

echo "=========================================="
echo "SUMMARY"
echo "=========================================="
echo -e "Tests Passed: ${GREEN}${PASSED}${NC}"
if [ $FAILED -gt 0 ]; then
    echo -e "Tests Failed: ${RED}${FAILED}${NC}"
else
    echo -e "Tests Failed: ${GREEN}0${NC}"
fi
echo ""

if [ $FAILED -eq 0 ]; then
    echo -e "${GREEN}✓ All critical components operational!${NC}"
    echo ""
    echo "Next steps:"
    echo "  1. View logs: docker-compose logs -f vector-ingest wazuh-manager"
    echo "  2. OpenSearch Dashboards: http://localhost:5601"
    echo "  3. Grafana: http://localhost:3000"
    echo "  4. Generate test logs: docker exec banking-log-simulator python enhanced_log_generator.py --mode continuous"
    exit 0
else
    echo -e "${RED}✗ Some components failed validation${NC}"
    echo ""
    echo "Troubleshooting:"
    echo "  1. Check service logs: docker-compose logs <service-name>"
    echo "  2. Verify networking: docker network ls"
    echo "  3. Check service status: docker-compose ps"
    echo "  4. Review configuration: See docs/END_TO_END_FLOW.md"
    exit 1
fi
