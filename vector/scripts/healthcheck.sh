#!/bin/bash
# Vector ETL Health Check Script for Banking SOC
# Validates pipeline health, TLS connectivity, and throughput metrics

set -euo pipefail

VECTOR_API_URL="http://localhost:8686"
HEALTH_CHECK_TIMEOUT=10
EXIT_CODE=0

echo "=== Vector ETL Health Check ==="

# Check Vector API Health
echo "Checking Vector API health..."
if ! curl -sf --max-time $HEALTH_CHECK_TIMEOUT "$VECTOR_API_URL/health" > /dev/null; then
    echo "❌ Vector API health check failed"
    EXIT_CODE=1
else
    echo "✅ Vector API is healthy"
fi

# Check metrics endpoint
echo "Checking metrics endpoint..."
if ! curl -sf --max-time $HEALTH_CHECK_TIMEOUT "http://localhost:9598/metrics" > /dev/null; then
    echo "❌ Metrics endpoint unavailable"
    EXIT_CODE=1
else
    echo "✅ Metrics endpoint is healthy"
fi

# Validate TLS certificates
echo "Checking TLS certificate validity..."
CERT_DIR="/etc/vector/tls"
if [ -f "$CERT_DIR/vector-client.crt" ]; then
    CERT_EXPIRY=$(openssl x509 -in "$CERT_DIR/vector-client.crt" -noout -enddate | cut -d= -f2)
    CERT_EXPIRY_EPOCH=$(date -d "$CERT_EXPIRY" +%s)
    CURRENT_EPOCH=$(date +%s)
    DAYS_UNTIL_EXPIRY=$(( (CERT_EXPIRY_EPOCH - CURRENT_EPOCH) / 86400 ))
    
    if [ $DAYS_UNTIL_EXPIRY -lt 30 ]; then
        echo "⚠️  TLS certificate expires in $DAYS_UNTIL_EXPIRY days"
        EXIT_CODE=1
    else
        echo "✅ TLS certificate valid for $DAYS_UNTIL_EXPIRY days"
    fi
else
    echo "⚠️  TLS certificate not found"
fi

# Check log processing throughput
echo "Checking log processing throughput..."
METRICS_RESPONSE=$(curl -sf --max-time $HEALTH_CHECK_TIMEOUT "http://localhost:9598/metrics" | grep "vector_banking_soc_events_total" | tail -1)
if [ -n "$METRICS_RESPONSE" ]; then
    echo "✅ Log processing metrics available"
else
    echo "⚠️  No throughput metrics found"
fi

# Check connectivity to downstream systems
echo "Checking downstream connectivity..."

# Wazuh connectivity
if nc -z wazuh.manager 1514 2>/dev/null; then
    echo "✅ Wazuh Manager connectivity OK"
else
    echo "❌ Cannot connect to Wazuh Manager"
    EXIT_CODE=1
fi

# OpenSearch connectivity
if nc -z opensearch.analytics 9200 2>/dev/null; then
    echo "✅ OpenSearch connectivity OK"
else
    echo "❌ Cannot connect to OpenSearch"
    EXIT_CODE=1
fi

# Check disk space for local backup
BACKUP_DIR="/var/log/vector"
DISK_USAGE=$(df "$BACKUP_DIR" | awk 'NR==2 {print $5}' | sed 's/%//')
if [ "$DISK_USAGE" -gt 85 ]; then
    echo "❌ Disk usage for backup directory is ${DISK_USAGE}%"
    EXIT_CODE=1
else
    echo "✅ Backup disk usage is ${DISK_USAGE}%"
fi

# Final health status
if [ $EXIT_CODE -eq 0 ]; then
    echo "🟢 Vector ETL Pipeline is healthy"
else
    echo "🔴 Vector ETL Pipeline has issues"
fi

exit $EXIT_CODE