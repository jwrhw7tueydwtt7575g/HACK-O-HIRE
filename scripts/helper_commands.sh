#!/bin/bash
# Helper Commands for Enterprise Banking SOC
# Use these commands with proper escaping for zsh

echo "=========================================="
echo "Enterprise Banking SOC - Helper Commands"
echo "=========================================="
echo ""

# OpenSearch credentials (properly escaped for zsh)
OS_USER="admin"
OS_PASS="Admin123!@#"
OS_URL="http://localhost:9200"

echo "1. Check OpenSearch cluster health:"
echo "   curl -s -u '${OS_USER}:${OS_PASS}' '${OS_URL}/_cluster/health' | jq '.'"
echo ""

echo "2. Check banking logs count:"
echo "   curl -s -u '${OS_USER}:${OS_PASS}' '${OS_URL}/banking-soc-logs-*/_count' | jq '.'"
echo ""

echo "3. Check Wazuh alerts count:"
echo "   curl -s -u '${OS_USER}:${OS_PASS}' '${OS_URL}/wazuh-alerts-*/_count' | jq '.'"
echo ""

echo "4. Check incidents count:"
echo "   curl -s -u '${OS_USER}:${OS_PASS}' '${OS_URL}/banking-soc-incidents/_count' | jq '.'"
echo ""

echo "5. List all indices:"
echo "   curl -s -u '${OS_USER}:${OS_PASS}' '${OS_URL}/_cat/indices?v'"
echo ""

echo "6. Check Vector metrics:"
echo "   curl -s http://localhost:8686/health"
echo ""

echo "7. View service logs:"
echo "   docker compose logs -f vector-ingest"
echo "   docker compose logs -f wazuh-manager"
echo "   docker compose logs -f opensearch"
echo ""

echo "8. Check all service status:"
echo "   docker compose ps"
echo ""

echo "=========================================="
echo "Quick Actions:"
echo "=========================================="
echo ""

# Function to check OpenSearch
check_opensearch() {
    echo "Checking OpenSearch..."
    curl -s -u "${OS_USER}:${OS_PASS}" "${OS_URL}/_cluster/health" | jq '.'
}

# Function to check logs count
check_logs() {
    echo "Checking log counts..."
    echo -n "Banking logs: "
    curl -s -u "${OS_USER}:${OS_PASS}" "${OS_URL}/banking-soc-logs-*/_count" 2>/dev/null | jq -r '.count // "Index not found"'
    echo -n "Wazuh alerts: "
    curl -s -u "${OS_USER}:${OS_PASS}" "${OS_URL}/wazuh-alerts-*/_count" 2>/dev/null | jq -r '.count // "Index not found"'
    echo -n "Incidents: "
    curl -s -u "${OS_USER}:${OS_PASS}" "${OS_URL}/banking-soc-incidents/_count" 2>/dev/null | jq -r '.count // "Index not found"'
}

# Function to list all indices
list_indices() {
    echo "Listing all indices..."
    curl -s -u "${OS_USER}:${OS_PASS}" "${OS_URL}/_cat/indices?v&s=index"
}

# If script is sourced, make functions available
# If executed, show menu
if [ "${BASH_SOURCE[0]}" == "${0}" ]; then
    echo "Choose an action:"
    echo "1) Check OpenSearch health"
    echo "2) Check log counts"
    echo "3) List all indices"
    echo "4) Check Vector health"
    echo "5) Show all service status"
    echo ""
    read -p "Enter choice (1-5): " choice
    
    case $choice in
        1) check_opensearch ;;
        2) check_logs ;;
        3) list_indices ;;
        4) curl -s http://localhost:8686/health && echo "" ;;
        5) docker compose ps ;;
        *) echo "Invalid choice" ;;
    esac
fi
