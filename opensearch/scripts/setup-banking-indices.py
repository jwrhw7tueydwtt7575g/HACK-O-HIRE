#!/bin/bash
# OpenSearch Banking SOC Setup Script
# Initializes indices, policies, and ML integration

set -euo pipefail

OPENSEARCH_URL="${OPENSEARCH_URL:-https://localhost:9200}"
OPENSEARCH_USER="${OPENSEARCH_USER:-admin}"
OPENSEARCH_PASS="${OPENSEARCH_PASS:-admin}"

echo "=== Banking SOC OpenSearch Setup ==="

# Wait for OpenSearch to be ready
echo "Waiting for OpenSearch to be ready..."
until curl -sf -k -u "$OPENSEARCH_USER:$OPENSEARCH_PASS" "$OPENSEARCH_URL/_cluster/health?wait_for_status=yellow&timeout=60s" > /dev/null; do
    echo "Waiting for OpenSearch cluster..."
    sleep 10
done

echo "✅ OpenSearch cluster is ready"

# Create index templates
echo "Creating banking index templates..."
curl -sf -k -u "$OPENSEARCH_USER:$OPENSEARCH_PASS" \
    -X PUT "$OPENSEARCH_URL/_index_template/banking_soc_logs" \
    -H "Content-Type: application/json" \
    -d @/usr/share/opensearch/banking-soc/templates/banking-index-templates.json

# Create ISM policies
echo "Creating index lifecycle policies..."
curl -sf -k -u "$OPENSEARCH_USER:$OPENSEARCH_PASS" \
    -X PUT "$OPENSEARCH_URL/_plugins/_ism/policies/banking_soc_lifecycle_policy" \
    -H "Content-Type: application/json" \
    -d "$(jq '.banking_soc_lifecycle_policy' /usr/share/opensearch/banking-soc/policies/ism-policies.json)"

curl -sf -k -u "$OPENSEARCH_USER:$OPENSEARCH_PASS" \
    -X PUT "$OPENSEARCH_URL/_plugins/_ism/policies/wazuh_alerts_lifecycle_policy" \
    -H "Content-Type: application/json" \
    -d "$(jq '.wazuh_alerts_lifecycle_policy' /usr/share/opensearch/banking-soc/policies/ism-policies.json)"

curl -sf -k -u "$OPENSEARCH_USER:$OPENSEARCH_PASS" \
    -X PUT "$OPENSEARCH_URL/_plugins/_ism/policies/banking_analytics_lifecycle_policy" \
    -H "Content-Type: application/json" \
    -d "$(jq '.banking_analytics_lifecycle_policy' /usr/share/opensearch/banking-soc/policies/ism-policies.json)"

# Create initial indices
echo "Creating initial banking SOC indices..."
TODAY=$(date '+%Y-%m-%d')
curl -sf -k -u "$OPENSEARCH_USER:$OPENSEARCH_PASS" \
    -X PUT "$OPENSEARCH_URL/banking-soc-logs-$TODAY-000001" \
    -H "Content-Type: application/json" \
    -d '{
        "aliases": {
            "banking-soc-logs-write": {},
            "banking-soc-logs": {}
        },
        "settings": {
            "plugins.index_state_management.rollover_alias": "banking-soc-logs-write"
        }
    }'

curl -sf -k -u "$OPENSEARCH_USER:$OPENSEARCH_PASS" \
    -X PUT "$OPENSEARCH_URL/wazuh-alerts-$TODAY-000001" \
    -H "Content-Type: application/json" \
    -d '{
        "aliases": {
            "wazuh-alerts-write": {},
            "wazuh-alerts": {}
        },
        "settings": {
            "plugins.index_state_management.rollover_alias": "wazuh-alerts-write"
        }
    }'

curl -sf -k -u "$OPENSEARCH_USER:$OPENSEARCH_PASS" \
    -X PUT "$OPENSEARCH_URL/banking-analytics-$TODAY-000001" \
    -H "Content-Type: application/json" \
    -d '{
        "aliases": {
            "banking-analytics-write": {},
            "banking-analytics": {}
        },
        "settings": {
            "plugins.index_state_management.rollover_alias": "banking-analytics-write"
        }
    }'

# Create custom analyzer for banking logs
echo "Setting up banking-specific analyzers..."
curl -sf -k -u "$OPENSEARCH_USER:$OPENSEARCH_PASS" \
    -X PUT "$OPENSEARCH_URL/_settings" \
    -H "Content-Type: application/json" \
    -d '{
        "index": {
            "analysis": {
                "analyzer": {
                    "banking_analyzer": {
                        "tokenizer": "keyword",
                        "filter": ["lowercase", "banking_filter"]
                    }
                },
                "filter": {
                    "banking_filter": {
                        "type": "pattern_replace",
                        "pattern": "([0-9]{4}-[0-9]{4}-[0-9]{4}-[0-9]{4})",
                        "replacement": "****-****-****-****"
                    }
                }
            }
        }
    }'

# Setup ML models for anomaly detection
echo "Initializing ML models..."
python3 /usr/share/opensearch/banking-soc/scripts/ml-integration.py

echo "✅ Banking SOC OpenSearch setup completed successfully"