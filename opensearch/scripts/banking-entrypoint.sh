#!/bin/bash
# Banking SOC OpenSearch Entrypoint
# Sets up banking-specific configuration before starting OpenSearch

set -euo pipefail

echo "🏦 Starting Banking SOC OpenSearch Analytics Platform..."

# Function to wait for OpenSearch to start
wait_for_opensearch() {
    echo "Waiting for OpenSearch to start..."
    until curl -sf -k -u admin:admin https://localhost:9200/_cluster/health?wait_for_status=yellow&timeout=60s > /dev/null; do
        echo "Waiting for OpenSearch startup..."
        sleep 5
    done
    echo "✅ OpenSearch is ready"
}

# Function to setup banking indices and policies
setup_banking_configuration() {
    echo "Setting up banking SOC configuration..."
    
    # Run the banking indices setup
    /usr/share/opensearch/banking-soc/scripts/setup-banking-indices.py
    
    echo "✅ Banking SOC configuration completed"
}

# Start OpenSearch in background
echo "Starting OpenSearch process..."
/usr/share/opensearch/opensearch-docker-entrypoint.sh opensearch &
OPENSEARCH_PID=$!

# Wait for OpenSearch to be ready
wait_for_opensearch

# Setup banking configuration
setup_banking_configuration

# Keep OpenSearch running in foreground
echo "✅ Banking SOC OpenSearch Analytics Platform is ready"
wait $OPENSEARCH_PID