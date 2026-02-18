#!/bin/bash
#
# Enterprise Banking SOC - Quick Deployment Script
# Automated setup and initialization
#

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Banner
echo -e "${BLUE}"
cat << "EOF"
╔═══════════════════════════════════════════════════════════╗
║   Enterprise Banking Autonomous SOC Platform              ║
║   Production-Grade Security Operations Center             ║
╚═══════════════════════════════════════════════════════════╝
EOF
echo -e "${NC}"

# Check prerequisites
check_prerequisites() {
    echo -e "${BLUE}[1/7] Checking prerequisites...${NC}"
    
    # Check Docker
    if ! command -v docker &> /dev/null; then
        echo -e "${RED}❌ Docker is not installed${NC}"
        echo "Please install Docker: https://docs.docker.com/get-docker/"
        exit 1
    fi
    echo -e "${GREEN}✅ Docker installed: $(docker --version)${NC}"
    
    # Check Docker Compose
    if ! command -v docker-compose &> /dev/null && ! docker compose version &> /dev/null; then
        echo -e "${RED}❌ Docker Compose is not installed${NC}"
        echo "Please install Docker Compose: https://docs.docker.com/compose/install/"
        exit 1
    fi
    echo -e "${GREEN}✅ Docker Compose installed${NC}"
    
    # Check system resources
    total_mem=$(free -g | awk '/^Mem:/{print $2}')
    if [ "$total_mem" -lt 16 ]; then
        echo -e "${YELLOW}⚠️  Warning: System has ${total_mem}GB RAM. Recommended: 32GB+${NC}"
        read -p "Continue anyway? (y/N): " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            exit 1
        fi
    else
        echo -e "${GREEN}✅ System resources: ${total_mem}GB RAM${NC}"
    fi
    
    # Check vm.max_map_count for OpenSearch
    current_max_map=$(sysctl vm.max_map_count | awk '{print $3}')
    if [ "$current_max_map" -lt 262144 ]; then
        echo -e "${YELLOW}⚠️  Setting vm.max_map_count for OpenSearch...${NC}"
        sudo sysctl -w vm.max_map_count=262144
        echo "vm.max_map_count=262144" | sudo tee -a /etc/sysctl.conf
    fi
    echo -e "${GREEN}✅ vm.max_map_count configured${NC}"
}

# Configure environment
configure_environment() {
    echo -e "${BLUE}[2/7] Configuring environment...${NC}"
    
    if [ ! -f .env ]; then
        echo -e "${YELLOW}Creating .env file from template...${NC}"
        cp .env.template .env
        
        # Generate random passwords
        OPENSEARCH_PASS=$(openssl rand -base64 32 | tr -d "=+/" | cut -c1-25)
        WAZUH_API_PASS=$(openssl rand -base64 32 | tr -d "=+/" | cut -c1-25)
        NEO4J_PASS=$(openssl rand -base64 32 | tr -d "=+/" | cut -c1-25)
        POSTGRES_PASS=$(openssl rand -base64 32 | tr -d "=+/" | cut -c1-25)
        REDIS_PASS=$(openssl rand -base64 32 | tr -d "=+/" | cut -c1-25)
        GRAFANA_PASS=$(openssl rand -base64 32 | tr -d "=+/" | cut -c1-25)
        
        # Update .env with generated passwords
        sed -i "s/OPENSEARCH_ADMIN_PASSWORD=.*/OPENSEARCH_ADMIN_PASSWORD=$OPENSEARCH_PASS/" .env
        sed -i "s/WAZUH_API_PASSWORD=.*/WAZUH_API_PASSWORD=$WAZUH_API_PASS/" .env
        sed -i "s/NEO4J_PASSWORD=.*/NEO4J_PASSWORD=$NEO4J_PASS/" .env
        sed -i "s/POSTGRES_PASSWORD=.*/POSTGRES_PASSWORD=$POSTGRES_PASS/" .env
        sed -i "s/REDIS_PASSWORD=.*/REDIS_PASSWORD=$REDIS_PASS/" .env
        sed -i "s/GRAFANA_PASSWORD=.*/GRAFANA_PASSWORD=$GRAFANA_PASS/" .env
        
        echo -e "${GREEN}✅ Environment file created with secure passwords${NC}"
        echo -e "${YELLOW}⚠️  IMPORTANT: Please edit .env to add your API keys (OpenAI, NVD, etc.)${NC}"
        
        read -p "Press Enter to continue after updating API keys, or Ctrl+C to exit..."
    else
        echo -e "${GREEN}✅ Environment file exists${NC}"
    fi
}

# Create directories
create_directories() {
    echo -e "${BLUE}[3/7] Creating required directories...${NC}"
    
    mkdir -p logs/{vector,wazuh,opensearch,ai-intelligence,enrichment,soar}
    mkdir -p data/{opensearch,neo4j,postgres,redis}
    mkdir -p certs
    mkdir -p backups
    
    echo -e "${GREEN}✅ Directories created${NC}"
}

# Generate certificates (optional)
generate_certificates() {
    echo -e "${BLUE}[4/7] Checking TLS certificates...${NC}"
    
    if [ ! -f certs/cert.pem ]; then
        echo -e "${YELLOW}Generating self-signed certificates for development...${NC}"
        openssl req -x509 -nodes -days 365 -newkey rsa:4096 \
            -keyout certs/key.pem \
            -out certs/cert.pem \
            -subj "/C=US/ST=State/L=City/O=BankingSOC/CN=localhost" \
            2>/dev/null
        echo -e "${GREEN}✅ Self-signed certificates generated${NC}"
        echo -e "${YELLOW}⚠️  For production, replace with CA-signed certificates${NC}"
    else
        echo -e "${GREEN}✅ Certificates exist${NC}"
    fi
}

# Pull Docker images
pull_images() {
    echo -e "${BLUE}[5/7] Pulling Docker images (this may take several minutes)...${NC}"
    
    docker-compose pull
    
    echo -e "${GREEN}✅ Docker images pulled${NC}"
}

# Start services
start_services() {
    echo -e "${BLUE}[6/7] Starting services...${NC}"
    
    echo "Starting core infrastructure..."
    docker-compose up -d opensearch redis neo4j postgres
    
    echo "Waiting for databases to be ready..."
    sleep 30
    
    echo "Starting Wazuh..."
    docker-compose up -d wazuh-manager
    sleep 20
    
    echo "Starting Vector ingestion..."
    docker-compose up -d vector-ingest
    sleep 10
    
    echo "Starting AI/ML services..."
    docker-compose up -d ai-intelligence enrichment soar-automation
    sleep 15
    
    echo "Starting monitoring..."
    docker-compose up -d prometheus grafana opensearch-dashboards
    
    echo "Starting log simulator..."
    docker-compose up -d log-simulator
    
    echo -e "${GREEN}✅ All services started${NC}"
}

# Initialize services
initialize_services() {
    echo -e "${BLUE}[7/7] Initializing services...${NC}"
    
    echo "Waiting for services to be healthy..."
    sleep 60
    
    # Check service health
    echo "Checking service health..."
    docker-compose ps
    
    # Initialize OpenSearch indices
    echo "Initializing OpenSearch indices..."
    docker-compose exec -T opensearch curl -X PUT 'localhost:9200/_index_template/banking-soc-logs' \
        -H 'Content-Type: application/json' \
        -d '{
          "index_patterns": ["banking-soc-logs-*"],
          "template": {
            "settings": {
              "number_of_shards": 3,
              "number_of_replicas": 1,
              "index.lifecycle.name": "banking-soc-ilm-policy"
            }
          }
        }' 2>/dev/null || true
    
    echo -e "${GREEN}✅ Services initialized${NC}"
}

# Print access information
print_access_info() {
    echo -e "${GREEN}"
    cat << "EOF"

╔═══════════════════════════════════════════════════════════╗
║   🎉 Deployment Complete!                                 ║
╚═══════════════════════════════════════════════════════════╝

📊 Access Points:
┌───────────────────────────────────────────────────────────┐
│ Service                   │ URL                           │
├───────────────────────────────────────────────────────────┤
│ OpenSearch Dashboards     │ http://localhost:5601         │
│ Grafana                   │ http://localhost:3000         │
│ Wazuh API                 │ https://localhost:55000       │
│ Neo4j Browser             │ http://localhost:7474         │
│ Prometheus                │ http://localhost:9090         │
│ AI Intelligence API       │ http://localhost:8001         │
│ Enrichment API            │ http://localhost:8002         │
│ SOAR API                  │ http://localhost:8003         │
└───────────────────────────────────────────────────────────┘

🔑 Default Credentials:
┌───────────────────────────────────────────────────────────┐
│ OpenSearch: admin / (check .env file)                    │
│ Grafana: admin / (check .env file)                       │
│ Neo4j: neo4j / (check .env file)                         │
│ Wazuh API: wazuh-api / (check .env file)                 │
└───────────────────────────────────────────────────────────┘

📝 Next Steps:
1. Access OpenSearch Dashboards to view logs
2. Configure Grafana dashboards for monitoring
3. Review incident processing in SOAR API
4. Customize detection rules in Wazuh
5. Review README.md for detailed documentation

🔍 Useful Commands:
• View logs: docker-compose logs -f [service]
• Check status: docker-compose ps
• Stop all: docker-compose down
• Restart service: docker-compose restart [service]

⚠️  SECURITY REMINDER:
• Change default passwords in .env
• Configure TLS certificates for production
• Review firewall rules and network access
• Enable audit logging and monitoring
• Implement backup procedures

EOF
    echo -e "${NC}"
    
    echo "Deployment completed at: $(date)"
}

# Main execution
main() {
    check_prerequisites
    configure_environment
    create_directories
    generate_certificates
    pull_images
    start_services
    initialize_services
    print_access_info
}

# Run main function
main
