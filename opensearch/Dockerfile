# OpenSearch Analytics Dockerfile for Enterprise Banking SOC
# Extended analytics, ML integration, and multi-tier index management
FROM opensearchproject/opensearch:2.11.1

# Install additional plugins for banking analytics
RUN /usr/share/opensearch/bin/opensearch-plugin install --batch analysis-icu && \
    /usr/share/opensearch/bin/opensearch-plugin install --batch analysis-phonetic && \
    /usr/share/opensearch/bin/opensearch-plugin install --batch mapper-murmur3 && \
    /usr/share/opensearch/bin/opensearch-plugin install --batch ingest-attachment

# Install Python for ML pipeline integration
USER root
RUN yum update -y && \
    yum install -y python3 python3-pip && \
    pip3 install opensearch-py numpy scikit-learn pandas requests && \
    yum clean all

# Create banking SOC specific directories
RUN mkdir -p /usr/share/opensearch/banking-soc/{templates,policies,scripts,ml-models} && \
    chown -R opensearch:opensearch /usr/share/opensearch/banking-soc

# Copy configuration files
COPY config/opensearch.yml /usr/share/opensearch/config/opensearch.yml
COPY config/banking-index-templates.json /usr/share/opensearch/banking-soc/templates/
COPY config/ism-policies.json /usr/share/opensearch/banking-soc/policies/
COPY config/security-roles.yml /usr/share/opensearch/config/opensearch-security/roles.yml
COPY config/security-roles-mapping.yml /usr/share/opensearch/config/opensearch-security/roles_mapping.yml
COPY scripts/setup-banking-indices.py /usr/share/opensearch/banking-soc/scripts/
COPY scripts/ml-integration.py /usr/share/opensearch/banking-soc/scripts/

# Set proper permissions
RUN chown -R opensearch:opensearch /usr/share/opensearch/config && \
    chown -R opensearch:opensearch /usr/share/opensearch/banking-soc && \
    chmod +x /usr/share/opensearch/banking-soc/scripts/*.py

# Switch back to opensearch user
USER opensearch

# Expose additional ports for banking SOC
EXPOSE 9200 9300 9600

# Health check for banking SOC specific indices
HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 \
    CMD curl -f -u admin:admin -k https://localhost:9200/_cluster/health || exit 1

# Custom entrypoint for banking setup
COPY scripts/banking-entrypoint.sh /usr/share/opensearch/banking-soc/banking-entrypoint.sh
RUN chmod +x /usr/share/opensearch/banking-soc/banking-entrypoint.sh

ENTRYPOINT ["/usr/share/opensearch/banking-soc/banking-entrypoint.sh"]