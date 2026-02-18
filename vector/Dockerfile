# Vector ETL Dockerfile for Enterprise Banking SOC
# High-throughput log normalization and routing
FROM timberio/vector:0.34.0-debian

# Install additional tools for banking environment
RUN apt-get update && apt-get install -y \
    curl \
    openssl \
    ca-certificates \
    jq \
    && rm -rf /var/lib/apt/lists/*

# Create vector user and directories
RUN useradd -r -s /bin/false vector && \
    mkdir -p /var/lib/vector /var/log/vector /etc/vector && \
    chown -R vector:vector /var/lib/vector /var/log/vector /etc/vector

# Copy configuration files
COPY config/vector.toml /etc/vector/vector.toml
# COPY config/banking-schemas.toml /etc/vector/banking-schemas.toml
# COPY config/tls-certs/ /etc/vector/tls/
# COPY scripts/healthcheck.sh /usr/local/bin/healthcheck.sh

# Set permissions
# RUN chmod +x /usr/local/bin/healthcheck.sh && \
RUN chown -R vector:vector /etc/vector

# Switch to non-root user
USER vector

# Expose ports for log ingestion
EXPOSE 5140/tcp 5141/tcp 5142/tcp 514/udp 1514/tcp

# Health check
# HEALTHCHECK --interval=30s --timeout=10s --start-period=30s --retries=3 \
#     CMD /usr/local/bin/healthcheck.sh

# Set working directory
WORKDIR /var/lib/vector

# Run Vector with banking SOC configuration
ENTRYPOINT ["vector", "--config", "/etc/vector/vector.toml"]