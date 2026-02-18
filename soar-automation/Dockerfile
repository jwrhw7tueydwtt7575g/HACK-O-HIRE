# SOAR Automation Dockerfile
# Enterprise Banking SOC - Security Orchestration, Automation and Response
FROM python:3.11-slim

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    g++ \
    curl \
    git \
    openssh-client \
    sshpass \
    iputils-ping \
    net-tools \
    postgresql-client \
    && rm -rf /var/lib/apt/lists/*

# Create application user
RUN useradd -r -s /bin/false soar && \
    mkdir -p /app /app/data /app/logs /app/playbooks /app/audit && \
    chown -R soar:soar /app

WORKDIR /app

# Copy requirements and install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY src/ ./src/
COPY config/ ./config/
COPY playbooks/ ./playbooks/
# COPY scripts/ ./scripts/

# Set permissions
RUN chown -R soar:soar /app
# RUN chmod +x /app/scripts/*.py /app/scripts/*.sh

# Switch to non-root user
USER soar

# Expose ports
EXPOSE 8200 8201 9092

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 \
    CMD curl -f http://localhost:8003/health || exit 1

# Environment variables
ENV PYTHONPATH=/app/src
ENV SOAR_CONFIG=/app/config/soar.yaml
ENV PLAYBOOKS_DIR=/app/playbooks
ENV LOG_LEVEL=INFO

# Run SOAR service
CMD ["python", "src/main.py"]