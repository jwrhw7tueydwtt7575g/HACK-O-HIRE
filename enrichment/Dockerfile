# Enrichment & LLM Playbook Generation Dockerfile
# Enterprise Banking SOC - Threat Intelligence and Response Automation
FROM python:3.11-slim

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    g++ \
    curl \
    git \
    jq \
    sqlite3 \
    && rm -rf /var/lib/apt/lists/*

# Create application user
RUN useradd -r -s /bin/false enrichment && \
    mkdir -p /app /app/data /app/logs /app/cache /app/prompts && \
    chown -R enrichment:enrichment /app

WORKDIR /app

# Copy requirements and install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY src/ ./src/
COPY config/ ./config/
COPY prompts/ ./prompts/
# COPY scripts/ ./scripts/

# Set permissions
RUN chown -R enrichment:enrichment /app
# RUN chmod +x /app/scripts/*.py /app/scripts/*.sh

# Switch to non-root user
USER enrichment

# Expose ports
EXPOSE 8100 8101 9091

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 \
    CMD curl -f http://localhost:8002/health || exit 1

# Environment variables
ENV PYTHONPATH=/app/src
ENV ENRICHMENT_CONFIG=/app/config/enrichment.yaml
ENV PROMPTS_DIR=/app/prompts
ENV LOG_LEVEL=INFO

# Run enrichment service
CMD ["python", "src/main.py"]