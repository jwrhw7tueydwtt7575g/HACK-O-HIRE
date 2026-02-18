# AI Intelligence UEBA Dockerfile for Enterprise Banking SOC
# Advanced behavioral analytics and anomaly detection
FROM python:3.11-slim

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    g++ \
    curl \
    git \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Create application user
RUN useradd -r -s /bin/false aiintel && \
    mkdir -p /app /app/models /app/data /app/logs && \
    chown -R aiintel:aiintel /app

# Set working directory
WORKDIR /app

# Copy requirements and install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application source code
COPY src/ ./src/
COPY config/ ./config/
COPY models/ ./models/
# COPY scripts/ ./scripts/

# Set proper permissions
RUN chown -R aiintel:aiintel /app
# RUN chmod +x /app/scripts/*.py /app/scripts/*.sh

# Switch to non-root user
USER aiintel

# Expose ports
EXPOSE 8000 8001 9090

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 \
    CMD curl -f http://localhost:8001/health || exit 1

# Set environment variables
ENV PYTHONPATH=/app/src
ENV AI_INTEL_CONFIG=/app/config/ai-intelligence.yaml
ENV MODEL_STORAGE=/app/models
ENV LOG_LEVEL=INFO

# Run the AI Intelligence service
CMD ["python", "src/main.py"]