# Multi-stage production-ready Dockerfile for DataGuard
# Base Image: Official lightweight Python 3.11 slim
FROM python:3.11-slim

# Prevent Python from writing .pyc files and enable unbuffered logging
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app \
    STREAMLIT_SERVER_PORT=8501 \
    STREAMLIT_SERVER_ADDRESS=0.0.0.0 \
    STREAMLIT_SERVER_HEADLESS=true

# Set working directory inside container
WORKDIR /app

# Install system dependencies (curl for healthchecks)
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies (leveraging Docker layer caching)
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Copy application source code
COPY config/ config/
COPY src/ src/
COPY tests/ tests/
COPY .streamlit/ .streamlit/
COPY README.md .

# Create persistent data directories
RUN mkdir -p data/raw data/processed data/mock_pipeline_data

# Create non-root user for enterprise container security
RUN useradd -m -u 1001 dataguard_user && \
    chown -R dataguard_user:dataguard_user /app

USER dataguard_user

# Expose Streamlit default web port
EXPOSE 8501

# Container Healthcheck
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8501/_stcore/health || exit 1

# Launch DataGuard Streamlit Application
ENTRYPOINT ["streamlit", "run", "src/ui/app.py"]
