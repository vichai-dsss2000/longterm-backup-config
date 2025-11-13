# =============================================================================
# Multi-stage Dockerfile for Network Device Backup Management System - Backend
# =============================================================================
# Stage 1: Build stage with full Python environment
# Stage 2: Runtime stage with minimal dependencies
# Security: Non-root user, minimal attack surface, no unnecessary packages
# =============================================================================

# -----------------------------------------------------------------------------
# Stage 1: Builder - Install dependencies and prepare application
# -----------------------------------------------------------------------------
FROM python:3.11-slim as builder

# Set working directory
WORKDIR /build

# Install system dependencies required for Python packages
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    g++ \
    libffi-dev \
    libssl-dev \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first for better layer caching
COPY requirements.txt .

# Create virtual environment and install dependencies
RUN python -m venv /opt/venv && \
    /opt/venv/bin/pip install --no-cache-dir --upgrade pip setuptools wheel && \
    /opt/venv/bin/pip install --no-cache-dir -r requirements.txt

# -----------------------------------------------------------------------------
# Stage 2: Runtime - Minimal production image
# -----------------------------------------------------------------------------
FROM python:3.11-slim

# Metadata labels
LABEL maintainer="vichai.saisood@gmail.com"
LABEL description="Network Device Backup Management System - Backend API"
LABEL version="1.0.0"

# Install only runtime dependencies (no build tools)
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpq5 \
    openssh-client \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user for security
RUN groupadd -r appuser && \
    useradd -r -g appuser -u 1000 -m -s /bin/bash appuser

# Set working directory
WORKDIR /app

# Copy virtual environment from builder
COPY --from=builder /opt/venv /opt/venv

# Copy application code
COPY --chown=appuser:appuser . .

# Create necessary directories with proper permissions
RUN mkdir -p /app/logs /app/backups /app/temp && \
    chown -R appuser:appuser /app

# Activate virtual environment
ENV PATH="/opt/venv/bin:$PATH"
ENV PYTHONPATH=/app
ENV PYTHONUNBUFFERED=1

# Security: Run as non-root user
USER appuser

# Expose port
EXPOSE 8000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=40s --retries=3 \
    CMD curl -f http://localhost:8000/api/health || exit 1

# Default command
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "4"]
