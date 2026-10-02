# syntax=docker/dockerfile:1
# Production Ephemeral Execution Sandbox for Untrusted Patch Testing
FROM python:3.11-slim

# Prevent Python from writing .pyc files and buffer stdout/stderr
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    DEBIAN_FRONTEND=noninteractive

# Install essential system dependencies and git
RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    curl \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Install verification dependencies (pytest, Semgrep SAST scanner, Flask, etc.)
RUN pip install --no-cache-dir \
    pytest>=8.0.0 \
    pytest-cov>=4.1.0 \
    semgrep>=1.65.0 \
    flask>=3.0.0 \
    pydantic>=2.5.0 \
    requests>=2.31.0 \
    httpx>=0.27.0

# Create unprivileged sandbox user with restricted permissions
RUN groupadd -g 1000 sandboxgroup && \
    useradd -u 1000 -g sandboxgroup -m -s /bin/bash sandboxuser

# Create workspace directory and set ownership
WORKDIR /workspace
RUN chown -R sandboxuser:sandboxgroup /workspace

# Switch to unprivileged user
USER sandboxuser

# Default command
CMD ["pytest", "-v"]
