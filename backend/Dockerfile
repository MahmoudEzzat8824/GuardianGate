# Multi-stage Dockerfile for GuardianGate Backend
# Stage 1: Install security scanner binaries
FROM alpine:latest AS scanner-builder

# Install trivy
RUN apk add --no-cache wget rpm && \
    wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key | \
    apk add --allow-untrusted && \
    wget https://github.com/aquasecurity/trivy/releases/download/v0.48.3/trivy_0.48.3_Linux-64bit.tar.gz && \
    tar -xzf trivy_0.48.3_Linux-64bit.tar.gz && \
    mv trivy /usr/local/bin/trivy && \
    chmod +x /usr/local/bin/trivy

# Install gitleaks
RUN wget https://github.com/gitleaks/gitleaks/releases/download/v8.18.2/gitleaks_8.18.2_linux_x64.tar.gz && \
    tar -xzf gitleaks_8.18.2_linux_x64.tar.gz && \
    mv gitleaks /usr/local/bin/gitleaks && \
    chmod +x /usr/local/bin/gitleaks

# Install terrascan
RUN wget https://github.com/tenable/terrascan/releases/download/v1.18.11/terrascan_1.18.11_Linux_x86_64.tar.gz && \
    tar -xzf terrascan_1.18.11_Linux_x86_64.tar.gz && \
    mv terrascan /usr/local/bin/terrascan && \
    chmod +x /usr/local/bin/terrascan

# Stage 2: Python application
FROM python:3.12-slim

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    postgresql-client \
    git \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy scanner binaries from builder stage
COPY --from=scanner-builder /usr/local/bin/trivy /usr/local/bin/trivy
COPY --from=scanner-builder /usr/local/bin/gitleaks /usr/local/bin/gitleaks
COPY --from=scanner-builder /usr/local/bin/terrascan /usr/local/bin/terrascan

# Set working directory
WORKDIR /app

# Copy requirements and install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Create non-root user
RUN useradd -m -u 1000 guardian && \
    chown -R guardian:guardian /app
USER guardian

# Expose port
EXPOSE 8000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

# Run the application
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
