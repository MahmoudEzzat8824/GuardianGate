🛡️ GuardianGate

A professional DevSecOps Orchestration Platform that automates security analysis for containerized environments. It integrates industry-standard security scanners into a unified SOC (Security Operations Center) dashboard.
🛠️ Tech Stack

    Backend: FastAPI (Python 3.12+), SQLAlchemy 2.0.

    Frontend: React 18 (Vite, Tailwind CSS, Lucide Icons).

    Infrastructure: PostgreSQL 16, Prometheus, Docker (Multi-stage builds).

    Security Engines: 🔍 Trivy (Containers), 🔐 Gitleaks (Secrets), ☁️ Terrascan (IaC).

🚀 Key Features

    Automated Security Gates: Webhook-driven pipeline that triggers scans on every GitHub push event.

    Asynchronous Processing: Non-blocking scan execution using FastAPI BackgroundTasks for high-availability.

    Production Observability: Exposed /metrics (OpenMetrics format) for Prometheus and /readyz for Kubernetes readiness probes.

    Risk Scoring Engine: Real-time calculation of overall security posture based on vulnerability severity.

🚦 Quick Start
Bash

# Clone and launch the full stack
git clone https://github.com/yourusername/GuardianGate.git
cd GuardianGate
docker-compose up -d --build

Component	Endpoint	Description
Dashboard	http://localhost:3002	SOC Monitoring Interface
API Docs	http://localhost:8001/docs	Interactive Swagger UI
Metrics	http://localhost:8001/metrics	Prometheus Scraping Endpoint
Health	http://localhost:8001/readyz	Scanner & DB Connectivity Status
🏗️ Technical Architecture

GuardianGate follows a microservices pattern optimized for Azure Kubernetes Service (AKS) deployment using Spot Instances to minimize cloud overhead.

    Ingestion: FastAPI receives GitHub Webhooks.

    Orchestration: Backend executes ephemeral scans via pre-installed scanner binaries.

    Persistence: Results are normalized and stored in PostgreSQL.

    Monitoring: Prometheus scrapes the app to track "Time to Remediation" and vulnerability trends.

📝 Roadmap

    [ ] IaC: Provisioning the production environment using Terraform.

    [ ] GitOps: Managing deployments with Argo CD.

    [ ] Persistence: Integrating MinIO for long-term storage of audit reports.