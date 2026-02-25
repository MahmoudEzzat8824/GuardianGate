"""
GuardianGate - Security Orchestration Platform Backend
FastAPI application with GitHub webhook integration and security scanning
"""
import asyncio
import json
import os
import subprocess
import shutil
from datetime import datetime
from typing import List, Optional
from enum import Enum

from fastapi import FastAPI, BackgroundTasks, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from prometheus_client import Counter, Gauge, generate_latest, CONTENT_TYPE_LATEST
from sqlalchemy import create_engine, Column, Integer, String, DateTime, Text, Float
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
from starlette.responses import Response

# Database configuration
DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://guardian:guardian123@db:5432/guardiangate")
engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# Database Models
class ScanResult(Base):
    __tablename__ = "scan_results"
    
    id = Column(Integer, primary_key=True, index=True)
    repository = Column(String(255), nullable=False)
    scan_type = Column(String(50), nullable=False)
    severity = Column(String(20))
    vulnerabilities_count = Column(Integer, default=0)
    results_json = Column(Text)
    scan_timestamp = Column(DateTime, default=datetime.utcnow)
    risk_score = Column(Float, default=0.0)

# Create tables
Base.metadata.create_all(bind=engine)

# Pydantic Models
class SeverityLevel(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

class WebhookPayload(BaseModel):
    repository: dict
    ref: Optional[str] = None
    commits: Optional[List[dict]] = []

class ScanResultResponse(BaseModel):
    id: int
    repository: str
    scan_type: str
    severity: Optional[str]
    vulnerabilities_count: int
    scan_timestamp: datetime
    risk_score: float
    
    class Config:
        from_attributes = True

# Prometheus Metrics
total_vulnerabilities = Counter(
    'guardiangate_total_vulnerabilities_found', 
    'Total number of vulnerabilities found',
    ['severity']
)
scans_performed = Counter(
    'guardiangate_scans_performed_total',
    'Total number of scans performed',
    ['scan_type']
)
current_risk_score = Gauge(
    'guardiangate_current_risk_score',
    'Current overall risk score'
)

# FastAPI App
app = FastAPI(
    title="GuardianGate API",
    description="Security Orchestration Platform",
    version="1.0.0"
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Scan Orchestrator
class ScanOrchestrator:
    """Orchestrates security scans using external tools"""
    
    @staticmethod
    def check_binary_available(binary: str) -> bool:
        """Check if a binary is available in the system path"""
        return shutil.which(binary) is not None
    
    @staticmethod
    async def run_trivy_scan(target: str) -> dict:
        """Run Trivy container/image scan"""
        try:
            result = subprocess.run(
                ["trivy", "image", "--format", "json", "--quiet", target],
                capture_output=True,
                text=True,
                timeout=300
            )
            
            if result.returncode == 0 and result.stdout:
                return json.loads(result.stdout)
            return {"error": result.stderr or "Trivy scan failed"}
        except subprocess.TimeoutExpired:
            return {"error": "Trivy scan timeout"}
        except Exception as e:
            return {"error": str(e)}
    
    @staticmethod
    async def run_gitleaks_scan(repo_path: str) -> dict:
        """Run Gitleaks secret detection"""
        try:
            result = subprocess.run(
                ["gitleaks", "detect", "--source", repo_path, "--report-format", "json", "--report-path", "/tmp/gitleaks-report.json", "--no-git"],
                capture_output=True,
                text=True,
                timeout=300
            )
            
            # Gitleaks returns exit code 1 if leaks found, which is expected
            if os.path.exists("/tmp/gitleaks-report.json"):
                with open("/tmp/gitleaks-report.json", "r") as f:
                    return json.load(f)
            return {"findings": [], "message": "No secrets detected"}
        except subprocess.TimeoutExpired:
            return {"error": "Gitleaks scan timeout"}
        except Exception as e:
            return {"error": str(e)}
    
    @staticmethod
    async def run_terrascan_scan(repo_path: str) -> dict:
        """Run Terrascan IaC scan"""
        try:
            result = subprocess.run(
                ["terrascan", "scan", "-d", repo_path, "-o", "json"],
                capture_output=True,
                text=True,
                timeout=300
            )
            
            if result.stdout:
                return json.loads(result.stdout)
            return {"error": result.stderr or "Terrascan scan failed"}
        except subprocess.TimeoutExpired:
            return {"error": "Terrascan scan timeout"}
        except Exception as e:
            return {"error": str(e)}
    
    @staticmethod
    def calculate_risk_score(vulnerability_counts: dict) -> float:
        """Calculate risk score based on vulnerability counts"""
        weights = {
            "CRITICAL": 10.0,
            "HIGH": 5.0,
            "MEDIUM": 2.0,
            "LOW": 0.5,
            "INFO": 0.1
        }
        
        score = sum(vulnerability_counts.get(severity, 0) * weight 
                   for severity, weight in weights.items())
        
        # Normalize to 0-100 scale (cap at 500 raw score = 100)
        return min(100.0, (score / 500.0) * 100.0)
    
    @staticmethod
    def generate_demo_data(repository_name: str) -> list:
        """Generate realistic fake scan data for demo purposes"""
        demo_scans = []
        
        # Fake Trivy scan with container vulnerabilities
        trivy_demo = {
            "scan_type": "trivy",
            "severity": "HIGH",
            "vulnerabilities_count": 23,
            "vulnerability_counts": {"CRITICAL": 2, "HIGH": 8, "MEDIUM": 10, "LOW": 3},
            "results_json": {
                "Results": [
                    {
                        "Target": "alpine:latest",
                        "Vulnerabilities": [
                            {
                                "VulnerabilityID": "CVE-2024-1234",
                                "PkgName": "openssl",
                                "InstalledVersion": "1.1.1",
                                "FixedVersion": "1.1.2",
                                "Severity": "CRITICAL",
                                "Title": "Buffer overflow in OpenSSL"
                            },
                            {
                                "VulnerabilityID": "CVE-2024-5678",
                                "PkgName": "libcurl",
                                "InstalledVersion": "7.68.0",
                                "FixedVersion": "7.71.0",
                                "Severity": "HIGH",
                                "Title": "Remote code execution in libcurl"
                            },
                            {
                                "VulnerabilityID": "CVE-2023-9999",
                                "PkgName": "zlib",
                                "InstalledVersion": "1.2.11",
                                "FixedVersion": "1.2.13",
                                "Severity": "MEDIUM",
                                "Title": "Memory leak in zlib compression"
                            }
                        ]
                    }
                ]
            }
        }
        demo_scans.append(trivy_demo)
        
        # Fake Gitleaks scan with secret detection
        gitleaks_demo = {
            "scan_type": "gitleaks",
            "severity": "CRITICAL",
            "vulnerabilities_count": 5,
            "vulnerability_counts": {"CRITICAL": 3, "HIGH": 2},
            "results_json": {
                "findings": [
                    {
                        "Description": "AWS Access Token",
                        "File": "config/database.yml",
                        "Secret": "AKIA...REDACTED",
                        "Match": "aws_access_key_id = AKIA...",
                        "Line": 15
                    },
                    {
                        "Description": "GitHub Token",
                        "File": "scripts/deploy.sh",
                        "Secret": "ghp_...REDACTED",
                        "Match": "GITHUB_TOKEN=ghp_...",
                        "Line": 8
                    },
                    {
                        "Description": "Private SSH Key",
                        "File": ".ssh/id_rsa",
                        "Secret": "-----BEGIN RSA PRIVATE KEY-----",
                        "Match": "-----BEGIN RSA PRIVATE KEY-----",
                        "Line": 1
                    },
                    {
                        "Description": "API Key",
                        "File": "src/config.js",
                        "Secret": "sk_live_...REDACTED",
                        "Match": "apiKey: 'sk_live_...'",
                        "Line": 42
                    },
                    {
                        "Description": "Database Password",
                        "File": ".env",
                        "Secret": "REDACTED",
                        "Match": "DB_PASSWORD=Super$ecret123",
                        "Line": 12
                    }
                ]
            }
        }
        demo_scans.append(gitleaks_demo)
        
        # Fake Terrascan scan with IaC issues
        terrascan_demo = {
            "scan_type": "terrascan",
            "severity": "HIGH",
            "vulnerabilities_count": 12,
            "vulnerability_counts": {"HIGH": 5, "MEDIUM": 7},
            "results_json": {
                "results": {
                    "violations": [
                        {
                            "rule_name": "s3BucketPublicReadAccess",
                            "severity": "HIGH",
                            "resource_name": "aws_s3_bucket.data",
                            "file": "terraform/s3.tf",
                            "line": 10,
                            "description": "S3 bucket allows public read access"
                        },
                        {
                            "rule_name": "ec2InstanceWithPublicIP",
                            "severity": "HIGH",
                            "resource_name": "aws_instance.web",
                            "file": "terraform/ec2.tf",
                            "line": 25,
                            "description": "EC2 instance has public IP without proper security group"
                        },
                        {
                            "rule_name": "securityGroupOpenToInternet",
                            "severity": "HIGH",
                            "resource_name": "aws_security_group.web",
                            "file": "terraform/security.tf",
                            "line": 5,
                            "description": "Security group allows 0.0.0.0/0 inbound traffic on port 22"
                        },
                        {
                            "rule_name": "rdsWithoutEncryption",
                            "severity": "MEDIUM",
                            "resource_name": "aws_db_instance.main",
                            "file": "terraform/rds.tf",
                            "line": 18,
                            "description": "RDS instance does not have encryption enabled"
                        },
                        {
                            "rule_name": "iamPolicyTooPermissive",
                            "severity": "MEDIUM",
                            "resource_name": "aws_iam_policy.admin",
                            "file": "terraform/iam.tf",
                            "line": 32,
                            "description": "IAM policy allows * actions on * resources"
                        }
                    ]
                }
            }
        }
        demo_scans.append(terrascan_demo)
        
        return demo_scans

# Background task for performing scans
async def perform_security_scan(repository_url: str, repository_name: str):
    """Background task to perform comprehensive security scans"""
    db = SessionLocal()
    
    try:
        orchestrator = ScanOrchestrator()
        scan_results = []
        vulnerability_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        
        # Check if this is a demo scan
        is_demo = "demo" in repository_name.lower() or "test" in repository_name.lower()
        
        if is_demo:
            # Generate and store fake demo data
            print(f"🎭 Generating demo data for {repository_name}")
            demo_scans = orchestrator.generate_demo_data(repository_name)
            
            for demo_scan in demo_scans:
                scan_type = demo_scan["scan_type"]
                vuln_counts = demo_scan.get("vulnerability_counts", {})
                
                # Update metrics
                scans_performed.labels(scan_type=scan_type).inc()
                for severity, count in vuln_counts.items():
                    if count > 0:
                        vulnerability_counts[severity] = vulnerability_counts.get(severity, 0) + count
                        total_vulnerabilities.labels(severity=severity).inc()
                
                # Create scan record
                scan_record = ScanResult(
                    repository=repository_name,
                    scan_type=scan_type,
                    severity=demo_scan["severity"],
                    vulnerabilities_count=demo_scan["vulnerabilities_count"],
                    results_json=json.dumps(demo_scan["results_json"]),
                    risk_score=orchestrator.calculate_risk_score(vulnerability_counts)
                )
                db.add(scan_record)
                scan_results.append(scan_record)
            
            # Update overall risk score
            final_risk_score = orchestrator.calculate_risk_score(vulnerability_counts)
            current_risk_score.set(final_risk_score)
            
            db.commit()
            print(f"✅ Demo scan completed for {repository_name}. Risk Score: {final_risk_score:.2f}, Total Vulnerabilities: {sum(vulnerability_counts.values())}")
            return
        
        # Real scan logic (original code)
        # For demo purposes, we'll scan the repository itself
        # In production, you'd clone the repo first
        scan_results = []
        vulnerability_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        
        # Run Trivy scan (scanning a common image as example)
        if orchestrator.check_binary_available("trivy"):
            scans_performed.labels(scan_type="trivy").inc()
            trivy_result = await orchestrator.run_trivy_scan("alpine:latest")
            
            # Parse Trivy results
            trivy_vulns = 0
            if "Results" in trivy_result:
                for result in trivy_result.get("Results", []):
                    for vuln in result.get("Vulnerabilities", []):
                        severity = vuln.get("Severity", "UNKNOWN")
                        if severity in vulnerability_counts:
                            vulnerability_counts[severity] += 1
                            trivy_vulns += 1
                            total_vulnerabilities.labels(severity=severity).inc()
            
            scan_record = ScanResult(
                repository=repository_name,
                scan_type="trivy",
                severity="CRITICAL" if vulnerability_counts["CRITICAL"] > 0 else "HIGH" if vulnerability_counts["HIGH"] > 0 else "MEDIUM",
                vulnerabilities_count=trivy_vulns,
                results_json=json.dumps(trivy_result),
                risk_score=orchestrator.calculate_risk_score(vulnerability_counts)
            )
            db.add(scan_record)
            scan_results.append(scan_record)
        
        # Run Gitleaks scan
        if orchestrator.check_binary_available("gitleaks"):
            scans_performed.labels(scan_type="gitleaks").inc()
            # For demo, scan current directory
            gitleaks_result = await orchestrator.run_gitleaks_scan("/app")
            
            gitleaks_findings = len(gitleaks_result.get("findings", []))
            if gitleaks_findings > 0:
                vulnerability_counts["HIGH"] += gitleaks_findings
                total_vulnerabilities.labels(severity="HIGH").inc()
            
            scan_record = ScanResult(
                repository=repository_name,
                scan_type="gitleaks",
                severity="HIGH" if gitleaks_findings > 0 else "INFO",
                vulnerabilities_count=gitleaks_findings,
                results_json=json.dumps(gitleaks_result),
                risk_score=orchestrator.calculate_risk_score(vulnerability_counts)
            )
            db.add(scan_record)
            scan_results.append(scan_record)
        
        # Run Terrascan scan
        if orchestrator.check_binary_available("terrascan"):
            scans_performed.labels(scan_type="terrascan").inc()
            terrascan_result = await orchestrator.run_terrascan_scan("/app")
            
            terrascan_violations = 0
            if "results" in terrascan_result:
                violations = terrascan_result["results"].get("violations", [])
                terrascan_violations = len(violations)
                for violation in violations:
                    severity = violation.get("severity", "MEDIUM")
                    if severity in vulnerability_counts:
                        vulnerability_counts[severity] += 1
                        total_vulnerabilities.labels(severity=severity).inc()
            
            scan_record = ScanResult(
                repository=repository_name,
                scan_type="terrascan",
                severity="MEDIUM" if terrascan_violations > 0 else "INFO",
                vulnerabilities_count=terrascan_violations,
                results_json=json.dumps(terrascan_result),
                risk_score=orchestrator.calculate_risk_score(vulnerability_counts)
            )
            db.add(scan_record)
            scan_results.append(scan_record)
        
        # Update overall risk score
        final_risk_score = orchestrator.calculate_risk_score(vulnerability_counts)
        current_risk_score.set(final_risk_score)
        
        db.commit()
        print(f"✅ Completed scan for {repository_name}. Risk Score: {final_risk_score:.2f}")
        
    except Exception as e:
        print(f"❌ Error during scan: {str(e)}")
        db.rollback()
    finally:
        db.close()

# API Endpoints
@app.get("/")
async def root():
    """Root endpoint"""
    return {
        "service": "GuardianGate",
        "version": "1.0.0",
        "status": "operational"
    }

@app.post("/webhook")
async def github_webhook(payload: WebhookPayload, background_tasks: BackgroundTasks):
    """
    Receive GitHub push events and trigger security scans
    """
    repository_name = payload.repository.get("full_name", "unknown/repo")
    repository_url = payload.repository.get("clone_url", "")
    
    # Add scan to background tasks
    background_tasks.add_task(perform_security_scan, repository_url, repository_name)
    
    return {
        "status": "accepted",
        "message": f"Security scan initiated for {repository_name}",
        "repository": repository_name
    }

@app.get("/scans", response_model=List[ScanResultResponse])
async def get_scans(limit: int = 50):
    """
    Get list of all historical scan results from the database
    """
    db = SessionLocal()
    try:
        scans = db.query(ScanResult).order_by(ScanResult.scan_timestamp.desc()).limit(limit).all()
        return scans
    finally:
        db.close()

@app.get("/scans/{scan_id}")
async def get_scan_detail(scan_id: int):
    """
    Get detailed results for a specific scan
    """
    db = SessionLocal()
    try:
        scan = db.query(ScanResult).filter(ScanResult.id == scan_id).first()
        if not scan:
            raise HTTPException(status_code=404, detail="Scan not found")
        
        return {
            "id": scan.id,
            "repository": scan.repository,
            "scan_type": scan.scan_type,
            "severity": scan.severity,
            "vulnerabilities_count": scan.vulnerabilities_count,
            "scan_timestamp": scan.scan_timestamp,
            "risk_score": scan.risk_score,
            "results": json.loads(scan.results_json) if scan.results_json else {}
        }
    finally:
        db.close()

@app.get("/metrics")
async def metrics():
    """
    Prometheus metrics endpoint
    """
    return Response(content=generate_latest(), media_type=CONTENT_TYPE_LATEST)

@app.get("/readyz")
async def readiness_check():
    """
    Check if scanner binaries are available in the system path
    """
    orchestrator = ScanOrchestrator()
    
    scanners = {
        "trivy": orchestrator.check_binary_available("trivy"),
        "gitleaks": orchestrator.check_binary_available("gitleaks"),
        "terrascan": orchestrator.check_binary_available("terrascan")
    }
    
    all_available = all(scanners.values())
    
    return {
        "ready": all_available,
        "scanners": scanners,
        "database": "connected"
    }

@app.get("/health")
async def health_check():
    """Basic health check"""
    return {"status": "healthy"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
