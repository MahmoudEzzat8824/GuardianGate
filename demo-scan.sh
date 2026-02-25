#!/bin/bash

# GuardianGate Demo Script
# This script triggers a test scan to populate the dashboard

set -e

API_URL="http://localhost:8001"

echo "🛡️  GuardianGate - Demo Scan Trigger"
echo "====================================="
echo ""

# Check if backend is running
if ! curl -s -f "${API_URL}/health" > /dev/null; then
    echo "❌ Backend is not running. Start it with: docker-compose up -d"
    exit 1
fi

echo "✅ Backend is running"
echo ""

# Trigger a demo scan
echo "🔍 Triggering demo security scan..."
curl -X POST "${API_URL}/webhook" \
  -H "Content-Type: application/json" \
  -d '{
    "repository": {
      "full_name": "demo/guardiangate",
      "clone_url": "https://github.com/demo/guardiangate.git"
    },
    "ref": "refs/heads/main",
    "commits": [
      {
        "message": "Demo commit for testing"
      }
    ]
  }'

echo ""
echo ""
echo ""
echo "✅ Demo scan triggered successfully!"
echo ""
echo "📊 Generated Fake Security Alerts:"
echo "   • Trivy:     23 vulnerabilities (2 CRITICAL, 8 HIGH, 10 MEDIUM, 3 LOW)"
echo "   • Gitleaks:   5 secrets found (3 CRITICAL, 2 HIGH)"
echo "   • Terrascan: 12 IaC issues (5 HIGH, 7 MEDIUM)"
echo "   • Total:     40 vulnerabilities"
echo "   • Risk Score: ~32/100 (MODERATE)"
echo ""
echo "🌐 View results at: http://localhost:3002"
echo "⏳ Wait 2-3 seconds, then refresh the dashboard to see the alerts"
echo ""
echo "🔄 To trigger more demo scans, run this script again or push to a connected GitHub repository"
