#!/bin/bash

# GuardianGate Setup Script
# This script helps you set up the GuardianGate platform

set -e

echo "🛡️  GuardianGate - Security Orchestration Platform Setup"
echo "========================================================"
echo ""

# Check if Docker is installed
if ! command -v docker &> /dev/null; then
    echo "❌ Docker is not installed. Please install Docker first."
    exit 1
fi

# Check if Docker Compose is installed
if ! command -v docker-compose &> /dev/null; then
    echo "❌ Docker Compose is not installed. Please install Docker Compose first."
    exit 1
fi

echo "✅ Docker and Docker Compose are installed"
echo ""

# Create .env files if they don't exist
if [ ! -f backend/.env ]; then
    echo "📝 Creating backend/.env file..."
    cat > backend/.env << EOF
DATABASE_URL=postgresql://guardian:guardian123@db:5432/guardiangate
EOF
fi

if [ ! -f frontend/.env ]; then
    echo "📝 Creating frontend/.env file..."
    cat > frontend/.env << EOF
VITE_API_URL=http://localhost:8000
EOF
fi

echo "✅ Environment files created"
echo ""

# Build and start containers
echo "🐳 Building and starting Docker containers..."
docker-compose up -d --build

echo ""
echo "⏳ Waiting for services to be ready..."
sleep 10

# Check if services are running
if docker-compose ps | grep -q "Up"; then
    echo "✅ Services are running!"
    echo ""
    echo "🎉 GuardianGate is ready!"
    echo ""
    echo "📊 Access points:"
    echo "   Frontend Dashboard: http://localhost:3002"
    echo "   Backend API:        http://localhost:8001"
    echo "   API Documentation:  http://localhost:8001/docs"
    echo "   Prometheus:         http://localhost:9091"
    echo ""
    echo "🔧 Useful commands:"
    echo "   View logs:          docker-compose logs -f"
    echo "   Stop services:      docker-compose down"
    echo "   Restart services:   docker-compose restart"
    echo ""
    echo "📖 Check README.md for more information on setting up GitHub webhooks"
else
    echo "❌ Some services failed to start. Check logs with: docker-compose logs"
    exit 1
fi
