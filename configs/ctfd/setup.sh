#!/bin/bash
# Purple Engine CTFd Auto-Setup Script
# Automates CTFd deployment with admin creation and plugin installation

set -e

echo "=========================================="
echo "Purple Engine - CTFd Auto-Setup"
echo "=========================================="
echo ""

# Color codes for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# Check if .env exists, if not copy from example
if [ ! -f .env ]; then
    echo -e "${YELLOW}Creating .env from .env.example...${NC}"
    cp .env.example .env
    echo -e "${RED}WARNING: Please edit .env and change default passwords!${NC}"
fi

# Load environment variables
source .env

# Start CTFd stack
echo -e "${GREEN}Starting CTFd stack...${NC}"
docker-compose up -d

# Wait for CTFd to be healthy
echo -e "${YELLOW}Waiting for CTFd to be ready...${NC}"
for i in {1..30}; do
    if curl -sf http://localhost:8000/healthcheck > /dev/null 2>&1; then
        echo -e "${GREEN}CTFd is ready!${NC}"
        break
    fi
    echo -n "."
    sleep 2
done

# Check if setup is needed
SETUP_NEEDED=$(curl -s http://localhost:8000/setup | grep -c "CTFd Setup" || true)

if [ "$SETUP_NEEDED" -gt "0" ]; then
    echo -e "${YELLOW}Running initial CTFd setup...${NC}"
    
    # Get nonce for CSRF
    NONCE=$(curl -s http://localhost:8000/setup | grep -oP 'name="nonce" value="\K[^"]+' || echo "")
    
    # Perform setup via API
    curl -s -X POST http://localhost:8000/setup \
        -H "Content-Type: application/x-www-form-urlencoded" \
        -d "ctf_name=Purple Engine CTF" \
        -d "ctf_description=Powered by Purple Engine - Agentic AI CTF Platform" \
        -d "name=${CTFD_ADMIN_USERNAME}" \
        -d "email=${CTFD_ADMIN_EMAIL}" \
        -d "password=${CTFD_ADMIN_PASSWORD}" \
        -d "user_mode=teams" \
        -d "nonce=${NONCE}" \
        > /dev/null
    
    echo -e "${GREEN}CTFd setup completed!${NC}"
else
    echo -e "${YELLOW}CTFd already configured.${NC}"
fi

# Create challenge packs directory
mkdir -p challenge_packs

# Download sample challenge pack (optional)
if [ ! -f challenge_packs/sample_challenges.zip ]; then
    echo -e "${YELLOW}Creating sample challenge directory...${NC}"
    mkdir -p challenge_packs/samples
fi

echo ""
echo -e "${GREEN}=========================================="
echo "CTFd Deployment Complete!"
echo "==========================================${NC}"
echo ""
echo "Access CTFd at: http://localhost:8000"
echo "Admin Username: ${CTFD_ADMIN_USERNAME}"
echo "Admin Password: ${CTFD_ADMIN_PASSWORD}"
echo ""
echo -e "${YELLOW}Next Steps:${NC}"
echo "1. Change admin password in CTFd settings"
echo "2. Generate API token for Purple Engine"
echo "3. Import challenge packs"
echo "4. Run: purple-engine ctfd-solve <challenge_url>"
echo ""
echo -e "${RED}SECURITY WARNING:${NC}"
echo "- Change default passwords in .env"
echo "- Use HTTPS in production with nginx"
echo "- Set CHALLENGE_VISIBILITY=private for timed events"
echo ""
