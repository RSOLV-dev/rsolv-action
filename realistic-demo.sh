#!/bin/bash

echo "🔍 RSOLV API Demo - What Actually Works"
echo "======================================="
echo

# Configuration
API_URL="http://localhost:4001"
API_KEY="rsolv_test_abc123"

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

echo -e "${YELLOW}1. Testing Pattern API${NC}"
echo "Fetching available Python patterns..."
curl -s "$API_URL/api/v1/patterns/python" \
  -H "X-API-Key: $API_KEY" | jq '{
    pattern_count: .patterns | length,
    patterns: .patterns | map(.id)
  }'

echo -e "\n${YELLOW}2. Testing AST Analysis (with encryption)${NC}"
echo "Note: AST endpoint requires encrypted content"

# Generate encryption key
ENCRYPTION_KEY=$(openssl rand -base64 32)
echo "Generated encryption key: ${ENCRYPTION_KEY:0:20}..."

# Create vulnerable Python code
PYTHON_CODE='import sqlite3
def get_user(user_id):
    query = "SELECT * FROM users WHERE id = " + user_id
    return conn.execute(query).fetchone()'

# The API expects encrypted content, which requires more setup
echo -e "${RED}✗ Direct file upload not supported - requires encryption${NC}"
echo "Would need to:"
echo "1. Generate AES key"
echo "2. Encrypt file content"
echo "3. Create proper JSON payload with iv, authTag, etc."
echo "4. Send encrypted payload"

echo -e "\n${YELLOW}3. Testing Webhook Endpoint${NC}"
echo "Sending mock GitHub webhook..."
WEBHOOK_RESPONSE=$(curl -s -X POST "$API_URL/webhook/github" \
  -H "X-GitHub-Event: issues" \
  -H "X-Hub-Signature-256: sha256=dummy" \
  -H "Content-Type: application/json" \
  -d '{
    "action": "labeled",
    "issue": {
      "number": 1,
      "title": "SQL Injection detected",
      "labels": [{"name": "rsolv:automate"}]
    }
  }')

echo "Webhook response: $WEBHOOK_RESPONSE"

echo -e "\n${YELLOW}4. Testing Health Endpoint${NC}"
curl -s "$API_URL/api/health" | jq '.'

echo -e "\n${YELLOW}5. What's Missing for Full Automation${NC}"
echo -e "${RED}❌ GitHub Action${NC} - Must be built"
echo -e "${RED}❌ Issue Creation${NC} - No GitHub API integration"
echo -e "${RED}❌ PR Creation${NC} - Not implemented"
echo -e "${RED}❌ Fix Generation${NC} - No AI integration"
echo -e "${RED}❌ Direct File Analysis${NC} - Only encrypted payloads"

echo -e "\n${YELLOW}6. Current Integration Options${NC}"
echo -e "${GREEN}✓${NC} Call AST analysis API with encrypted payloads"
echo -e "${GREEN}✓${NC} Fetch patterns for local analysis"
echo -e "${GREEN}✓${NC} Build custom CI/CD integration"
echo -e "${GREEN}✓${NC} Use webhook endpoint for event reception"

echo -e "\n${YELLOW}Summary${NC}"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "RSOLV provides a security analysis API with:"
echo "- 429 security patterns"
echo "- Multi-language AST analysis"
echo "- E2E encryption for code security"
echo "- Webhook reception capability"
echo
echo "However, the automated GitHub workflow"
echo "integration must be built by customers."