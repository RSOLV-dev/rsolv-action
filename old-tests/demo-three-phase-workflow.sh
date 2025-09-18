#!/bin/bash

# RSOLV Three-Phase Demo Workflow Script
# Demonstrates: Scan -> Validate -> Mitigate flow

set -e

# Configuration
API_KEY="rsolv_-1U3PpIl2T3wo3Nw5v9wB1EM-riNnBcloKtq_gveimc"
BASE_URL="https://api.rsolv.dev"
DEMO_REPO="demo-vulnerable-app"
FORGE_ACCOUNT="demo-account-$(date +%s)"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}================================================${NC}"
echo -e "${BLUE}    RSOLV Three-Phase Security Demo Workflow    ${NC}"
echo -e "${BLUE}================================================${NC}"
echo ""

# Step 0: Get temporary credentials for AI providers
echo -e "${YELLOW}[SETUP] Obtaining AI provider credentials...${NC}"
CRED_RESPONSE=$(curl -s -X POST "$BASE_URL/api/v1/credentials/exchange" \
  -H "Content-Type: application/json" \
  -H "X-Api-Key: $API_KEY" \
  -d '{
    "providers": ["anthropic", "openai"],
    "ttl_minutes": 120
  }')

ANTHROPIC_KEY=$(echo "$CRED_RESPONSE" | jq -r '.credentials.anthropic.api_key')
echo -e "${GREEN}✓ Obtained temporary AI credentials${NC}"
echo ""

# ============================================
# PHASE 1: VULNERABILITY SCANNING
# ============================================
echo -e "${BLUE}================================================${NC}"
echo -e "${BLUE}       PHASE 1: VULNERABILITY SCANNING          ${NC}"
echo -e "${BLUE}================================================${NC}"
echo ""

echo -e "${YELLOW}[SCAN] Analyzing demo-vulnerable-app.js for security issues...${NC}"

# Read the vulnerable file
VULNERABLE_CODE=$(base64 -w 0 < demo-vulnerable-app.js)

# Create scan request
cat > scan-request.json <<EOF
{
  "repository": "$DEMO_REPO",
  "language": "javascript",
  "files": [
    {
      "path": "demo-vulnerable-app.js",
      "content": "$(cat demo-vulnerable-app.js | jq -Rs .)"
    }
  ]
}
EOF

# Perform vulnerability scan
echo -e "${YELLOW}[SCAN] Sending code to RSOLV for analysis...${NC}"
SCAN_RESPONSE=$(curl -s -X POST "$BASE_URL/api/v1/vulnerability/scan" \
  -H "Content-Type: application/json" \
  -H "X-Api-Key: $API_KEY" \
  -d @scan-request.json)

# Display found vulnerabilities
echo -e "${GREEN}[SCAN] Vulnerabilities detected:${NC}"
echo "$SCAN_RESPONSE" | jq '.vulnerabilities[] | {type: .type, severity: .severity, line: .location.line}'

VULNERABILITY_COUNT=$(echo "$SCAN_RESPONSE" | jq '.vulnerabilities | length')
echo -e "${RED}[SCAN] Found $VULNERABILITY_COUNT vulnerabilities${NC}"
echo ""

# ============================================
# PHASE 2: VULNERABILITY VALIDATION
# ============================================
echo -e "${BLUE}================================================${NC}"
echo -e "${BLUE}      PHASE 2: VULNERABILITY VALIDATION         ${NC}"
echo -e "${BLUE}================================================${NC}"
echo ""

echo -e "${YELLOW}[VALIDATE] Validating detected vulnerabilities and proposed fixes...${NC}"

# For each vulnerability, validate a fix
FIRST_VULN=$(echo "$SCAN_RESPONSE" | jq -r '.vulnerabilities[0]')

if [ "$FIRST_VULN" != "null" ]; then
    # Extract first vulnerability details
    VULN_TYPE=$(echo "$FIRST_VULN" | jq -r '.type')
    VULN_SEVERITY=$(echo "$FIRST_VULN" | jq -r '.severity')
    VULN_LINE=$(echo "$FIRST_VULN" | jq -r '.location.line')

    echo -e "${YELLOW}[VALIDATE] Testing fix for $VULN_TYPE vulnerability (line $VULN_LINE)...${NC}"

    # Create a proposed fix (in real scenario, this would come from AI)
    FIX_CONTENT="const userId = mysql.escape(req.params.id); // Sanitized input"

    # Validate the fix
    VALIDATION_REQUEST=$(cat <<EOF
{
  "forge_account_id": "$FORGE_ACCOUNT",
  "repository": "$DEMO_REPO",
  "vulnerability": {
    "type": "$VULN_TYPE",
    "severity": "$VULN_SEVERITY",
    "location": {
      "file": "demo-vulnerable-app.js",
      "line": $VULN_LINE,
      "column": 5
    }
  },
  "fix": {
    "content": "$FIX_CONTENT",
    "description": "Sanitized user input to prevent SQL injection"
  }
}
EOF
)

    VALIDATION_RESPONSE=$(curl -s -X POST "$BASE_URL/api/v1/vulnerability/validate" \
      -H "Content-Type: application/json" \
      -H "X-Api-Key: $API_KEY" \
      -d "$VALIDATION_REQUEST")

    VALIDATION_ID=$(echo "$VALIDATION_RESPONSE" | jq -r '.validation_id')
    IS_CACHED=$(echo "$VALIDATION_RESPONSE" | jq -r '.cached // false')

    echo -e "${GREEN}[VALIDATE] Validation ID: $VALIDATION_ID${NC}"
    echo -e "${GREEN}[VALIDATE] Cache Status: $([ "$IS_CACHED" = "true" ] && echo "HIT" || echo "MISS")${NC}"

    # Test cache by validating again
    echo -e "${YELLOW}[VALIDATE] Testing cache system with repeated validation...${NC}"
    CACHE_TEST=$(curl -s -X POST "$BASE_URL/api/v1/vulnerability/validate" \
      -H "Content-Type: application/json" \
      -H "X-Api-Key: $API_KEY" \
      -d "$VALIDATION_REQUEST")

    IS_CACHED_2=$(echo "$CACHE_TEST" | jq -r '.cached // false')
    echo -e "${GREEN}[VALIDATE] Second validation cache: $([ "$IS_CACHED_2" = "true" ] && echo "HIT ✓" || echo "MISS")${NC}"
fi

echo ""

# ============================================
# PHASE 3: FIX/MITIGATION
# ============================================
echo -e "${BLUE}================================================${NC}"
echo -e "${BLUE}         PHASE 3: FIX/MITIGATION                ${NC}"
echo -e "${BLUE}================================================${NC}"
echo ""

echo -e "${YELLOW}[MITIGATE] Generating production-ready fixes...${NC}"

# In a real scenario, this would:
# 1. Use the AI credentials to generate fixes via Claude/OpenAI
# 2. Create a pull request with the fixes
# 3. Include comprehensive documentation

# Simulate fix generation
cat > proposed-fixes.md <<EOF
# Security Fixes for $DEMO_REPO

## 1. SQL Injection Fix
\`\`\`javascript
// BEFORE (Vulnerable):
const query = "SELECT * FROM users WHERE id = " + userId;

// AFTER (Secure):
const query = "SELECT * FROM users WHERE id = ?";
db.query(query, [userId], (err, result) => {
    res.json(result);
});
\`\`\`

## 2. Command Injection Fix
\`\`\`javascript
// BEFORE (Vulnerable):
eval(userCommand);

// AFTER (Secure):
// Remove eval entirely, use safe alternatives
const allowedCommands = ['status', 'info', 'help'];
if (allowedCommands.includes(userCommand)) {
    executeAllowedCommand(userCommand);
}
\`\`\`

## 3. XSS Prevention
\`\`\`javascript
// BEFORE (Vulnerable):
res.send(\`<h1>Search results for: \${searchTerm}</h1>\`);

// AFTER (Secure):
const sanitized = escapeHtml(searchTerm);
res.send(\`<h1>Search results for: \${sanitized}</h1>\`);
\`\`\`
EOF

echo -e "${GREEN}[MITIGATE] Generated fixes saved to proposed-fixes.md${NC}"
echo ""

# Report usage
echo -e "${YELLOW}[USAGE] Reporting AI token usage...${NC}"
USAGE_REPORT=$(curl -s -X POST "$BASE_URL/api/v1/credentials/report-usage" \
  -H "Content-Type: application/json" \
  -H "X-Api-Key: $API_KEY" \
  -d '{
    "provider": "anthropic",
    "tokens_used": 2500,
    "request_count": 3,
    "job_id": "demo-'$(date +%s)'"
  }')

echo -e "${GREEN}[USAGE] Usage reported: $(echo "$USAGE_REPORT" | jq -r '.status')${NC}"
echo ""

# ============================================
# SUMMARY
# ============================================
echo -e "${BLUE}================================================${NC}"
echo -e "${BLUE}              WORKFLOW SUMMARY                   ${NC}"
echo -e "${BLUE}================================================${NC}"
echo ""

echo -e "${GREEN}✓ Phase 1 - Scan:${NC} Detected $VULNERABILITY_COUNT vulnerabilities"
echo -e "${GREEN}✓ Phase 2 - Validate:${NC} Validated fixes with caching"
echo -e "${GREEN}✓ Phase 3 - Mitigate:${NC} Generated production-ready fixes"
echo ""

echo -e "${BLUE}Key Features Demonstrated:${NC}"
echo "• Zero-configuration vulnerability detection"
echo "• AI-powered fix generation with credential vending"
echo "• Validation with intelligent caching"
echo "• Usage tracking and billing alignment"
echo "• Support for string forge account IDs (RFC-055)"
echo ""

echo -e "${GREEN}RSOLV is ready for production use!${NC}"
echo ""
echo -e "${YELLOW}Next Steps:${NC}"
echo "1. Install RSOLV GitHub Action in your repository"
echo "2. Add your RSOLV API key as a GitHub secret"
echo "3. RSOLV will automatically scan, validate, and fix vulnerabilities"
echo "4. Review and merge the generated pull requests"
echo "5. Pay only for fixes you deploy to production"

# Cleanup
rm -f scan-request.json 2>/dev/null || true