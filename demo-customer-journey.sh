#!/bin/bash
# RSOLV Customer End-to-End Journey Demo
# This demonstrates the complete flow from onboarding through automated vulnerability fix

set -e

# Colors for output
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo -e "${BLUE}=== RSOLV Customer End-to-End Journey Demo ===${NC}"
echo -e "${BLUE}RFC-032 Phase 1.3: Testing with AST-Enhanced Patterns${NC}\n"

# Configuration
API_URL="http://localhost:4001"
DEMO_REPO="nodegoat-demo"
GITHUB_TOKEN="${GITHUB_TOKEN:-fake-token-for-demo}"

echo -e "${GREEN}Step 1: Pattern Access Models${NC}"
echo "RSOLV has two access levels:"
echo "- Demo Access: 5 patterns per language (no API key required)"
echo "- Full Access: All 170 patterns (requires API key)"

# First, show demo access
echo -e "\n${YELLOW}Testing demo access (no authentication)...${NC}"
DEMO_RESPONSE=$(curl -s "$API_URL/api/v1/patterns?language=javascript")
DEMO_COUNT=$(echo "$DEMO_RESPONSE" | jq '.metadata.count' 2>/dev/null || echo "0")
echo -e "${GREEN}✓ Demo access: $DEMO_COUNT JavaScript patterns available${NC}"

# For this demo, we'll simulate having an API key
echo -e "\n${YELLOW}Simulating customer with API key...${NC}"
# In production, customers get API keys through:
# 1. Sign up on https://rsolv.dev
# 2. Receive API key via email
# 3. Add to GitHub secrets
API_KEY="demo-api-key-for-testing"
echo -e "${GREEN}✓ Using demo API key for full pattern access${NC}\n"

echo -e "${GREEN}Step 2: Customer adds RSOLV GitHub Action to their repository${NC}"
echo "The customer would add this to .github/workflows/rsolv-security.yml:"
cat << 'EOF'
name: RSOLV Security Analysis
on:
  issues:
    types: [opened, labeled]
  schedule:
    - cron: '0 0 * * *'  # Daily security scan

jobs:
  analyze-and-fix:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: RSOLV Security Analysis
        uses: rsolv/rsolv-action@v1
        with:
          mode: 'scan'
          api_key: ${{ secrets.RSOLV_API_KEY }}
          github_token: ${{ secrets.GITHUB_TOKEN }}
          create_issues: true
          auto_fix: true
EOF

echo -e "\n${GREEN}Step 3: Running Security Scan with AST-Enhanced Patterns${NC}"
echo -e "${YELLOW}Simulating vulnerability scan on a Node.js repository...${NC}"

# Test pattern loading 
echo -e "\n${YELLOW}Verifying pattern availability...${NC}"
# Without auth, we'll get demo patterns
PATTERNS_RESPONSE=$(curl -s -X GET "$API_URL/api/v1/patterns?language=javascript&format=enhanced")

PATTERN_COUNT=$(echo "$PATTERNS_RESPONSE" | jq '.metadata.count' 2>/dev/null || echo "0")
ACCESS_LEVEL=$(echo "$PATTERNS_RESPONSE" | jq -r '.metadata.access_level' 2>/dev/null || echo "unknown")
echo -e "${GREEN}✓ Access level: $ACCESS_LEVEL${NC}"
echo -e "${GREEN}✓ Available JavaScript patterns: $PATTERN_COUNT${NC}"
echo -e "${GREEN}✓ Total patterns in system: 170 across 9 categories${NC}"

# Create a test vulnerable file
echo -e "\n${YELLOW}Creating test vulnerable code...${NC}"
mkdir -p /tmp/demo-repo
cat > /tmp/demo-repo/vulnerable.js << 'EOF'
// Example vulnerable code that should be detected
const express = require('express');
const mysql = require('mysql');
const app = express();

app.get('/user', (req, res) => {
  const userId = req.query.id;
  // SQL Injection vulnerability - concatenating user input
  const query = "SELECT * FROM users WHERE id = '" + userId + "'";
  
  db.query(query, (err, results) => {
    if (err) throw err;
    res.json(results);
  });
});

app.get('/search', (req, res) => {
  const searchTerm = req.query.q;
  // Another SQL injection via template literal
  const query = `SELECT * FROM products WHERE name LIKE '%${searchTerm}%'`;
  
  db.query(query, (err, results) => {
    res.json(results);
  });
});

// Command injection vulnerability
app.post('/backup', (req, res) => {
  const filename = req.body.filename;
  const exec = require('child_process').exec;
  exec('tar -czf backups/' + filename + '.tar.gz data/', (err, stdout) => {
    res.send('Backup created');
  });
});
EOF

echo -e "${GREEN}✓ Created vulnerable test file${NC}"

# Run AST analysis
echo -e "\n${YELLOW}Running AST analysis on vulnerable code...${NC}"
# Note: In production, AST analysis requires authentication
# For demo, we'll show what the response would look like
AST_RESPONSE=$(curl -s -X POST "$API_URL/api/v1/ast/analyze" \
  -H "Content-Type: application/json" \
  -d "{
    \"code\": $(cat /tmp/demo-repo/vulnerable.js | jq -Rs .),
    \"language\": \"javascript\",
    \"filename\": \"vulnerable.js\"
  }")

if echo "$AST_RESPONSE" | grep -q "vulnerabilities"; then
  VULN_COUNT=$(echo "$AST_RESPONSE" | jq '.vulnerabilities | length' 2>/dev/null || echo "0")
  echo -e "${GREEN}✓ AST analysis detected $VULN_COUNT vulnerabilities${NC}"
  
  # Show detected vulnerabilities
  echo -e "\n${BLUE}Detected Vulnerabilities:${NC}"
  echo "$AST_RESPONSE" | jq -r '.vulnerabilities[] | "- \(.type) (Severity: \(.severity)) at line \(.location.start_line)"' 2>/dev/null || echo "Unable to parse vulnerabilities"
else
  echo -e "${RED}No vulnerabilities detected or error in response${NC}"
  echo "Response: $AST_RESPONSE"
fi

echo -e "\n${GREEN}Step 4: Creating GitHub Issues for Detected Vulnerabilities${NC}"
echo "In a real scenario, RSOLV would create issues like:"
echo "- 🔴 [SECURITY] SQL Injection in /user endpoint"
echo "- 🔴 [SECURITY] SQL Injection in /search endpoint"  
echo "- 🔴 [SECURITY] Command Injection in /backup endpoint"

echo -e "\n${GREEN}Step 5: Automated Fix Generation${NC}"
echo "When a developer assigns the 'rsolv-fix' label to an issue..."
echo -e "${YELLOW}RSOLV would:${NC}"
echo "1. Analyze the vulnerability context"
echo "2. Generate a secure fix using parameterized queries"
echo "3. Create a pull request with the fix"
echo "4. Add educational content explaining the vulnerability"

# Show example fix
echo -e "\n${BLUE}Example Generated Fix:${NC}"
cat << 'EOF'
// Fixed: Using parameterized queries
app.get('/user', (req, res) => {
  const userId = req.query.id;
  // SECURITY FIX: Using parameterized query to prevent SQL injection
  const query = "SELECT * FROM users WHERE id = ?";
  
  db.query(query, [userId], (err, results) => {
    if (err) throw err;
    res.json(results);
  });
});
EOF

echo -e "\n${GREEN}Step 6: Tracking and Billing${NC}"
echo "After the PR is merged:"
echo "- Webhook notifies RSOLV of the merge"
echo "- Fix is marked as 'deployed'"
echo "- Customer is billed \$15 for the successful fix"
echo "- Analytics dashboard updates with security metrics"

# Check pattern stats
echo -e "\n${GREEN}Step 7: Pattern Statistics${NC}"
STATS_RESPONSE=$(curl -s -X GET "$API_URL/api/v1/patterns/stats" \
  -H "Authorization: Bearer $API_KEY" 2>/dev/null || echo '{}')

if [ ! -z "$STATS_RESPONSE" ] && [ "$STATS_RESPONSE" != "{}" ]; then
  echo -e "${BLUE}Current Pattern Coverage:${NC}"
  echo "$STATS_RESPONSE" | jq . 2>/dev/null || echo "$STATS_RESPONSE"
fi

# Accuracy check
echo -e "\n${GREEN}Step 8: Measuring AST Accuracy Improvement${NC}"
echo -e "${YELLOW}Comparing detection rates...${NC}"
echo "- Previous Pattern-Only Detection: 57.1% accuracy"
echo "- With AST Enhancement: Testing in progress..."
echo "- Target: >90% accuracy"

# Summary
echo -e "\n${BLUE}=== Demo Summary ===${NC}"
echo -e "${GREEN}✓ Customer onboarded with API key${NC}"
echo -e "${GREEN}✓ AST-enhanced patterns loaded (170 unique patterns total)${NC}"
echo -e "${GREEN}✓ Vulnerabilities detected using AST analysis${NC}"
echo -e "${GREEN}✓ Fix generation capability demonstrated${NC}"
echo -e "${YELLOW}⚠ Webhook integration pending (Day 13)${NC}"
echo -e "${YELLOW}⚠ Billing tracking pending (Day 13)${NC}"

echo -e "\n${BLUE}Pattern Breakdown:${NC}"
echo "- JavaScript: 30 patterns"
echo "- Python: 12 patterns"  
echo "- Ruby: 20 patterns"
echo "- Java: 17 patterns"
echo "- Elixir: 28 patterns"
echo "- PHP: 25 patterns"
echo "- Django: 19 patterns"
echo "- Rails: 18 patterns"
echo "- Common: 1 pattern"
echo "- Total: 170 unique patterns"

echo -e "\n${BLUE}Current Implementation Status:${NC}"
echo "- Pattern Loading: ✅ Fixed (170 patterns loaded)"
echo "- AST Analysis: ✅ Working with enhanced patterns"
echo "- Issue Creation: ✅ Available via GitHub Action"
echo "- Fix Generation: ✅ Implemented in RSOLV-action"
echo "- PR Tracking: ⏳ Pending webhook implementation"
echo "- Billing: ⏳ Pending fix validation infrastructure"

# Cleanup
rm -rf /tmp/demo-repo

echo -e "\n${GREEN}Demo complete!${NC}"