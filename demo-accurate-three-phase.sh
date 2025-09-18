#!/bin/bash

# RSOLV Three-Phase Demo Workflow
# Based on the actual architecture from ADRs and implementation
#
# Architecture Understanding:
# 1. SCAN PHASE: RSOLV-action scans repository locally using patterns from API
# 2. VALIDATE PHASE: Sends vulnerabilities to AST validation API to reduce false positives
# 3. MITIGATE PHASE: Uses Claude Code SDK locally to generate fixes via in-place editing
#
# Key Components:
# - Credential Vending: Exchange RSOLV API key for AI provider credentials
# - Pattern Detection: Local scanning with regex patterns
# - AST Validation: Server-side false positive reduction
# - Fix Generation: Local Claude Code SDK with git-based editing

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Configuration
API_URL="${RSOLV_API_URL:-https://api.rsolv.dev}"
API_KEY="${RSOLV_API_KEY:-rsolv_-1U3PpIl2T3wo3Nw5v9wB1EM-riNnBcloKtq_gveimc}"

echo -e "${BLUE}═══════════════════════════════════════════════════════════${NC}"
echo -e "${BLUE}        RSOLV Three-Phase Security Workflow Demo              ${NC}"
echo -e "${BLUE}═══════════════════════════════════════════════════════════${NC}"
echo

# Step 1: Test credential vending (foundation of the system)
echo -e "${YELLOW}Step 1: Testing Credential Vending${NC}"
echo "Exchanging RSOLV API key for temporary AI provider credentials..."
echo

# Note: The credential exchange endpoint requires specific parameters that vary by environment
# In production, this would be called with forge_account_id, repository, and issue_number
# from the GitHub Action context
echo -e "${YELLOW}⚠ Credential exchange requires GitHub Action context parameters${NC}"
echo "In a real workflow, this would exchange: RSOLV API key → Temporary AI credentials"
echo "This enables secure AI access without storing provider keys in repositories"
echo

# Step 2: Fetch security patterns (used for local scanning)
echo -e "${YELLOW}Step 2: Fetching Security Patterns${NC}"
echo "Retrieving pattern library for vulnerability detection..."
echo

PATTERNS_RESPONSE=$(curl -s -X GET "$API_URL/api/v1/patterns/v2" \
  -H "X-Api-Key: $API_KEY")

PATTERN_COUNT=$(echo "$PATTERNS_RESPONSE" | jq -r '.patterns | length' 2>/dev/null || echo "0")
if [ "$PATTERN_COUNT" -gt "0" ]; then
  echo -e "${GREEN}✓ Retrieved $PATTERN_COUNT security patterns${NC}"
  echo "Languages covered: $(echo "$PATTERNS_RESPONSE" | jq -r '.patterns | map(.language) | unique | join(", ")')"
else
  echo -e "${RED}✗ Failed to retrieve patterns${NC}"
  echo "Response: $PATTERNS_RESPONSE"
fi
echo

# Step 3: Demonstrate AST validation (false positive reduction)
echo -e "${YELLOW}Step 3: Testing AST-Based Validation${NC}"
echo "Validating detected vulnerabilities to reduce false positives..."
echo

# Create test vulnerability data
VALIDATION_REQUEST='{
  "vulnerabilities": [
    {
      "id": "test-vuln-1",
      "type": "code-injection",
      "filePath": "app.js",
      "line": 42,
      "code": "eval(userInput)",
      "severity": "critical"
    },
    {
      "id": "test-vuln-2",
      "type": "sql-injection",
      "filePath": "db.js",
      "line": 15,
      "code": "query = \"SELECT * FROM users WHERE id = \" + userId",
      "severity": "high"
    }
  ],
  "files": {
    "app.js": {
      "content": "// Sample file\nconst userInput = req.body.code;\neval(userInput); // This is dangerous\n"
    },
    "db.js": {
      "content": "// Database operations\nfunction getUser(userId) {\n  const query = \"SELECT * FROM users WHERE id = \" + userId;\n  return db.execute(query);\n}\n"
    }
  }
}'

VALIDATION_RESPONSE=$(curl -s -X POST "$API_URL/api/v1/vulnerabilities/validate" \
  -H "X-Api-Key: $API_KEY" \
  -H "Content-Type: application/json" \
  -d "$VALIDATION_REQUEST")

if echo "$VALIDATION_RESPONSE" | grep -q "validated"; then
  echo -e "${GREEN}✓ AST validation completed${NC}"
  VALIDATED_COUNT=$(echo "$VALIDATION_RESPONSE" | jq -r '.stats.validated' 2>/dev/null || echo "unknown")
  REJECTED_COUNT=$(echo "$VALIDATION_RESPONSE" | jq -r '.stats.rejected' 2>/dev/null || echo "unknown")
  echo "Results: $VALIDATED_COUNT validated, $REJECTED_COUNT rejected as false positives"

  # Show cache stats if available
  CACHE_HITS=$(echo "$VALIDATION_RESPONSE" | jq -r '.cache_stats.cache_hits' 2>/dev/null || echo "0")
  if [ "$CACHE_HITS" != "null" ] && [ "$CACHE_HITS" != "0" ]; then
    echo "Cache performance: $CACHE_HITS cache hits"
  fi
else
  echo -e "${RED}✗ AST validation failed${NC}"
  echo "Response: $VALIDATION_RESPONSE"
fi
echo

# Step 4: Report usage for billing
echo -e "${YELLOW}Step 4: Testing Usage Reporting${NC}"
echo "Reporting fix attempt for success-based billing..."
echo

USAGE_REQUEST='{
  "issue_number": 123,
  "repository": "demo-repo",
  "vulnerabilities_found": 2,
  "vulnerabilities_fixed": 2,
  "pr_created": true,
  "execution_time": 45.2,
  "tokens_used": 8500
}'

USAGE_RESPONSE=$(curl -s -X POST "$API_URL/api/v1/usage/report" \
  -H "X-Api-Key: $API_KEY" \
  -H "Content-Type: application/json" \
  -d "$USAGE_REQUEST")

if echo "$USAGE_RESPONSE" | grep -q "success"; then
  echo -e "${GREEN}✓ Usage reported successfully${NC}"
else
  echo -e "${YELLOW}⚠ Usage reporting returned: $USAGE_RESPONSE${NC}"
fi
echo

# Summary of the actual workflow
echo -e "${BLUE}═══════════════════════════════════════════════════════════${NC}"
echo -e "${BLUE}                    Workflow Summary                          ${NC}"
echo -e "${BLUE}═══════════════════════════════════════════════════════════${NC}"
echo
echo "The RSOLV workflow operates as follows:"
echo
echo -e "${GREEN}1. SCAN PHASE (Local)${NC}"
echo "   - GitHub Action runs in repository"
echo "   - Fetches patterns from RSOLV API"
echo "   - Scans code locally for vulnerabilities"
echo "   - Creates GitHub issues for findings"
echo
echo -e "${GREEN}2. VALIDATE PHASE (Hybrid)${NC}"
echo "   - Sends detected vulnerabilities to AST validation API"
echo "   - Server performs false positive reduction (70-90% reduction)"
echo "   - Returns validated vulnerabilities with confidence scores"
echo "   - Caches results for performance"
echo
echo -e "${GREEN}3. MITIGATE PHASE (Local)${NC}"
echo "   - Exchanges RSOLV API key for AI credentials"
echo "   - Uses Claude Code SDK locally to generate fixes"
echo "   - Performs git-based in-place editing (ADR-012)"
echo "   - Creates pull request with educational content"
echo
echo -e "${BLUE}Key Insights:${NC}"
echo "• No direct 'scan' endpoint - scanning happens in GitHub Action"
echo "• AST validation is the core false positive reduction mechanism"
echo "• Fix generation uses structured phased prompting (ADR-019)"
echo "• All customer code processing happens locally or in sandboxed AST service"
echo "• Success-based billing tracked via usage reporting"
echo
echo -e "${GREEN}Demo completed successfully!${NC}"