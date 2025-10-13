#!/bin/bash

# API Endpoint Demonstration
# RFC-060-AMENDMENT-001 Phase 1 - Backend
#
# Demonstrates the /api/v1/test-integration/analyze endpoint
# with real HTTP requests using curl

set -e

echo "================================================================================"
echo "TestIntegration API Endpoint Demonstration"
echo "RFC-060-AMENDMENT-001 Phase 1 - Backend"
echo "================================================================================"
echo ""

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# API endpoint
API_URL="${API_URL:-http://localhost:4000}"
ENDPOINT="${API_URL}/api/v1/test-integration/analyze"

echo -e "${BLUE}API Endpoint:${NC} ${ENDPOINT}"
echo ""

# Check if API key is provided
if [ -z "$RSOLV_API_KEY" ]; then
    echo -e "${YELLOW}⚠️  RSOLV_API_KEY environment variable not set${NC}"
    echo "   This demonstration shows the request format."
    echo "   To test against a running server, set RSOLV_API_KEY."
    echo ""
    DEMO_MODE=true
else
    echo -e "${GREEN}✓ RSOLV_API_KEY found${NC}"
    echo ""
    DEMO_MODE=false
fi

# Function to make API request
make_request() {
    local title="$1"
    local json_payload="$2"

    echo "--------------------------------------------------------------------------------"
    echo -e "${BLUE}${title}${NC}"
    echo "--------------------------------------------------------------------------------"
    echo ""

    echo -e "${YELLOW}Request:${NC}"
    echo "$json_payload" | jq '.'
    echo ""

    if [ "$DEMO_MODE" = true ]; then
        echo -e "${YELLOW}Curl Command (for reference):${NC}"
        echo "curl -X POST '${ENDPOINT}' \\"
        echo "  -H 'Authorization: Bearer \$RSOLV_API_KEY' \\"
        echo "  -H 'Content-Type: application/json' \\"
        echo "  -d '${json_payload}'"
        echo ""
        echo -e "${YELLOW}Response:${NC} (Skipped - no API key provided)"
    else
        echo -e "${YELLOW}Sending request...${NC}"
        response=$(curl -s -w "\n%{http_code}" -X POST "${ENDPOINT}" \
            -H "Authorization: Bearer ${RSOLV_API_KEY}" \
            -H "Content-Type: application/json" \
            -d "${json_payload}")

        http_code=$(echo "$response" | tail -n1)
        body=$(echo "$response" | sed '$d')

        echo -e "${YELLOW}Response (HTTP ${http_code}):${NC}"
        echo "$body" | jq '.'
    fi

    echo ""
}

# Scenario 1: Ruby/RSpec - Perfect match
make_request "Scenario 1: Ruby/RSpec - Perfect Match" '{
  "vulnerableFile": "lib/app/services/user_service.rb",
  "vulnerabilityType": "sql_injection",
  "candidateTestFiles": [
    "spec/services/user_service_spec.rb",
    "spec/models/user_spec.rb",
    "spec/controllers/users_controller_spec.rb"
  ],
  "framework": "rspec"
}'

# Scenario 2: JavaScript/Vitest - Multiple candidates
make_request "Scenario 2: JavaScript/Vitest - Multiple Candidates" '{
  "vulnerableFile": "src/api/v1/auth/login.js",
  "vulnerabilityType": "authentication_bypass",
  "candidateTestFiles": [
    "test/api/v1/auth/login.test.js",
    "test/api/auth.test.js",
    "test/integration/auth_flow.test.js",
    "test/unit/helpers.test.js"
  ],
  "framework": "vitest"
}'

# Scenario 3: Python/pytest - No good match
make_request "Scenario 3: Python/pytest - No Good Match" '{
  "vulnerableFile": "app/database/migrations/001_initial.py",
  "vulnerabilityType": "sql_injection",
  "candidateTestFiles": [
    "tests/test_api.py",
    "tests/test_models.py"
  ],
  "framework": "pytest"
}'

# Scenario 4: Validation error - missing field
echo "--------------------------------------------------------------------------------"
echo -e "${BLUE}Scenario 4: Validation Error - Missing Required Field${NC}"
echo "--------------------------------------------------------------------------------"
echo ""

echo -e "${YELLOW}Request (missing 'framework' field):${NC}"
json_payload='{
  "vulnerableFile": "src/app.js",
  "candidateTestFiles": ["test/app.test.js"]
}'
echo "$json_payload" | jq '.'
echo ""

if [ "$DEMO_MODE" = false ]; then
    echo -e "${YELLOW}Sending request...${NC}"
    response=$(curl -s -w "\n%{http_code}" -X POST "${ENDPOINT}" \
        -H "Authorization: Bearer ${RSOLV_API_KEY}" \
        -H "Content-Type: application/json" \
        -d "${json_payload}")

    http_code=$(echo "$response" | tail -n1)
    body=$(echo "$response" | sed '$d')

    echo -e "${RED}Response (HTTP ${http_code}):${NC}"
    echo "$body" | jq '.'
else
    echo -e "${YELLOW}Expected Response:${NC} HTTP 400"
    echo '{
  "error": {
    "code": "INVALID_REQUEST",
    "message": "missing required fields: framework"
  }
}' | jq '.'
fi

echo ""

# Scenario 5: Validation error - unsupported framework
echo "--------------------------------------------------------------------------------"
echo -e "${BLUE}Scenario 5: Validation Error - Unsupported Framework${NC}"
echo "--------------------------------------------------------------------------------"
echo ""

echo -e "${YELLOW}Request (unsupported framework 'tape'):${NC}"
json_payload='{
  "vulnerableFile": "src/app.js",
  "candidateTestFiles": ["test/app.test.js"],
  "framework": "tape"
}'
echo "$json_payload" | jq '.'
echo ""

if [ "$DEMO_MODE" = false ]; then
    echo -e "${YELLOW}Sending request...${NC}"
    response=$(curl -s -w "\n%{http_code}" -X POST "${ENDPOINT}" \
        -H "Authorization: Bearer ${RSOLV_API_KEY}" \
        -H "Content-Type: application/json" \
        -d "${json_payload}")

    http_code=$(echo "$response" | tail -n1)
    body=$(echo "$response" | sed '$d')

    echo -e "${RED}Response (HTTP ${http_code}):${NC}"
    echo "$body" | jq '.'
else
    echo -e "${YELLOW}Expected Response:${NC} HTTP 400"
    echo '{
  "error": {
    "code": "INVALID_REQUEST",
    "message": "unsupported framework: tape. Supported: rspec, vitest, jest, pytest, mocha, minitest"
  }
}' | jq '.'
fi

echo ""

# Summary
echo "================================================================================"
echo "Demonstration Complete!"
echo "================================================================================"
echo ""
echo -e "${GREEN}Key Observations:${NC}"
echo ""
echo "1. ${BLUE}Perfect Matches${NC} (score ≥ 1.0):"
echo "   - Same directory structure + same filename = high score"
echo "   - Module bonus (+0.3) and directory bonus (+0.2) push score above 1.0"
echo ""
echo "2. ${BLUE}Good Matches${NC} (0.8-1.0):"
echo "   - Similar directory structure"
echo "   - Strongly-paired prefixes (lib/test, spec/test) score 1.0"
echo "   - Different prefixes (src/test) score 0.99"
echo ""
echo "3. ${BLUE}Poor Matches${NC} (< 0.5):"
echo "   - Different directory structures"
echo "   - Different module names"
echo "   - Fallback path suggested for creating new test file"
echo ""
echo "4. ${BLUE}Validation${NC}:"
echo "   - Missing required fields → HTTP 400"
echo "   - Unsupported frameworks → HTTP 400"
echo "   - Clear error messages with supported options"
echo ""

if [ "$DEMO_MODE" = true ]; then
    echo -e "${YELLOW}To test against a running server:${NC}"
    echo "  1. Start the server: mix phx.server"
    echo "  2. Set your API key: export RSOLV_API_KEY=your_key_here"
    echo "  3. Run this script again: ./test/demonstrations/api_demo.sh"
    echo ""
fi

echo "================================================================================"
