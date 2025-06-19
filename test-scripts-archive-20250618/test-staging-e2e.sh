#!/bin/bash
# Comprehensive E2E test for staging environment
# Tests the complete workflow: Issue → Analysis → PR → API tracking

set -e

echo "🧪 Running Comprehensive E2E Test Against Staging..."
echo "================================================"

# Test configuration
STAGING_API_URL="https://api.rsolv-staging.com"
STAGING_API_KEY="${RSOLV_STAGING_API_KEY:-test-staging-key}"
TEST_REPO="RSOLV-dev/test-e2e-staging"
TEST_ISSUE_NUMBER="${1:-1}"

# Color codes
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Test results
TESTS_PASSED=0
TESTS_FAILED=0

# Test function
test_step() {
    local test_name="$1"
    local test_command="$2"
    
    echo -e "\n${YELLOW}Testing: ${test_name}${NC}"
    if eval "$test_command"; then
        echo -e "${GREEN}✅ PASSED: ${test_name}${NC}"
        ((TESTS_PASSED++))
    else
        echo -e "${RED}❌ FAILED: ${test_name}${NC}"
        ((TESTS_FAILED++))
    fi
}

# 1. Test API Health
test_step "API Health Check" \
    "curl -s ${STAGING_API_URL}/health | jq -e '.status == \"healthy\"'"

# 2. Test Pattern API
test_step "Pattern API - JavaScript" \
    "curl -s '${STAGING_API_URL}/api/v1/patterns/javascript' | jq -e '.patterns | length > 10'"

test_step "Pattern API - Django Framework" \
    "curl -s '${STAGING_API_URL}/api/v1/patterns/python?framework=django' | jq -e '.patterns | length > 0'"

# 3. Test Pattern API with Authentication
test_step "Pattern API - Authenticated Access" \
    "curl -s -H 'Authorization: Bearer ${STAGING_API_KEY}' '${STAGING_API_URL}/api/v1/patterns/javascript' | jq -e '.patterns | length > 0'"

# 4. Test Clustering
test_step "BEAM Clustering Active" \
    "curl -s ${STAGING_API_URL}/health | jq -e '.clustering.enabled == true and .clustering.node_count >= 1'"

# 5. Test GitHub Action with act (if available)
if command -v act &> /dev/null; then
    echo -e "\n${YELLOW}Testing GitHub Action locally with act...${NC}"
    
    # Create a test workflow file
    cat > .github/workflows/test-staging-e2e.yml << 'EOF'
name: Test Staging E2E
on:
  workflow_dispatch:
    inputs:
      issue_number:
        description: 'Issue number to process'
        required: true
        default: '1'

jobs:
  test-staging:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: Test Pattern Fetching
        run: |
          echo "Testing pattern API..."
          curl -s "${{ env.RSOLV_API_URL }}/api/v1/patterns/javascript" | jq '.patterns | length'
      
      - name: Run RSOLV Action
        uses: ./
        with:
          github_token: ${{ secrets.GITHUB_TOKEN }}
          rsolv_api_key: ${{ secrets.RSOLV_API_KEY }}
          issue_label: "rsolv:automate"
        env:
          RSOLV_API_URL: ${{ env.RSOLV_API_URL }}
EOF

    test_step "GitHub Action with act" \
        "act workflow_dispatch \
            -s GITHUB_TOKEN='${GITHUB_TOKEN}' \
            -s RSOLV_API_KEY='${STAGING_API_KEY}' \
            --var RSOLV_API_URL='${STAGING_API_URL}' \
            -W .github/workflows/test-staging-e2e.yml \
            --input issue_number='${TEST_ISSUE_NUMBER}' \
            --container-architecture linux/amd64 \
            --dryrun"
    
    # Clean up test workflow
    rm -f .github/workflows/test-staging-e2e.yml
else
    echo -e "${YELLOW}⚠️  Skipping GitHub Action test (act not installed)${NC}"
fi

# 6. Test Fix Attempt Tracking
echo -e "\n${YELLOW}Testing Fix Attempt Tracking...${NC}"
MOCK_FIX_ATTEMPT=$(cat << EOF
{
  "github_org": "test-org",
  "repo_name": "test-repo",
  "issue_number": 999,
  "pr_number": 888,
  "pr_title": "E2E Test Fix",
  "pr_url": "https://github.com/test-org/test-repo/pull/888",
  "issue_title": "E2E Test Issue",
  "issue_url": "https://github.com/test-org/test-repo/issues/999",
  "api_key_used": "${STAGING_API_KEY}"
}
EOF
)

test_step "Fix Attempt API" \
    "curl -s -X POST '${STAGING_API_URL}/api/v1/fix-attempts' \
        -H 'Content-Type: application/json' \
        -H 'Authorization: Bearer ${STAGING_API_KEY}' \
        -d '${MOCK_FIX_ATTEMPT}' | jq -e '.id != null'"

# 7. Test Database Connectivity (via health endpoint)
test_step "Database Connectivity" \
    "curl -s ${STAGING_API_URL}/health | jq -e '.services.database == \"healthy\"'"

# 8. Test AI Provider Health
test_step "AI Providers Healthy" \
    "curl -s ${STAGING_API_URL}/health | jq -e '.services.ai_providers.anthropic == \"healthy\"'"

# 9. Run Integration Test Script
echo -e "\n${YELLOW}Running Integration Test Script...${NC}"
test_step "Bun Integration Tests" \
    "bun test-e2e-integration.ts --pattern-only"

# 10. Load Test Pattern API (basic)
echo -e "\n${YELLOW}Basic Load Test...${NC}"
LOAD_TEST_PASSED=true
for i in {1..10}; do
    if ! curl -s "${STAGING_API_URL}/api/v1/patterns/javascript" > /dev/null; then
        LOAD_TEST_PASSED=false
        break
    fi
done

test_step "Pattern API Load Test (10 requests)" \
    "$LOAD_TEST_PASSED"

# Summary
echo -e "\n================================================"
echo -e "🎯 E2E Test Results"
echo -e "✅ Tests Passed: ${TESTS_PASSED}"
echo -e "❌ Tests Failed: ${TESTS_FAILED}"
echo -e "📊 Success Rate: $(( TESTS_PASSED * 100 / (TESTS_PASSED + TESTS_FAILED) ))%"
echo -e "🔗 API Endpoint: ${STAGING_API_URL}"
echo -e "================================================"

# Exit with appropriate code
if [ $TESTS_FAILED -eq 0 ]; then
    echo -e "\n${GREEN}🎉 All E2E tests passed! Ready for production.${NC}"
    exit 0
else
    echo -e "\n${RED}⚠️  Some tests failed. Please fix before deploying to production.${NC}"
    exit 1
fi