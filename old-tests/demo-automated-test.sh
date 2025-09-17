#!/bin/bash

# RSOLV Demo Automated Test Script
# Non-interactive version for programmatic testing

set -e

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
REPO="RSOLV-dev/nodegoat-vulnerability-demo"
ADMIN_URL="${ADMIN_URL:-https://rsolv-staging.com/admin}"
API_URL="${API_URL:-https://api.rsolv-staging.com}"

echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}   RSOLV Demo Automated Test Suite     ${NC}"
echo -e "${BLUE}========================================${NC}"
echo

# Test results tracking
TESTS_PASSED=0
TESTS_FAILED=0

# Function to test and report
test_feature() {
    local test_name=$1
    local command=$2

    echo -n "Testing: $test_name... "
    if eval "$command" &>/dev/null; then
        echo -e "${GREEN}✓${NC}"
        ((TESTS_PASSED++))
        return 0
    else
        echo -e "${RED}✗${NC}"
        ((TESTS_FAILED++))
        return 1
    fi
}

# Function to test with output
test_with_output() {
    local test_name=$1
    local command=$2

    echo -e "\n${YELLOW}Testing: $test_name${NC}"
    if eval "$command"; then
        ((TESTS_PASSED++))
        return 0
    else
        ((TESTS_FAILED++))
        return 1
    fi
}

echo -e "${YELLOW}=== ENVIRONMENT CHECKS ===${NC}"

# Check GitHub CLI
test_feature "GitHub CLI authentication" "gh auth status"

# Check RSOLV API Key
if [ -n "$RSOLV_API_KEY" ]; then
    echo -e "Testing: RSOLV API Key... ${GREEN}✓${NC}"
    ((TESTS_PASSED++))
else
    echo -e "Testing: RSOLV API Key... ${RED}✗${NC}"
    ((TESTS_FAILED++))
fi

# Check repository access
test_feature "Repository access" "gh repo view $REPO"

echo -e "\n${YELLOW}=== PHASE 1: SCAN VERIFICATION ===${NC}"

# Check for detected issues
echo "Checking detected vulnerabilities..."
DETECTED_ISSUES=$(gh issue list --repo $REPO --state open --label "rsolv:detected" --json number,title 2>/dev/null | jq length)
if [ "$DETECTED_ISSUES" -gt 0 ]; then
    echo -e "Found ${GREEN}$DETECTED_ISSUES${NC} detected issues"
    ((TESTS_PASSED++))

    # Show sample issues
    echo -e "\nSample detected issues:"
    gh issue list --repo $REPO --state open --label "rsolv:detected" --limit 3 --json number,title,labels | \
        jq -r '.[] | "  Issue #\(.number): \(.title)"'
else
    echo -e "${RED}No detected issues found${NC}"
    ((TESTS_FAILED++))
fi

echo -e "\n${YELLOW}=== PHASE 2: VALIDATION CAPABILITY ===${NC}"

# Check if validation label exists
if gh label list --repo $REPO --json name | jq -r '.[].name' | grep -q "rsolv:validate"; then
    echo -e "Validation label available: ${GREEN}✓${NC}"
    ((TESTS_PASSED++))
else
    echo -e "Validation label available: ${RED}✗${NC}"
    ((TESTS_FAILED++))
fi

# Check for previously validated issues
VALIDATED_COUNT=$(gh issue list --repo $REPO --state all --search "Validation Results" --json number | jq length)
echo "Previously validated issues: $VALIDATED_COUNT"

echo -e "\n${YELLOW}=== PHASE 3: MITIGATION HISTORY ===${NC}"

# Check for automation label
if gh label list --repo $REPO --json name | jq -r '.[].name' | grep -q "rsolv:automate"; then
    echo -e "Automation label available: ${GREEN}✓${NC}"
    ((TESTS_PASSED++))
else
    echo -e "Automation label available: ${RED}✗${NC}"
    ((TESTS_FAILED++))
fi

# Check for generated PRs
echo "Checking for RSOLV-generated PRs..."
RSOLV_PRS=$(gh pr list --repo $REPO --state all --search "RSOLV" --json number,title,state 2>/dev/null | jq length)
if [ "$RSOLV_PRS" -gt 0 ]; then
    echo -e "Found ${GREEN}$RSOLV_PRS${NC} RSOLV-generated PRs"
    ((TESTS_PASSED++))

    # Show recent PRs
    echo -e "\nRecent RSOLV PRs:"
    gh pr list --repo $REPO --state all --search "RSOLV" --limit 3 --json number,title,state | \
        jq -r '.[] | "  PR #\(.number): \(.title) [\(.state)]"'
else
    echo -e "${RED}No RSOLV PRs found${NC}"
    ((TESTS_FAILED++))
fi

# Check example artifacts
echo -e "\n${YELLOW}=== EXAMPLE ARTIFACTS ===${NC}"

# Check Issue #42
if gh issue view 42 --repo $REPO &>/dev/null; then
    echo -e "Example Issue #42: ${GREEN}✓${NC}"
    ((TESTS_PASSED++))
    gh issue view 42 --repo $REPO --json title,state | jq -r '"  Title: \(.title)\n  State: \(.state)"'
else
    echo -e "Example Issue #42: ${RED}✗${NC}"
    ((TESTS_FAILED++))
fi

# Check PR #43
if gh pr view 43 --repo $REPO &>/dev/null; then
    echo -e "Example PR #43: ${GREEN}✓${NC}"
    ((TESTS_PASSED++))
    gh pr view 43 --repo $REPO --json title,state | jq -r '"  Title: \(.title)\n  State: \(.state)"'
else
    echo -e "Example PR #43: ${RED}✗${NC}"
    ((TESTS_FAILED++))
fi

echo -e "\n${YELLOW}=== GITHUB ACTIONS STATUS ===${NC}"

# Check recent workflow runs
echo "Checking recent workflow runs..."
RECENT_RUNS=$(gh run list --repo $REPO --limit 5 --json conclusion,name,createdAt 2>/dev/null | jq length)
if [ "$RECENT_RUNS" -gt 0 ]; then
    echo -e "Found ${GREEN}$RECENT_RUNS${NC} recent workflow runs"
    ((TESTS_PASSED++))

    # Show run status
    gh run list --repo $REPO --limit 3 --json conclusion,name,createdAt | \
        jq -r '.[] | "  \(.name): \(.conclusion // "in progress")"'
else
    echo -e "${RED}No recent workflow runs found${NC}"
    ((TESTS_FAILED++))
fi

echo -e "\n${YELLOW}=== API CONNECTIVITY TEST ===${NC}"

# Test API health (if accessible)
echo -n "Testing API connectivity... "
if curl -s -f "$API_URL/health" &>/dev/null || curl -s -f "$API_URL/api/v1/health" &>/dev/null; then
    echo -e "${GREEN}✓${NC}"
    ((TESTS_PASSED++))
else
    echo -e "${YELLOW}⚠ API not directly accessible (expected in production)${NC}"
fi

echo -e "\n${BLUE}========================================${NC}"
echo -e "${BLUE}           TEST SUMMARY                 ${NC}"
echo -e "${BLUE}========================================${NC}"
echo

echo -e "Tests Passed: ${GREEN}$TESTS_PASSED${NC}"
echo -e "Tests Failed: ${RED}$TESTS_FAILED${NC}"

if [ $TESTS_FAILED -eq 0 ]; then
    echo -e "\n${GREEN}✓ All tests passed! Demo environment is ready.${NC}"
    EXIT_CODE=0
else
    echo -e "\n${YELLOW}⚠ Some tests failed. Review the output above.${NC}"
    EXIT_CODE=1
fi

echo -e "\n${YELLOW}=== DEMO READINESS CHECKLIST ===${NC}"
echo

# Create readiness checklist
READY=true

echo -n "✓ GitHub CLI authenticated... "
if gh auth status &>/dev/null; then
    echo -e "${GREEN}Ready${NC}"
else
    echo -e "${RED}Not ready${NC}"
    READY=false
fi

echo -n "✓ Repository accessible... "
if gh repo view $REPO &>/dev/null; then
    echo -e "${GREEN}Ready${NC}"
else
    echo -e "${RED}Not ready${NC}"
    READY=false
fi

echo -n "✓ Detected issues exist... "
if [ "$DETECTED_ISSUES" -gt 0 ]; then
    echo -e "${GREEN}Ready ($DETECTED_ISSUES issues)${NC}"
else
    echo -e "${YELLOW}Warning: No issues to demo${NC}"
fi

echo -n "✓ Example artifacts exist... "
if gh issue view 42 --repo $REPO &>/dev/null && gh pr view 43 --repo $REPO &>/dev/null; then
    echo -e "${GREEN}Ready${NC}"
else
    echo -e "${YELLOW}Partial (can use as fallback)${NC}"
fi

echo -n "✓ Admin dashboard... "
echo -e "${YELLOW}Manual check required${NC}"

echo -e "\n${BLUE}=== NEXT STEPS ===${NC}"
echo
echo "1. For PROVISION phase:"
echo "   - Open $ADMIN_URL/login"
echo "   - Create demo customer account"
echo "   - Generate API key"
echo
echo "2. For SCAN phase:"
echo "   - Use existing $DETECTED_ISSUES detected issues"
echo "   - Or trigger new scan with code push"
echo
echo "3. For VALIDATE phase:"
echo "   - Add 'rsolv:validate' label to any issue"
echo
echo "4. For MITIGATE phase:"
echo "   - Add 'rsolv:automate' label to trigger fix"
echo "   - Or use existing PR #43 as example"
echo
echo "5. For MONITOR phase:"
echo "   - Return to $ADMIN_URL/customers"
echo "   - Show usage metrics and API management"

exit $EXIT_CODE