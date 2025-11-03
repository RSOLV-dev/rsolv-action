#!/bin/bash
#
# RSOLV Load Testing Script
#
# This script runs the three load tests specified in RFC-069:
# 1. Signup test (100 concurrent users)
# 2. Webhook test (1000 webhooks/minute)
# 3. API rate limit test (verify 500/hour limit)
#
# Usage: ./load_tests/run_load_tests.sh [staging|production|local]
#
# Environment variables (optional):
#   API_BASE_URL - Override base URL (default: https://api.rsolv-staging.com for staging)
#   API_KEY - API key for rate limit testing (default: will use test key)
#   STRIPE_WEBHOOK_SECRET - Webhook secret (default: whsec_test_secret)

set -e

# Configuration
ENVIRONMENT=${1:-staging}
RESULTS_DIR="load_tests/results"
TIMESTAMP=$(date +"%Y-%m-%d_%H-%M-%S")
LOG_FILE="$RESULTS_DIR/load_test_run_${TIMESTAMP}.log"

# Color codes for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Set API URL based on environment
if [ "$ENVIRONMENT" = "local" ]; then
    export API_BASE_URL="${API_BASE_URL:-http://localhost:4000}"
    echo -e "${BLUE}Running load tests against LOCAL${NC}"
elif [ "$ENVIRONMENT" = "staging" ]; then
    export API_BASE_URL="${API_BASE_URL:-https://api.rsolv-staging.com}"
    echo -e "${GREEN}Running load tests against STAGING${NC}"
else
    echo -e "${RED}ERROR: Invalid environment '$ENVIRONMENT'${NC}"
    echo "Usage: $0 [staging|local]"
    exit 1
fi

# Set defaults for other environment variables
export STRIPE_WEBHOOK_SECRET="${STRIPE_WEBHOOK_SECRET:-whsec_test_secret}"
export API_KEY="${API_KEY:-rsolv_test_key_123}"

# Create results directory
mkdir -p "$RESULTS_DIR"

# Start logging
exec > >(tee -a "$LOG_FILE")
exec 2>&1

echo ""
echo "================================================================"
echo "RFC-069 Thursday - Load Testing & Performance Validation"
echo "================================================================"
echo "Environment:     $ENVIRONMENT"
echo "API Base URL:    $API_BASE_URL"
echo "Results Dir:     $RESULTS_DIR"
echo "Timestamp:       $TIMESTAMP"
echo "Log File:        $LOG_FILE"
echo "================================================================"
echo ""

# Check k6 installation
if ! command -v k6 &> /dev/null; then
    echo -e "${RED}ERROR: k6 is not installed${NC}"
    echo "Install with: brew install k6 (macOS) or see https://k6.io/docs/get-started/installation/"
    exit 1
fi

echo -e "${GREEN}✓${NC} k6 $(k6 version | head -n1)"
echo ""

# Function to run a test
run_test() {
    local test_name=$1
    local test_script=$2
    local description=$3

    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo -e "${BLUE}Test:${NC} $test_name"
    echo -e "${BLUE}Description:${NC} $description"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo ""

    local start_time=$(date +%s)

    if k6 run "$test_script"; then
        local end_time=$(date +%s)
        local duration=$((end_time - start_time))
        echo ""
        echo -e "${GREEN}✓${NC} $test_name completed successfully in ${duration}s"
        return 0
    else
        local end_time=$(date +%s)
        local duration=$((end_time - start_time))
        echo ""
        echo -e "${RED}✗${NC} $test_name failed after ${duration}s"
        return 1
    fi
}

# Track overall success
overall_success=true
failed_tests=()

# Test 1: Signup Load Test
echo ""
echo "════════════════════════════════════════════════════════════════"
echo " TEST 1/3: Customer Signup Load Test"
echo "════════════════════════════════════════════════════════════════"
if ! run_test \
    "signup_test" \
    "load_tests/signup_test.js" \
    "100 concurrent users signing up (ramps up over 3.5 minutes, holds for 2 minutes)"; then
    overall_success=false
    failed_tests+=("signup_test")
fi

# Cooldown period
echo ""
echo -e "${YELLOW}Waiting 30 seconds before next test...${NC}"
sleep 30

# Test 2: Webhook Load Test
echo ""
echo "════════════════════════════════════════════════════════════════"
echo " TEST 2/3: Stripe Webhook Load Test"
echo "════════════════════════════════════════════════════════════════"
if ! run_test \
    "webhook_test" \
    "load_tests/webhook_test.js" \
    "1000 webhooks/minute sustained load + burst test to 3000/minute"; then
    overall_success=false
    failed_tests+=("webhook_test")
fi

# Cooldown period
echo ""
echo -e "${YELLOW}Waiting 30 seconds before next test...${NC}"
sleep 30

# Test 3: API Rate Limit Test
echo ""
echo "════════════════════════════════════════════════════════════════"
echo " TEST 3/3: API Rate Limit Enforcement Test"
echo "════════════════════════════════════════════════════════════════"
if ! run_test \
    "api_rate_limit_test" \
    "load_tests/api_rate_limit_test.js" \
    "Verify rate limiting at 500 requests/hour per API key"; then
    overall_success=false
    failed_tests+=("api_rate_limit_test")
fi

# Summary
echo ""
echo "================================================================"
echo " LOAD TEST SUMMARY"
echo "================================================================"
echo ""

if $overall_success; then
    echo -e "${GREEN}✓ ALL TESTS PASSED${NC}"
    echo ""
    echo "Performance Targets (RFC-069):"
    echo "  • Customer onboarding: <5s (p95)      - Check signup_test results"
    echo "  • API response time: <200ms (p95)     - Check all test results"
    echo "  • Webhook processing: <1s (p95)       - Check webhook_test results"
    echo "  • Connection pool: No timeouts        - Check logs/monitoring"
    echo "  • Memory usage: Stable (no leaks)     - Check Grafana dashboards"
    echo ""
    echo "Next Steps:"
    echo "  1. Review detailed results in: $RESULTS_DIR/"
    echo "  2. Check Grafana dashboards for infrastructure metrics"
    echo "  3. Verify database connection pool usage (kubectl/Grafana)"
    echo "  4. Check for any errors in pod logs"
    echo "  5. Document findings in RFC-069 or create LOAD-TEST-RESULTS.md"
    echo ""
    echo "Monitoring Commands:"
    echo "  • kubectl get pods -n rsolv-staging"
    echo "  • kubectl top pods -n rsolv-staging"
    echo "  • kubectl logs -n rsolv-staging deployment/rsolv-platform --tail=100"
    echo ""
    exit 0
else
    echo -e "${RED}✗ SOME TESTS FAILED${NC}"
    echo ""
    echo "Failed tests:"
    for test in "${failed_tests[@]}"; do
        echo -e "  ${RED}✗${NC} $test"
    done
    echo ""
    echo "Review:"
    echo "  1. Check test output above for specific failures"
    echo "  2. Review results in: $RESULTS_DIR/"
    echo "  3. Check application logs: kubectl logs -n rsolv-staging"
    echo "  4. Verify staging environment is healthy"
    echo ""
    exit 1
fi
