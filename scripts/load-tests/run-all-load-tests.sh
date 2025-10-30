#!/bin/bash

# Run all k6 load tests for RFC-068
# This script executes all three load test suites and aggregates results
#
# Usage: ./scripts/load-tests/run-all-load-tests.sh [staging|production]
#
# Environment variables:
#   API_URL - Base API URL (default: https://api.rsolv-staging.com)
#   TEST_API_KEY_1-5 - Test API keys for credential vending tests
#   STRIPE_WEBHOOK_SECRET - Webhook secret for signature validation

set -e

# Configuration
ENVIRONMENT=${1:-staging}
RESULTS_DIR="load_tests/results"
TIMESTAMP=$(date +"%Y-%m-%d_%H-%M-%S")

# Set API URL based on environment
if [ "$ENVIRONMENT" = "production" ]; then
    export API_URL="https://api.rsolv.dev"
    echo "⚠️  WARNING: Running load tests against PRODUCTION"
    read -p "Are you sure? (yes/no): " confirm
    if [ "$confirm" != "yes" ]; then
        echo "Aborted."
        exit 1
    fi
else
    export API_URL="https://api.rsolv-staging.com"
    echo "✓ Running load tests against STAGING"
fi

# Create results directory
mkdir -p "$RESULTS_DIR"

echo ""
echo "======================================"
echo "RFC-068 Load Testing Suite"
echo "======================================"
echo "Environment: $ENVIRONMENT"
echo "API URL: $API_URL"
echo "Results Dir: $RESULTS_DIR"
echo "Timestamp: $TIMESTAMP"
echo ""

# Function to run a test and capture results
run_test() {
    local test_name=$1
    local test_script=$2
    local result_file="$RESULTS_DIR/${test_name}-${TIMESTAMP}.txt"

    echo "--------------------------------------"
    echo "Running: $test_name"
    echo "--------------------------------------"
    echo ""

    if k6 run "$test_script" 2>&1 | tee "$result_file"; then
        echo ""
        echo "✓ $test_name completed successfully"
        echo "  Results saved to: $result_file"
        return 0
    else
        echo ""
        echo "✗ $test_name failed"
        echo "  Check results at: $result_file"
        return 1
    fi
}

# Track overall success
overall_success=true

# Test 1: Customer Onboarding API (100 RPS, ~9 minutes total)
if ! run_test "onboarding" "scripts/load-tests/onboarding-load-test.k6.js"; then
    overall_success=false
fi

echo ""
echo "Waiting 30 seconds before next test..."
sleep 30

# Test 2: Credential Vending API (200 RPS, ~9 minutes total)
# Note: Requires TEST_API_KEY_* environment variables
if [ -z "$TEST_API_KEY_1" ]; then
    echo "⚠️  WARNING: TEST_API_KEY_1 not set. Credential vending test may fail."
    echo "   Set TEST_API_KEY_1-5 environment variables for realistic testing."
fi

if ! run_test "credential-vending" "scripts/load-tests/credential-vending-load-test.k6.js"; then
    overall_success=false
fi

echo ""
echo "Waiting 30 seconds before next test..."
sleep 30

# Test 3: Webhook Endpoint (50 RPS, ~9 minutes total)
if ! run_test "webhook" "scripts/load-tests/webhook-load-test.k6.js"; then
    overall_success=false
fi

# Summary
echo ""
echo "======================================"
echo "Load Test Suite Summary"
echo "======================================"
echo ""

# Check for JSON results and display key metrics
for test in onboarding credential-vending webhook; do
    json_file="$RESULTS_DIR/${test}-results.json"
    if [ -f "$json_file" ]; then
        echo "[$test]"
        echo "  Total Requests: $(jq -r '.metrics.http_reqs.values.count' "$json_file")"
        echo "  Avg RPS: $(jq -r '.metrics.http_reqs.values.rate' "$json_file" | xargs printf "%.2f")"
        echo "  P95 Latency: $(jq -r '.metrics.http_req_duration.values["p(95)"]' "$json_file" | xargs printf "%.2f")ms"
        echo "  Error Rate: $(jq -r '.metrics.errors.values.rate * 100' "$json_file" | xargs printf "%.2f")%"
        echo ""
    fi
done

if $overall_success; then
    echo "✓ All load tests completed successfully!"
    echo ""
    echo "Next steps:"
    echo "1. Review detailed results in $RESULTS_DIR/"
    echo "2. Check Grafana dashboards for system metrics"
    echo "3. Document baseline metrics in WEEK-3-LOAD-TEST-RESULTS.md"
    exit 0
else
    echo "✗ Some load tests failed. Review the results above."
    exit 1
fi
