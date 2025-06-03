#!/bin/bash
# End-to-end production API verification script

set -e

API_URL="https://api.rsolv.dev"
TIMESTAMP=$(date +%s)
TEST_RESULTS_FILE="production_test_results_${TIMESTAMP}.json"

echo "🧪 Starting RSOLV API Production Verification Tests"
echo "================================================"
echo "API URL: $API_URL"
echo "Timestamp: $(date)"
echo ""

# Color codes for output
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Test result tracking
TESTS_PASSED=0
TESTS_FAILED=0

# Function to test endpoint
test_endpoint() {
    local test_name=$1
    local method=$2
    local endpoint=$3
    local expected_status=$4
    local data=$5
    local headers=$6
    
    echo -n "Testing: $test_name... "
    
    if [ -z "$headers" ]; then
        headers="-H 'Content-Type: application/json'"
    fi
    
    if [ "$method" == "GET" ]; then
        response=$(curl -s -w "\n%{http_code}" "$API_URL$endpoint" $headers)
    else
        response=$(curl -s -w "\n%{http_code}" -X "$method" "$API_URL$endpoint" \
            $headers \
            -d "$data" 2>/dev/null || echo "CURL_ERROR")
    fi
    
    if [ "$response" == "CURL_ERROR" ]; then
        echo -e "${RED}✗ Failed (curl error)${NC}"
        ((TESTS_FAILED++))
        return 1
    fi
    
    http_code=$(echo "$response" | tail -n1)
    body=$(echo "$response" | sed '$d')
    
    if [ "$http_code" == "$expected_status" ]; then
        echo -e "${GREEN}✓ Passed${NC} (HTTP $http_code)"
        ((TESTS_PASSED++))
        
        # Save successful response
        echo "{\"test\": \"$test_name\", \"status\": \"passed\", \"http_code\": $http_code, \"response\": $body}" >> "$TEST_RESULTS_FILE"
        return 0
    else
        echo -e "${RED}✗ Failed${NC} (Expected: $expected_status, Got: $http_code)"
        echo "Response: $body"
        ((TESTS_FAILED++))
        
        # Save failed response
        echo "{\"test\": \"$test_name\", \"status\": \"failed\", \"expected\": $expected_status, \"actual\": $http_code, \"response\": $body}" >> "$TEST_RESULTS_FILE"
        return 1
    fi
}

# Test 1: Health Check
echo "1️⃣  Health Check Tests"
echo "-------------------"
test_endpoint "Health endpoint accessibility" "GET" "/health" "200"

# Verify health response structure
if [ $? -eq 0 ]; then
    health_response=$(curl -s "$API_URL/health")
    
    # Check for required fields
    echo -n "   Checking response structure... "
    if echo "$health_response" | jq -e '.status, .service, .version, .services' > /dev/null 2>&1; then
        echo -e "${GREEN}✓ Valid${NC}"
        ((TESTS_PASSED++))
    else
        echo -e "${RED}✗ Invalid structure${NC}"
        ((TESTS_FAILED++))
    fi
    
    # Check service health
    echo -n "   Checking database health... "
    db_status=$(echo "$health_response" | jq -r '.services.database // "unknown"')
    if [ "$db_status" == "healthy" ]; then
        echo -e "${GREEN}✓ Healthy${NC}"
        ((TESTS_PASSED++))
    else
        echo -e "${RED}✗ Unhealthy ($db_status)${NC}"
        ((TESTS_FAILED++))
    fi
fi

echo ""

# Test 2: API Authentication
echo "2️⃣  Authentication Tests"
echo "----------------------"
test_endpoint "Reject unauthenticated request" "POST" "/api/v1/credentials/exchange" "401" '{"providers":["anthropic"]}'
test_endpoint "Reject invalid API key" "POST" "/api/v1/credentials/exchange" "401" '{"providers":["anthropic"]}' "-H 'X-API-Key: invalid_key_12345' -H 'Content-Type: application/json'"

echo ""

# Test 3: Input Validation
echo "3️⃣  Validation Tests"
echo "------------------"
test_endpoint "Reject empty body" "POST" "/api/v1/credentials/exchange" "400" '{}' "-H 'X-API-Key: test_key' -H 'Content-Type: application/json'"
test_endpoint "Reject invalid provider" "POST" "/api/v1/credentials/exchange" "400" '{"providers":["invalid_provider"]}' "-H 'X-API-Key: test_key' -H 'Content-Type: application/json'"

echo ""

# Test 4: Database Connectivity (via health endpoint)
echo "4️⃣  Database Verification"
echo "-----------------------"
echo -n "   Checking database connection... "
db_healthy=$(curl -s "$API_URL/health" | jq -r '.services.database')
if [ "$db_healthy" == "healthy" ]; then
    echo -e "${GREEN}✓ Connected${NC}"
    ((TESTS_PASSED++))
else
    echo -e "${RED}✗ Not connected${NC}"
    ((TESTS_FAILED++))
fi

echo ""

# Test 5: Response Time Performance
echo "5️⃣  Performance Tests"
echo "-------------------"
echo -n "   Health endpoint response time... "
response_time=$(curl -o /dev/null -s -w '%{time_total}\n' "$API_URL/health")
response_time_ms=$(echo "$response_time * 1000" | bc)

if (( $(echo "$response_time < 1.0" | bc -l) )); then
    echo -e "${GREEN}✓ Fast${NC} (${response_time_ms}ms)"
    ((TESTS_PASSED++))
else
    echo -e "${YELLOW}⚠ Slow${NC} (${response_time_ms}ms)"
    ((TESTS_FAILED++))
fi

echo ""

# Test 6: CORS Headers
echo "6️⃣  CORS Configuration"
echo "--------------------"
echo -n "   Checking CORS headers... "
cors_headers=$(curl -s -I "$API_URL/health" | grep -i "access-control")
if [ -n "$cors_headers" ]; then
    echo -e "${GREEN}✓ Present${NC}"
    ((TESTS_PASSED++))
else
    echo -e "${YELLOW}⚠ Not configured${NC}"
    ((TESTS_PASSED++)) # Not a failure, just a note
fi

echo ""

# Summary
echo "========================================"
echo "📊 Test Summary"
echo "========================================"
echo -e "Passed: ${GREEN}$TESTS_PASSED${NC}"
echo -e "Failed: ${RED}$TESTS_FAILED${NC}"
echo "Total:  $((TESTS_PASSED + TESTS_FAILED))"
echo ""

if [ $TESTS_FAILED -eq 0 ]; then
    echo -e "${GREEN}✅ All tests passed! The production API is working as expected.${NC}"
    exit 0
else
    echo -e "${RED}❌ Some tests failed. Please review the results above.${NC}"
    echo "Detailed results saved to: $TEST_RESULTS_FILE"
    exit 1
fi