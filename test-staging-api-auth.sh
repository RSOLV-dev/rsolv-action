#!/bin/bash
# Comprehensive test of API authentication behavior on staging
# Run before deploying to production to ensure no breaking changes

set -e

STAGING_API="https://api.rsolv-staging.com"
TEST_API_KEY="rsolv_test_full_access_no_quota_2025"
INVALID_KEY="invalid_key_that_does_not_exist_12345"

echo "=========================================="
echo "API Authentication Behavior Test - Staging"
echo "=========================================="
echo ""

# Test 1: No API key - should return 200 with demo patterns
echo "Test 1: No API key (expecting 200 with demo access)"
RESPONSE=$(curl -s -w "\nHTTP_CODE:%{http_code}" "$STAGING_API/api/v1/patterns?language=javascript")
HTTP_CODE=$(echo "$RESPONSE" | grep "HTTP_CODE:" | cut -d: -f2)
BODY=$(echo "$RESPONSE" | sed '/HTTP_CODE:/d')
ACCESS_LEVEL=$(echo "$BODY" | jq -r '.metadata.access_level')
PATTERN_COUNT=$(echo "$BODY" | jq '.patterns | length')

if [ "$HTTP_CODE" = "200" ] && [ "$ACCESS_LEVEL" = "demo" ] && [ "$PATTERN_COUNT" -le 5 ]; then
    echo "✅ PASS: No API key returns 200 with demo access ($PATTERN_COUNT patterns)"
else
    echo "❌ FAIL: Expected 200 with demo access, got HTTP $HTTP_CODE with $ACCESS_LEVEL access and $PATTERN_COUNT patterns"
    exit 1
fi
echo ""

# Test 2: Invalid API key - should return 401
echo "Test 2: Invalid API key (expecting 401)"
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" -H "Authorization: Bearer $INVALID_KEY" "$STAGING_API/api/v1/patterns?language=javascript")
if [ "$HTTP_CODE" = "401" ]; then
    echo "✅ PASS: Invalid API key returns 401 Unauthorized"
else
    echo "❌ FAIL: Expected 401, got HTTP $HTTP_CODE"
    exit 1
fi
echo ""

# Test 3: Valid API key - should return 200 with full access
echo "Test 3: Valid API key (expecting 200 with full access)"
RESPONSE=$(curl -s -w "\nHTTP_CODE:%{http_code}" -H "Authorization: Bearer $TEST_API_KEY" "$STAGING_API/api/v1/patterns?language=javascript")
HTTP_CODE=$(echo "$RESPONSE" | grep "HTTP_CODE:" | cut -d: -f2)
BODY=$(echo "$RESPONSE" | sed '/HTTP_CODE:/d')
ACCESS_LEVEL=$(echo "$BODY" | jq -r '.metadata.access_level')
PATTERN_COUNT=$(echo "$BODY" | jq '.patterns | length')

if [ "$HTTP_CODE" = "200" ] && [ "$ACCESS_LEVEL" = "full" ] && [ "$PATTERN_COUNT" -gt 20 ]; then
    echo "✅ PASS: Valid API key returns 200 with full access ($PATTERN_COUNT patterns)"
else
    echo "❌ FAIL: Expected 200 with full access, got HTTP $HTTP_CODE with $ACCESS_LEVEL access and $PATTERN_COUNT patterns"
    exit 1
fi
echo ""

# Test 4: Malformed Bearer token - should return 200 with demo (no auth provided)
echo "Test 4: Malformed Bearer token (expecting 200 with demo)"
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" -H "Authorization: NotBearer $TEST_API_KEY" "$STAGING_API/api/v1/patterns?language=javascript")
if [ "$HTTP_CODE" = "200" ]; then
    echo "✅ PASS: Malformed auth header returns 200 (treated as no auth)"
else
    echo "❌ FAIL: Expected 200, got HTTP $HTTP_CODE"
    exit 1
fi
echo ""

# Test 5: Test with enhanced format parameter
echo "Test 5: Valid API key with enhanced format (expecting 200)"
RESPONSE=$(curl -s -w "\nHTTP_CODE:%{http_code}" -H "Authorization: Bearer $TEST_API_KEY" "$STAGING_API/api/v1/patterns?language=javascript&format=enhanced")
HTTP_CODE=$(echo "$RESPONSE" | grep "HTTP_CODE:" | cut -d: -f2)
BODY=$(echo "$RESPONSE" | sed '/HTTP_CODE:/d')
ENHANCED=$(echo "$BODY" | jq -r '.metadata.enhanced')

if [ "$HTTP_CODE" = "200" ] && [ "$ENHANCED" = "true" ]; then
    echo "✅ PASS: Enhanced format works with valid API key"
else
    echo "❌ FAIL: Expected 200 with enhanced=true, got HTTP $HTTP_CODE with enhanced=$ENHANCED"
    exit 1
fi
echo ""

# Test 6: Test other endpoints still work (health check)
echo "Test 6: Health endpoint (expecting 200)"
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" "$STAGING_API/health")
if [ "$HTTP_CODE" = "200" ]; then
    echo "✅ PASS: Health endpoint returns 200"
else
    echo "❌ FAIL: Expected 200, got HTTP $HTTP_CODE"
    exit 1
fi
echo ""

# Test 7: Test backward compatibility with different languages
echo "Test 7: Testing multiple languages with valid key"
LANGUAGES=("python" "ruby" "java" "php" "elixir")
ALL_PASSED=true

for LANG in "${LANGUAGES[@]}"; do
    HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" -H "Authorization: Bearer $TEST_API_KEY" "$STAGING_API/api/v1/patterns?language=$LANG")
    if [ "$HTTP_CODE" = "200" ]; then
        echo "  ✅ $LANG: 200 OK"
    else
        echo "  ❌ $LANG: Expected 200, got $HTTP_CODE"
        ALL_PASSED=false
    fi
done

if [ "$ALL_PASSED" = true ]; then
    echo "✅ PASS: All languages work correctly"
else
    echo "❌ FAIL: Some languages failed"
    exit 1
fi
echo ""

# Test 8: Verify exact error message format for 401
echo "Test 8: Verify 401 error message format"
ERROR_RESPONSE=$(curl -s -H "Authorization: Bearer $INVALID_KEY" "$STAGING_API/api/v1/patterns?language=javascript")
ERROR_MSG=$(echo "$ERROR_RESPONSE" | jq -r '.error')
MESSAGE=$(echo "$ERROR_RESPONSE" | jq -r '.message')

if [ "$ERROR_MSG" = "Unauthorized" ] && [ "$MESSAGE" = "Invalid API key" ]; then
    echo "✅ PASS: 401 error message format is correct"
else
    echo "❌ FAIL: Expected {\"error\":\"Unauthorized\",\"message\":\"Invalid API key\"}"
    echo "Got: $ERROR_RESPONSE"
    exit 1
fi
echo ""

echo "=========================================="
echo "✅ ALL TESTS PASSED!"
echo "=========================================="
echo ""
echo "Summary:"
echo "- No API key: Returns 200 with demo patterns ✓"
echo "- Invalid API key: Returns 401 Unauthorized ✓"
echo "- Valid API key: Returns 200 with full access ✓"
echo "- Backward compatibility maintained ✓"
echo "- Error messages formatted correctly ✓"
echo ""
echo "Safe to deploy to production!"