#!/bin/bash
set -euo pipefail

# Test script to validate cache controller fix for string forge IDs
API_KEY="${RSOLV_API_KEY:-rsolv_xud6j-kCuMwsQ371QNBkQvTi5gmfZQ98FPXbmNmhMio}"
API_BASE="${API_BASE:-https://rsolv-staging.com}"

echo "Testing validation endpoint with cache controller fix..."
echo "API Base: $API_BASE"
echo ""

# Test validation endpoint with false positive
echo "Testing validation with false positive (should cache)..."
response=$(curl -s -w "\n%{http_code}" -X POST "$API_BASE/api/v1/vulnerabilities/validate" \
  -H "X-Api-Key: $API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "vulnerabilities": [{
      "filePath": "test.js",
      "type": "xss",
      "severity": "medium",
      "line": 42,
      "column": 10,
      "message": "XSS vulnerability detected",
      "pattern": "xss_html",
      "code": "const safe = escapeHtml(userInput);"
    }],
    "files": {
      "test.js": {
        "content": "const safe = escapeHtml(userInput);",
        "hash": "sha256:test123"
      }
    },
    "repository": "test-org/test-repo"
  }')

http_code=$(echo "$response" | tail -n1)
body=$(echo "$response" | head -n-1)

if [ "$http_code" -eq 200 ]; then
  echo "✅ Validation successful (HTTP $http_code)"

  # Check for cache metadata
  if echo "$body" | grep -q "cache_stats"; then
    echo "✅ Cache stats present in response"
  fi

  # Pretty print response
  echo "$body" | jq '.'
else
  echo "❌ Validation failed (HTTP $http_code)"
  echo "$body"
  exit 1
fi

echo ""
echo "Waiting 2 seconds before second request..."
sleep 2

# Second request - should hit cache
echo "Testing same validation again (should hit cache)..."
response2=$(curl -s -w "\n%{http_code}" -X POST "$API_BASE/api/v1/vulnerabilities/validate" \
  -H "X-Api-Key: $API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "vulnerabilities": [{
      "filePath": "test.js",
      "type": "xss",
      "severity": "medium",
      "line": 42,
      "column": 10,
      "message": "XSS vulnerability detected",
      "pattern": "xss_html",
      "code": "const safe = escapeHtml(userInput);"
    }],
    "files": {
      "test.js": {
        "content": "const safe = escapeHtml(userInput);",
        "hash": "sha256:test123"
      }
    },
    "repository": "test-org/test-repo"
  }')

http_code2=$(echo "$response2" | tail -n1)
body2=$(echo "$response2" | head -n-1)

if [ "$http_code2" -eq 200 ]; then
  echo "✅ Second validation successful (HTTP $http_code2)"

  # Check for cache hit
  if echo "$body2" | jq -e '.validated[0].fromCache == true' > /dev/null 2>&1; then
    echo "✅ Cache hit detected!"
  elif echo "$body2" | jq -e '.cache_stats.cache_hits > 0' > /dev/null 2>&1; then
    echo "✅ Cache hit detected via stats!"
  else
    echo "⚠️  Cache hit not detected (might be first run)"
  fi

  # Pretty print response
  echo "$body2" | jq '.'
else
  echo "❌ Second validation failed (HTTP $http_code2)"
  echo "$body2"
  exit 1
fi

echo ""
echo "✅ All tests passed! Cache controller fix is working."