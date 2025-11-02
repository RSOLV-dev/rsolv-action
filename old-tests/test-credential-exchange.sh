#!/bin/bash

# Test credential exchange with API key in header
# This tests the fix for the credential controller

API_KEY="${1:-rsolv_xud6j-kCuMwsQ371QNBkQvTi5gmfZQ98FPXbmNmhMio}"
ENVIRONMENT="${2:-staging}"

if [ "$ENVIRONMENT" = "production" ]; then
    API_URL="https://api.rsolv.ai"
else
    API_URL="https://api.rsolv-staging.com"
fi

echo "Testing credential exchange on $ENVIRONMENT"
echo "API URL: $API_URL"
echo "API Key: ${API_KEY:0:20}..."
echo ""

echo "Making credential exchange request..."
response=$(curl -s -X POST "$API_URL/api/v1/credentials/exchange" \
  -H "Content-Type: application/json" \
  -H "X-Api-Key: $API_KEY" \
  -d '{
    "providers": ["anthropic"],
    "ttl_minutes": 60
  }' -w "\nHTTP_STATUS:%{http_code}")

http_status=$(echo "$response" | grep "HTTP_STATUS" | cut -d: -f2)
body=$(echo "$response" | sed '$d')

echo "HTTP Status: $http_status"
echo "Response:"
echo "$body" | jq . 2>/dev/null || echo "$body"

if [ "$http_status" = "200" ]; then
    echo ""
    echo "✅ SUCCESS! API key authentication is working!"
    echo "The credential controller now properly accepts API keys from the X-Api-Key header."
else
    echo ""
    echo "❌ FAILED: Got HTTP $http_status"
    echo "The API key may be invalid or the fix hasn't been deployed yet."
fi