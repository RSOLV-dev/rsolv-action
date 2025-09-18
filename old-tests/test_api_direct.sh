#!/bin/bash

echo "🔍 Testing API responses directly"
echo ""

# Test standard format
echo "1️⃣ Standard format response:"
curl -s -X GET 'http://localhost:4000/api/v1/patterns?language=javascript&format=standard' \
  -H 'Accept: application/json' | jq -r '. | type'

# Test enhanced format
echo ""
echo "2️⃣ Enhanced format response:"
response=$(curl -s -X GET 'http://localhost:4000/api/v1/patterns?language=javascript&format=enhanced' \
  -H 'Accept: application/json')

# Check if it's an error
if echo "$response" | jq -e '.error' > /dev/null 2>&1; then
    echo "   ❌ API returned error:"
    echo "$response" | jq '.'
    
    # Let's check server logs
    echo ""
    echo "3️⃣ Checking server logs for error details..."
    echo "   Run: journalctl -u phoenix -n 50"
    echo "   Or check the Phoenix console output"
else
    echo "   ✅ API returned data"
    echo "$response" | jq '.metadata'
fi

# Test with a mock API key
echo ""
echo "4️⃣ Testing with API key for full patterns:"
curl -s -X GET 'http://localhost:4000/api/v1/patterns?language=javascript&format=enhanced' \
  -H 'Accept: application/json' \
  -H 'Authorization: Bearer test-key-12345' | \
  jq '. | if .error then .error else {patterns: (.patterns | length), has_ast: (.patterns[0] | has("ast_rules"))} end'