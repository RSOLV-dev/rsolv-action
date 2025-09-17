#!/bin/bash

# Test script for false positive cache in staging

API_KEY="${STAGING_API_KEY:-test-key}"
API_URL="https://staging-api.rsolv.dev/api/v1/vulnerabilities/validate"

# Test payload
PAYLOAD='{
  "vulnerabilities": [
    {
      "id": "vuln-1",
      "type": "sql-injection",
      "filePath": "app/routes/user.js",
      "line": 42,
      "code": "db.query(userInput)",
      "locations": [
        {"file_path": "app/routes/user.js", "line": 42, "is_primary": true}
      ]
    }
  ],
  "files": {
    "app/routes/user.js": {
      "content": "function getUserData(userInput) {\n  return db.query(userInput);\n}",
      "hash": "sha256:test123"
    }
  },
  "repository": "test-org/test-repo"
}'

echo "Testing false positive cache in staging..."
echo "========================================="
echo ""

# First request - should be cache miss
echo "Request 1 (expecting cache miss):"
RESPONSE1=$(curl -s -X POST "$API_URL" \
  -H "X-API-Key: $API_KEY" \
  -H "Content-Type: application/json" \
  -d "$PAYLOAD")

echo "$RESPONSE1" | jq '.validated[0] | {id, isValid, fromCache}'
echo ""

# Wait a moment
sleep 2

# Second request - should be cache hit if feature flag is enabled
echo "Request 2 (expecting cache hit if feature enabled):"
RESPONSE2=$(curl -s -X POST "$API_URL" \
  -H "X-API-Key: $API_KEY" \
  -H "Content-Type: application/json" \
  -d "$PAYLOAD")

echo "$RESPONSE2" | jq '.validated[0] | {id, isValid, fromCache}'
echo ""

# Check cache stats
echo "Cache statistics:"
echo "$RESPONSE2" | jq '.cache_stats'