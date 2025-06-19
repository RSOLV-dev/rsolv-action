#!/bin/bash

# Direct API test script
echo "🔍 Testing RSOLV API endpoints directly..."
echo "========================================="

# Test health
echo "1. Health Check:"
curl -s https://api.rsolv.dev/health | jq .

echo -e "\n2. Pattern API (JavaScript):"
curl -s "https://api.rsolv.dev/api/v1/patterns?language=javascript" \
    -H "Authorization: Bearer test" | jq '.metadata'

echo -e "\n3. Pattern API (Django):"
curl -s "https://api.rsolv.dev/api/v1/patterns?language=python&framework=django" \
    -H "Authorization: Bearer test" | jq '.metadata'

echo -e "\n4. Test Fix Attempt (should fail with 401):"
curl -s -X POST https://api.rsolv.dev/api/v1/fix-attempts \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer test" \
    -d '{"pr_url": "https://github.com/test/repo/pull/123", "issue_url": "https://github.com/test/repo/issues/456"}' | jq .

echo -e "\n5. Webhook endpoint (should return 405 for GET):"
curl -s -X GET https://api.rsolv.dev/webhook/github \
    -H "X-GitHub-Event: pull_request" | head -1

echo -e "\n========================================="
echo "✅ API endpoints are accessible"