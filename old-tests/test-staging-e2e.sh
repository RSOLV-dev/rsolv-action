#!/bin/bash
# End-to-end test of RSOLV staging with GitHub Actions

set -euo pipefail

echo "=================================================="
echo "RSOLV Staging End-to-End Test"
echo "=================================================="

# Configuration
STAGING_URL="https://rsolv-staging.com"
API_KEY="rsolv_Nc4KkUwhoEtkKC2vZvrM8bINAY4t258qh8cYoam9hxE"

echo ""
echo "1. Testing health endpoint..."
HEALTH=$(curl -s "$STAGING_URL/health" | jq -r '.status')
if [[ "$HEALTH" == "ok" ]]; then
    echo "   ✅ Health check passed"
else
    echo "   ❌ Health check failed: $HEALTH"
    exit 1
fi

echo ""
echo "2. Testing credential exchange..."
CRED_RESPONSE=$(curl -s -X POST "$STAGING_URL/api/v1/credentials/exchange" \
    -H "X-Api-Key: $API_KEY" \
    -H "Content-Type: application/json" \
    -d '{"providers": ["anthropic"], "ttl_minutes": 60}')

if echo "$CRED_RESPONSE" | jq -e '.credentials.anthropic.api_key' > /dev/null; then
    echo "   ✅ Credential exchange successful"
    ANTHROPIC_KEY=$(echo "$CRED_RESPONSE" | jq -r '.credentials.anthropic.api_key')
    echo "   Got temporary Anthropic key: ${ANTHROPIC_KEY:0:20}..."
else
    echo "   ❌ Credential exchange failed"
    echo "$CRED_RESPONSE"
    exit 1
fi

echo ""
echo "3. Setting up GitHub secret for testing..."
# This would normally be done in GitHub Actions
export RSOLV_API_KEY="$API_KEY"
echo "   ✅ API key exported as environment variable"

echo ""
echo "4. Summary:"
echo "   - Staging URL: $STAGING_URL"
echo "   - API Key: ${API_KEY:0:20}..."
echo "   - Credential Exchange: ✅ Working"
echo "   - Header Authentication: ✅ Working"

echo ""
echo "=================================================="
echo "✅ All tests passed! Ready for GitHub Actions"
echo "=================================================="
echo ""
echo "To use in GitHub Actions, set this secret:"
echo "gh secret set RSOLV_API_KEY --body \"$API_KEY\" -R <your-repo>"
echo ""
echo "The action will automatically:"
echo "1. Use the API key from secrets"
echo "2. Exchange for temporary AI credentials"
echo "3. Generate fixes for vulnerabilities"
echo "4. Create pull requests with fixes"