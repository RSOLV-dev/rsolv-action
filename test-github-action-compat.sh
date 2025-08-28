#!/bin/bash
# Test GitHub Action compatibility with staging API
# Simulates what the GitHub Action does when fetching patterns

set -e

echo "Testing GitHub Action pattern fetching compatibility..."
echo ""

# Test what happens when GitHub Action has no API key (should get demo patterns)
echo "1. GitHub Action without API key (common for public repos):"
curl -s "https://api.rsolv-staging.com/api/v1/patterns?language=javascript&format=enhanced" | jq '.metadata' | grep -q '"access_level": "demo"'
if [ $? -eq 0 ]; then
    echo "   ✅ Gets demo patterns as expected"
else
    echo "   ❌ Failed to get demo patterns"
    exit 1
fi

# Test with expired/revoked key (should now get 401)
echo "2. GitHub Action with revoked/invalid API key:"
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" -H "Authorization: Bearer rsolv_revoked_key_example" "https://api.rsolv-staging.com/api/v1/patterns?language=javascript")
if [ "$HTTP_CODE" = "401" ]; then
    echo "   ✅ Gets 401 for invalid key (Action should handle this)"
else
    echo "   ❌ Expected 401, got $HTTP_CODE"
    exit 1
fi

# Test with valid key
echo "3. GitHub Action with valid API key:"
PATTERNS=$(curl -s -H "Authorization: Bearer rsolv_test_full_access_no_quota_2025" "https://api.rsolv-staging.com/api/v1/patterns?language=javascript&format=enhanced" | jq '.patterns | length')
if [ "$PATTERNS" -gt 20 ]; then
    echo "   ✅ Gets full patterns ($PATTERNS patterns)"
else
    echo "   ❌ Expected >20 patterns, got $PATTERNS"
    exit 1
fi

echo ""
echo "✅ GitHub Action compatibility verified!"
echo ""
echo "Note: The RSOLV-action should handle 401 responses gracefully"
echo "      and fall back to local patterns when API key is invalid."