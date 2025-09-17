#!/bin/bash
# Test pattern tier filtering

echo "Testing Pattern Tier Filtering"
echo "=============================="

# Test public patterns (no auth)
echo -e "\n1. Testing PUBLIC patterns (no auth):"
curl -s "http://localhost:4000/api/v1/patterns?language=javascript&tier=public" | jq '.metadata.count, .metadata.tier'

# Test protected patterns (with auth)
echo -e "\n2. Testing PROTECTED patterns (with auth):"
curl -s -H "Authorization: Bearer test_1234567890" "http://localhost:4000/api/v1/patterns?language=javascript&tier=protected" | jq '.metadata.count, .metadata.tier' 2>/dev/null || echo "Needs valid API key"

# Test AI patterns (with auth)
echo -e "\n3. Testing AI patterns (with auth):"
curl -s -H "Authorization: Bearer test_1234567890" "http://localhost:4000/api/v1/patterns?language=javascript&tier=ai" | jq '.metadata.count, .metadata.tier' 2>/dev/null || echo "Needs valid API key"

# Test enterprise patterns (with auth)
echo -e "\n4. Testing ENTERPRISE patterns (with auth):"
curl -s -H "Authorization: Bearer test_1234567890" "http://localhost:4000/api/v1/patterns?language=javascript&tier=enterprise" | jq '.metadata.count, .metadata.tier' 2>/dev/null || echo "Needs valid API key"

# Check what tiers patterns actually have
echo -e "\n5. Checking pattern tier assignments in code:"
echo "Public tier patterns:"
grep -r "default_tier: :public" /Users/dylan/dev/rsolv/RSOLV-api/lib/rsolv_api/security/patterns/javascript/*.ex 2>/dev/null | wc -l

echo "Protected tier patterns:"
grep -r "default_tier: :protected" /Users/dylan/dev/rsolv/RSOLV-api/lib/rsolv_api/security/patterns/javascript/*.ex 2>/dev/null | wc -l

echo "AI tier patterns:"
grep -r "default_tier: :ai" /Users/dylan/dev/rsolv/RSOLV-api/lib/rsolv_api/security/patterns/javascript/*.ex 2>/dev/null | wc -l

echo "Enterprise tier patterns:"
grep -r "default_tier: :enterprise" /Users/dylan/dev/rsolv/RSOLV-api/lib/rsolv_api/security/patterns/javascript/*.ex 2>/dev/null | wc -l

echo -e "\n6. Sample pattern tier assignments:"
grep -r "default_tier:" /Users/dylan/dev/rsolv/RSOLV-api/lib/rsolv_api/security/patterns/javascript/*.ex 2>/dev/null | head -5