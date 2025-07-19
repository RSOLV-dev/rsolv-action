#!/bin/bash
# Test script for RSOLV API keys with correct header
# Generated on 2025-07-18

echo "Testing RSOLV API Keys with x-api-key header..."
echo "==========================================="

# API Keys (configured in Kubernetes secrets)
DEMO_KEY="demo_69b3158556cf1717c14bfcd8a1186a42"
INTERNAL_KEY="internal_c9d0a3569b45597be41a44ca007abd5c"
DOGFOOD_KEY="dogfood_3132182ffed1ab7fbe4e9abbd54d8309"
MASTER_KEY="master_58d4c71fcbf98327b088b21dd24f6c4327e87b4f4e080f7f81ebbc2f0e0aef32"

# Test endpoints
PROD_URL="https://api.rsolv.dev"
STAGING_URL="https://api.rsolv-staging.com"

# Function to test an API key
test_api_key() {
    local key_name=$1
    local api_key=$2
    local base_url=$3
    
    echo -n "Testing $key_name on $base_url... "
    
    # Test with x-api-key header (primary method)
    response=$(curl -s -X POST "$base_url/api/v1/vulnerabilities/validate" \
        -H "x-api-key: $api_key" \
        -H "Content-Type: application/json" \
        -d '{"vulnerabilities": []}')
    
    if echo "$response" | grep -q '"validated"'; then
        echo "SUCCESS"
        echo "  Response: $(echo "$response" | jq -c .)"
    elif echo "$response" | grep -q "error"; then
        echo "FAILED: $response"
    else
        echo "UNKNOWN: $response"
    fi
}

# Test each key on production
echo "Production Tests:"
test_api_key "Demo API Key" "$DEMO_KEY" "$PROD_URL"
test_api_key "Internal API Key" "$INTERNAL_KEY" "$PROD_URL"
test_api_key "Dogfood API Key" "$DOGFOOD_KEY" "$PROD_URL"
test_api_key "Master API Key" "$MASTER_KEY" "$PROD_URL"

echo ""
echo "Testing staging..."
test_api_key "Demo API Key" "$DEMO_KEY" "$STAGING_URL"

echo ""
echo "API Key Details:"
echo "================"
echo "Demo API Key:     $DEMO_KEY (10 requests/month limit)"
echo "Internal API Key: $INTERNAL_KEY (1000 requests/month limit)"
echo "Dogfood API Key:  $DOGFOOD_KEY (unlimited)"
echo "Master API Key:   ${MASTER_KEY:0:20}... (unlimited, full access)"

echo ""
echo "Usage:"
echo "- Use 'x-api-key' header (preferred)"
echo "- Or 'Authorization: Bearer API_KEY' header"
echo ""
echo "curl -X POST https://api.rsolv.dev/api/v1/vulnerabilities/validate \\"
echo "  -H 'x-api-key: YOUR_API_KEY' \\"
echo "  -H 'Content-Type: application/json' \\"
echo "  -d '{\"vulnerabilities\": [...]}'"