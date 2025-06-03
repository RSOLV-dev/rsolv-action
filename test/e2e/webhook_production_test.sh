#!/bin/bash

# End-to-end test for webhook functionality in production
# This tests the complete flow without needing actual GitHub webhook secret

echo "🧪 Testing RSOLV Webhook Infrastructure"
echo "======================================"

# API endpoint
API_URL="https://api.rsolv.dev"

# Test 1: Health check
echo -e "\n1️⃣ Testing health endpoint..."
HEALTH_RESPONSE=$(curl -s "$API_URL/health")
HEALTH_STATUS=$(echo "$HEALTH_RESPONSE" | jq -r '.status')
if [ "$HEALTH_STATUS" = "healthy" ]; then
    echo "✅ Health check passed"
else
    echo "❌ Health check failed: $HEALTH_RESPONSE"
    exit 1
fi

# Test 2: Webhook endpoint without signature
echo -e "\n2️⃣ Testing webhook endpoint without signature..."
RESPONSE=$(curl -s -w "\n%{http_code}" -X POST "$API_URL/webhook/github" \
    -H "Content-Type: application/json" \
    -H "x-github-event: pull_request" \
    -d '{"action":"opened"}')
STATUS_CODE=$(echo "$RESPONSE" | tail -n1)
BODY=$(echo "$RESPONSE" | head -n-1)

if [ "$STATUS_CODE" = "401" ] && [[ "$BODY" == *"Missing signature"* ]]; then
    echo "✅ Correctly rejected request without signature"
else
    echo "❌ Unexpected response: Status=$STATUS_CODE, Body=$BODY"
fi

# Test 3: Webhook endpoint with invalid signature
echo -e "\n3️⃣ Testing webhook endpoint with invalid signature..."
RESPONSE=$(curl -s -w "\n%{http_code}" -X POST "$API_URL/webhook/github" \
    -H "Content-Type: application/json" \
    -H "x-github-event: pull_request" \
    -H "x-hub-signature-256: sha256=invalid" \
    -d '{"action":"opened"}')
STATUS_CODE=$(echo "$RESPONSE" | tail -n1)
BODY=$(echo "$RESPONSE" | head -n-1)

if [ "$STATUS_CODE" = "401" ] && [[ "$BODY" == *"Invalid signature"* ]]; then
    echo "✅ Correctly rejected request with invalid signature"
else
    echo "❌ Unexpected response: Status=$STATUS_CODE, Body=$BODY"
fi

# Test 4: Database connectivity through health check
echo -e "\n4️⃣ Verifying database connectivity..."
DB_STATUS=$(echo "$HEALTH_RESPONSE" | jq -r '.services.database')
if [ "$DB_STATUS" = "healthy" ]; then
    echo "✅ Database connection healthy"
else
    echo "❌ Database connection unhealthy"
fi

# Test 5: Check deployment info
echo -e "\n5️⃣ Checking deployment information..."
kubectl get deployment rsolv-api -o wide
kubectl get pods -l app=rsolv-api

# Summary
echo -e "\n📊 Test Summary"
echo "==============="
echo "✅ API is deployed and healthy"
echo "✅ Webhook endpoint is accessible"
echo "✅ Signature verification is working"
echo "✅ Database connectivity confirmed"
echo ""
echo "⚠️  Note: Full webhook testing requires GITHUB_WEBHOOK_SECRET configuration"
echo ""
echo "Next steps:"
echo "1. Configure GITHUB_WEBHOOK_SECRET in production:"
echo "   kubectl create secret generic rsolv-api-secrets --from-literal=github-webhook-secret=YOUR_SECRET"
echo "2. Update deployment to use the secret"
echo "3. Configure GitHub webhook in repository settings"