#!/bin/bash

# Test Admin UI on Staging
echo "=== Testing Admin UI on Staging ==="
echo

# Base URL - using port-forward for testing
STAGING_URL="http://localhost:8080"

# Test credentials from seeds.exs
ADMIN_EMAIL="admin@rsolv.dev"
ADMIN_PASSWORD="AdminP@ssw0rd2025!"
STAFF_EMAIL="staff@rsolv.dev"
STAFF_PASSWORD="StaffP@ssw0rd2025!"

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo "1. Setting up port-forward to staging..."
kubectl port-forward -n rsolv-staging deployment/staging-rsolv-platform 8080:4000 &
PF_PID=$!
sleep 3

echo
echo "2. Testing health endpoint..."
HEALTH_RESPONSE=$(curl -s "$STAGING_URL/api/health" 2>/dev/null)
if echo "$HEALTH_RESPONSE" | grep -q "healthy"; then
    echo -e "${GREEN}✓ Health check passed${NC}"
    echo "$HEALTH_RESPONSE" | jq '.'
else
    echo -e "${RED}✗ Health check failed${NC}"
fi

echo
echo "3. Testing admin login endpoint..."
LOGIN_RESPONSE=$(curl -s -X POST "$STAGING_URL/admin/login" \
    -H "Content-Type: application/json" \
    -d "{\"email\":\"$ADMIN_EMAIL\",\"password\":\"$ADMIN_PASSWORD\"}" \
    -c /tmp/admin-cookies.txt \
    -w "\n%{http_code}" 2>/dev/null)
    
HTTP_CODE=$(echo "$LOGIN_RESPONSE" | tail -n1)
if [ "$HTTP_CODE" == "302" ] || [ "$HTTP_CODE" == "200" ]; then
    echo -e "${GREEN}✓ Admin login endpoint accessible (HTTP $HTTP_CODE)${NC}"
else
    echo -e "${YELLOW}⚠ Admin login returned HTTP $HTTP_CODE${NC}"
fi

echo
echo "4. Testing admin dashboard access..."
DASHBOARD_RESPONSE=$(curl -s -L "$STAGING_URL/admin" \
    -b /tmp/admin-cookies.txt \
    -w "\n%{http_code}" 2>/dev/null)
    
HTTP_CODE=$(echo "$DASHBOARD_RESPONSE" | tail -n1)
if [ "$HTTP_CODE" == "200" ]; then
    echo -e "${GREEN}✓ Admin dashboard accessible${NC}"
elif [ "$HTTP_CODE" == "302" ]; then
    echo -e "${YELLOW}⚠ Admin dashboard redirects (likely to login)${NC}"
else
    echo -e "${RED}✗ Admin dashboard returned HTTP $HTTP_CODE${NC}"
fi

echo
echo "5. Testing customer list endpoint..."
CUSTOMERS_RESPONSE=$(curl -s "$STAGING_URL/admin/customers" \
    -b /tmp/admin-cookies.txt \
    -w "\n%{http_code}" 2>/dev/null)
    
HTTP_CODE=$(echo "$CUSTOMERS_RESPONSE" | tail -n1)
if [ "$HTTP_CODE" == "200" ]; then
    echo -e "${GREEN}✓ Customer list accessible${NC}"
else
    echo -e "${YELLOW}⚠ Customer list returned HTTP $HTTP_CODE${NC}"
fi

echo
echo "6. Testing rate limiting..."
echo "Making 15 rapid login attempts to test rate limiting..."
for i in {1..15}; do
    RATE_TEST=$(curl -s -X POST "$STAGING_URL/admin/login" \
        -H "Content-Type: application/json" \
        -d "{\"email\":\"test@test.com\",\"password\":\"wrong$i\"}" \
        -w "%{http_code}" -o /dev/null 2>/dev/null)
    
    if [ "$RATE_TEST" == "429" ]; then
        echo -e "${GREEN}✓ Rate limiting activated at attempt $i (HTTP 429)${NC}"
        break
    elif [ "$i" == "15" ]; then
        echo -e "${YELLOW}⚠ Rate limiting not triggered after 15 attempts${NC}"
    fi
done

echo
echo "7. Checking Mnesia table status via exec..."
kubectl exec -n rsolv-staging staging-rsolv-platform-96846d884-69kjx -- /bin/sh -c "bin/rsolv eval 'IO.inspect(:mnesia.system_info(:tables))'" 2>/dev/null

echo
echo "8. Checking cluster nodes..."
kubectl exec -n rsolv-staging staging-rsolv-platform-96846d884-69kjx -- /bin/sh -c "bin/rsolv eval 'IO.inspect(Node.list())'" 2>/dev/null

# Cleanup
echo
echo "Cleaning up..."
kill $PF_PID 2>/dev/null
rm -f /tmp/admin-cookies.txt

echo
echo "=== Staging Admin UI Test Complete ==="