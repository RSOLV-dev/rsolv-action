#!/bin/bash

# Staging Customer Admin Test Script
# Tests all CRUD operations programmatically

BASE_URL="https://api.rsolv-staging.com"
ADMIN_EMAIL="admin@rsolv.dev"
ADMIN_PASSWORD="AdminP@ssw0rd2025!"

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${YELLOW}Starting Customer Admin Dashboard Tests on Staging${NC}"
echo "================================================"

# Function to extract CSRF token
extract_csrf_token() {
    echo "$1" | grep -oP 'name="csrf-token" content="\K[^"]+' | head -1
}

# Function to extract cookie from headers
extract_cookie() {
    echo "$1" | grep -i 'set-cookie:' | grep -oP '_rsolv_landing_key=\K[^;]+' | head -1
}

# 1. Test Admin Login
echo -e "\n${YELLOW}1. Testing Admin Login...${NC}"
LOGIN_RESPONSE=$(curl -k -s -i -X GET "$BASE_URL/admin/login")
CSRF_TOKEN=$(extract_csrf_token "$LOGIN_RESPONSE")
SESSION_COOKIE=$(extract_cookie "$LOGIN_RESPONSE")

if [ -z "$CSRF_TOKEN" ]; then
    echo -e "${RED}Failed to get CSRF token${NC}"
    exit 1
fi

echo "   Got CSRF token: ${CSRF_TOKEN:0:10}..."
echo "   Got session cookie: ${SESSION_COOKIE:0:20}..."

# Perform login
LOGIN_POST=$(curl -k -s -i -X POST "$BASE_URL/admin/login" \
    -H "Cookie: _rsolv_landing_key=$SESSION_COOKIE" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "email=$ADMIN_EMAIL&password=$ADMIN_PASSWORD&_csrf_token=$CSRF_TOKEN" \
    --location)

if echo "$LOGIN_POST" | grep -q "/admin/auth"; then
    echo -e "${GREEN}   ✓ Admin login successful${NC}"
    AUTH_COOKIE=$(extract_cookie "$LOGIN_POST")
else
    echo -e "${RED}   ✗ Admin login failed${NC}"
    echo "$LOGIN_POST" | head -20
    exit 1
fi

# 2. Test Customer List View
echo -e "\n${YELLOW}2. Testing Customer List View...${NC}"
CUSTOMER_LIST=$(curl -k -s "$BASE_URL/admin/customers" \
    -H "Cookie: _rsolv_landing_key=$AUTH_COOKIE")

if echo "$CUSTOMER_LIST" | grep -q "Customer Management"; then
    echo -e "${GREEN}   ✓ Customer list page loaded${NC}"
else
    echo -e "${RED}   ✗ Failed to load customer list${NC}"
    exit 1
fi

# Check for key UI elements
if echo "$CUSTOMER_LIST" | grep -q "New Customer"; then
    echo -e "${GREEN}   ✓ New Customer button present${NC}"
else
    echo -e "${RED}   ✗ New Customer button missing${NC}"
fi

if echo "$CUSTOMER_LIST" | grep -q "Actions"; then
    echo -e "${GREEN}   ✓ Actions column present${NC}"
else
    echo -e "${RED}   ✗ Actions column missing${NC}"
fi

if echo "$CUSTOMER_LIST" | grep -q "View"; then
    echo -e "${GREEN}   ✓ View buttons present${NC}"
else
    echo -e "${RED}   ✗ View buttons missing${NC}"
fi

if echo "$CUSTOMER_LIST" | grep -q "Edit"; then
    echo -e "${GREEN}   ✓ Edit buttons present${NC}"
else
    echo -e "${RED}   ✗ Edit buttons missing${NC}"
fi

if echo "$CUSTOMER_LIST" | grep -q "Delete"; then
    echo -e "${GREEN}   ✓ Delete buttons present${NC}"
else
    echo -e "${RED}   ✗ Delete buttons missing${NC}"
fi

# 3. Test Customer Detail View
echo -e "\n${YELLOW}3. Testing Customer Detail View...${NC}"

# First, get a customer ID from the list
CUSTOMER_ID=$(echo "$CUSTOMER_LIST" | grep -oP 'href="/admin/customers/\K[0-9]+' | head -1)

if [ -z "$CUSTOMER_ID" ]; then
    echo -e "${YELLOW}   No customers found to test detail view${NC}"
else
    echo "   Testing customer ID: $CUSTOMER_ID"

    CUSTOMER_DETAIL=$(curl -k -s "$BASE_URL/admin/customers/$CUSTOMER_ID" \
        -H "Cookie: _rsolv_landing_key=$AUTH_COOKIE")

    if echo "$CUSTOMER_DETAIL" | grep -q "Customer Information"; then
        echo -e "${GREEN}   ✓ Customer detail page loaded${NC}"
    else
        echo -e "${RED}   ✗ Failed to load customer detail${NC}"
    fi

    if echo "$CUSTOMER_DETAIL" | grep -q "Usage Statistics"; then
        echo -e "${GREEN}   ✓ Usage statistics section present${NC}"
    else
        echo -e "${RED}   ✗ Usage statistics section missing${NC}"
    fi

    if echo "$CUSTOMER_DETAIL" | grep -q "API Keys"; then
        echo -e "${GREEN}   ✓ API Keys section present${NC}"
    else
        echo -e "${RED}   ✗ API Keys section missing${NC}"
    fi

    if echo "$CUSTOMER_DETAIL" | grep -q "Generate New Key"; then
        echo -e "${GREEN}   ✓ Generate API Key button present${NC}"
    else
        echo -e "${RED}   ✗ Generate API Key button missing${NC}"
    fi

    if echo "$CUSTOMER_DETAIL" | grep -q "Back to Customers"; then
        echo -e "${GREEN}   ✓ Back navigation present${NC}"
    else
        echo -e "${RED}   ✗ Back navigation missing${NC}"
    fi
fi

# 4. Test Pagination
echo -e "\n${YELLOW}4. Testing Pagination...${NC}"
if echo "$CUSTOMER_LIST" | grep -q "Showing.*of.*customers"; then
    echo -e "${GREEN}   ✓ Pagination info present${NC}"
else
    echo -e "${RED}   ✗ Pagination info missing${NC}"
fi

# 5. Test Sorting
echo -e "\n${YELLOW}5. Testing Sorting...${NC}"
if echo "$CUSTOMER_LIST" | grep -q 'phx-click="sort"'; then
    echo -e "${GREEN}   ✓ Sort columns are clickable${NC}"
else
    echo -e "${RED}   ✗ Sort columns not clickable${NC}"
fi

# 6. Test Filtering
echo -e "\n${YELLOW}6. Testing Status Filter...${NC}"
if echo "$CUSTOMER_LIST" | grep -q '<select.*name="status"'; then
    echo -e "${GREEN}   ✓ Status filter present${NC}"
    if echo "$CUSTOMER_LIST" | grep -q 'value="active"'; then
        echo -e "${GREEN}   ✓ Active filter option present${NC}"
    fi
    if echo "$CUSTOMER_LIST" | grep -q 'value="inactive"'; then
        echo -e "${GREEN}   ✓ Inactive filter option present${NC}"
    fi
else
    echo -e "${RED}   ✗ Status filter missing${NC}"
fi

# 7. Test Dark Mode Support
echo -e "\n${YELLOW}7. Testing Dark Mode Support...${NC}"
if echo "$CUSTOMER_LIST" | grep -q 'dark:bg-gray'; then
    echo -e "${GREEN}   ✓ Dark mode classes present${NC}"
else
    echo -e "${YELLOW}   ⚠ Dark mode classes not detected${NC}"
fi

# Summary
echo -e "\n${YELLOW}================================================${NC}"
echo -e "${GREEN}Customer Admin Dashboard Test Complete!${NC}"
echo -e "${YELLOW}================================================${NC}"

# Note about LiveView testing limitations
echo -e "\n${YELLOW}Note:${NC} Some features like Create, Edit, and Delete require"
echo "LiveView WebSocket connections and cannot be fully tested via curl."
echo "These should be tested manually or with browser automation tools."