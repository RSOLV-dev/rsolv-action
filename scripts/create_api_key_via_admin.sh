#!/bin/bash

# Create API key via admin dashboard
# Credentials provided: admin@rsolv.dev / AdminP@ssw0rd2025!

BASE_URL="https://rsolv-staging.com"
EMAIL="admin@rsolv.dev"
PASSWORD="AdminP@ssw0rd2025!"

echo "Creating API key via admin dashboard..."
echo "======================================="

# First, we need to get a CSRF token and session
echo "1. Getting CSRF token..."
RESPONSE=$(curl -s -c /tmp/cookies.txt \
  -H "Accept: text/html" \
  "${BASE_URL}/admin/login")

CSRF_TOKEN=$(echo "$RESPONSE" | grep -oP 'name="_csrf_token" value="\K[^"]+' | head -1)

if [ -z "$CSRF_TOKEN" ]; then
    echo "Failed to get CSRF token"
    exit 1
fi

echo "   Got CSRF token: ${CSRF_TOKEN:0:20}..."

# Login
echo "2. Logging in as admin..."
LOGIN_RESPONSE=$(curl -s -b /tmp/cookies.txt -c /tmp/cookies.txt \
  -X POST \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "user[email]=${EMAIL}&user[password]=${PASSWORD}&_csrf_token=${CSRF_TOKEN}" \
  -L \
  "${BASE_URL}/admin/login")

# Check if login was successful by looking for admin dashboard content
if echo "$LOGIN_RESPONSE" | grep -q "Dashboard\|Customers\|Admin Panel"; then
    echo "   ✓ Login successful"
else
    echo "   ✗ Login failed"
    echo "   Attempting alternative login method..."

    # Try with different form field names
    LOGIN_RESPONSE=$(curl -s -b /tmp/cookies.txt -c /tmp/cookies.txt \
      -X POST \
      -H "Content-Type: application/x-www-form-urlencoded" \
      -d "email=${EMAIL}&password=${PASSWORD}&_csrf_token=${CSRF_TOKEN}" \
      -L \
      "${BASE_URL}/admin/login")
fi

# Get customers page to find or create customer
echo "3. Accessing customers page..."
CUSTOMERS_RESPONSE=$(curl -s -b /tmp/cookies.txt \
  -H "Accept: text/html" \
  "${BASE_URL}/admin/customers")

# Check if NodeGoat Demo customer exists
if echo "$CUSTOMERS_RESPONSE" | grep -q "NodeGoat Demo\|nodegoat@demo.test"; then
    echo "   NodeGoat Demo customer already exists"
    # Extract customer ID from the page
    CUSTOMER_ID=$(echo "$CUSTOMERS_RESPONSE" | grep -oP '/admin/customers/\K\d+' | head -1)
    echo "   Customer ID: $CUSTOMER_ID"
else
    echo "   Creating new NodeGoat Demo customer..."

    # Get CSRF token for customer creation
    CSRF_TOKEN=$(echo "$CUSTOMERS_RESPONSE" | grep -oP 'name="_csrf_token" value="\K[^"]+' | head -1)

    # Create customer via form submission
    CREATE_RESPONSE=$(curl -s -b /tmp/cookies.txt -c /tmp/cookies.txt \
      -X POST \
      -H "Content-Type: application/x-www-form-urlencoded" \
      -d "customer[name]=NodeGoat+Demo&customer[email]=nodegoat@demo.test&customer[company]=RSOLV+Demo&customer[subscription_tier]=professional&customer[monthly_limit]=100&customer[active]=true&_csrf_token=${CSRF_TOKEN}" \
      -L \
      "${BASE_URL}/admin/customers")

    # Extract customer ID from response
    CUSTOMER_ID=$(echo "$CREATE_RESPONSE" | grep -oP '/admin/customers/\K\d+' | head -1)
    echo "   Created customer with ID: $CUSTOMER_ID"
fi

# Navigate to customer detail page
echo "4. Accessing customer detail page..."
CUSTOMER_DETAIL=$(curl -s -b /tmp/cookies.txt \
  -H "Accept: text/html" \
  "${BASE_URL}/admin/customers/${CUSTOMER_ID}")

# Get CSRF token for API key generation
CSRF_TOKEN=$(echo "$CUSTOMER_DETAIL" | grep -oP 'name="_csrf_token" value="\K[^"]+' | head -1)

# Generate API key
echo "5. Generating API key..."
API_KEY_RESPONSE=$(curl -s -b /tmp/cookies.txt \
  -X POST \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "api_key[name]=NodeGoat+Demo+Key&_csrf_token=${CSRF_TOKEN}" \
  -L \
  "${BASE_URL}/admin/customers/${CUSTOMER_ID}/api_keys")

# Extract API key from response
# The key is typically shown in a success message or modal
API_KEY=$(echo "$API_KEY_RESPONSE" | grep -oP 'rsolv_[a-zA-Z0-9_]+' | head -1)

if [ -n "$API_KEY" ]; then
    echo "   ✓ API key generated successfully!"
    echo
    echo "======================================="
    echo "API KEY CREATED:"
    echo "$API_KEY"
    echo "======================================="
    echo
    echo "Updating GitHub secret..."
    echo "$API_KEY" | gh secret set RSOLV_API_KEY --repo RSOLV-dev/nodegoat-vulnerability-demo
    echo "✓ GitHub secret updated"
else
    echo "   ✗ Failed to extract API key"
    echo "   Response preview:"
    echo "$API_KEY_RESPONSE" | head -50
fi

# Clean up
rm -f /tmp/cookies.txt

echo
echo "Done!"