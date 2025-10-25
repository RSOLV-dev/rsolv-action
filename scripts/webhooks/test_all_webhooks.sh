#!/bin/bash
# Test all Stripe webhook simulations in sequence

set -e

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Testing All Stripe Webhook Simulations"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

# Configuration
export WEBHOOK_URL="${WEBHOOK_URL:-http://localhost:4000/api/webhooks/stripe}"
export WEBHOOK_SECRET="${WEBHOOK_SECRET:-whsec_test_secret_at_least_32_chars}"
export CUSTOMER_ID="${CUSTOMER_ID:-cus_test123}"
export SUBSCRIPTION_ID="${SUBSCRIPTION_ID:-sub_test456}"

echo "Configuration:"
echo "  Webhook URL: $WEBHOOK_URL"
echo "  Customer ID: $CUSTOMER_ID"
echo "  Subscription ID: $SUBSCRIPTION_ID"
echo ""

# Test 1: Invoice Payment Succeeded
echo "Test 1/4: Invoice Payment Succeeded"
mix run scripts/webhooks/simulate_invoice_paid.exs
sleep 2

# Test 2: Invoice Payment Failed
echo "Test 2/4: Invoice Payment Failed"
FAILURE_CODE=card_declined mix run scripts/webhooks/simulate_invoice_failed.exs
sleep 2

# Test 3: Subscription Updated (Plan Change)
echo "Test 3/4: Subscription Updated (Plan Change)"
OLD_PLAN=price_growth_monthly \
NEW_PLAN=price_enterprise_monthly \
mix run scripts/webhooks/simulate_subscription_updated.exs
sleep 2

# Test 4: Subscription Deleted
echo "Test 4/4: Subscription Deleted"
CANCEL_REASON=user_requested mix run scripts/webhooks/simulate_subscription_deleted.exs

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "✅ All webhook tests completed"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
