#!/bin/bash
# Quick verification script for Stripe webhook testing
# Usage: ./verify_webhooks.sh

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Database connection
DB_URL="${DATABASE_URL:-postgresql://postgres:postgres@localhost/rsolv_dev}"

echo -e "${BLUE}╔═══════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║   Stripe Webhook Testing - Verification Script           ║${NC}"
echo -e "${BLUE}╚═══════════════════════════════════════════════════════════╝${NC}"
echo ""

# Function to run query and display results
run_query() {
  local title="$1"
  local query="$2"

  echo -e "${YELLOW}─────────────────────────────────────────────────────────${NC}"
  echo -e "${GREEN}${title}${NC}"
  echo -e "${YELLOW}─────────────────────────────────────────────────────────${NC}"
  psql "$DB_URL" -c "$query" 2>&1
  echo ""
}

# 1. Check if test customer exists
run_query "Test Customer Status" "
SELECT
  id,
  email,
  stripe_customer_id,
  credit_balance,
  subscription_type,
  subscription_state,
  stripe_subscription_id,
  subscription_cancel_at_period_end
FROM customers
WHERE email = 'webhook-test@example.com';
"

# 2. Check billing events
run_query "Recent Billing Events (Last 10)" "
SELECT
  be.id,
  be.event_type,
  be.stripe_event_id,
  be.amount_cents,
  be.inserted_at,
  c.email as customer_email
FROM billing_events be
JOIN customers c ON c.id = be.customer_id
WHERE c.email = 'webhook-test@example.com'
ORDER BY be.inserted_at DESC
LIMIT 10;
"

# 3. Check Oban jobs
run_query "Recent Webhook Jobs (Last 10)" "
SELECT
  id,
  state,
  queue,
  worker,
  args->>'event_type' as event_type,
  args->>'stripe_event_id' as stripe_event_id,
  attempted_at,
  completed_at
FROM oban_jobs
WHERE queue = 'webhooks'
ORDER BY inserted_at DESC
LIMIT 10;
"

# 4. Check for duplicate events (idempotency test)
run_query "Duplicate Event Check" "
SELECT
  stripe_event_id,
  COUNT(*) as occurrence_count
FROM billing_events
WHERE customer_id = (SELECT id FROM customers WHERE email = 'webhook-test@example.com')
GROUP BY stripe_event_id
HAVING COUNT(*) > 1;
"

# 5. Event type summary
run_query "Event Type Summary" "
SELECT
  event_type,
  COUNT(*) as count,
  MAX(inserted_at) as last_occurrence
FROM billing_events
WHERE customer_id = (SELECT id FROM customers WHERE email = 'webhook-test@example.com')
GROUP BY event_type
ORDER BY last_occurrence DESC;
"

# 6. Credit transaction history
run_query "Credit Transaction History" "
SELECT
  ct.id,
  ct.amount,
  ct.transaction_type,
  ct.source,
  ct.metadata,
  ct.inserted_at
FROM credit_transactions ct
JOIN customers c ON c.id = ct.customer_id
WHERE c.email = 'webhook-test@example.com'
ORDER BY ct.inserted_at DESC
LIMIT 10;
"

echo -e "${BLUE}═══════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}Verification Complete!${NC}"
echo -e "${BLUE}═══════════════════════════════════════════════════════════${NC}"
echo ""

# Check for common issues
echo -e "${YELLOW}Quick Health Check:${NC}"

# Check if customer exists
CUSTOMER_EXISTS=$(psql "$DB_URL" -t -c "SELECT EXISTS(SELECT 1 FROM customers WHERE email = 'webhook-test@example.com');" | tr -d ' ')
if [ "$CUSTOMER_EXISTS" = "t" ]; then
  echo -e "  ${GREEN}✓${NC} Test customer exists"
else
  echo -e "  ${RED}✗${NC} Test customer not found - run setup first!"
fi

# Check if any events were processed
EVENT_COUNT=$(psql "$DB_URL" -t -c "SELECT COUNT(*) FROM billing_events WHERE customer_id = (SELECT id FROM customers WHERE email = 'webhook-test@example.com');" | tr -d ' ')
if [ "$EVENT_COUNT" -gt 0 ]; then
  echo -e "  ${GREEN}✓${NC} ${EVENT_COUNT} billing events recorded"
else
  echo -e "  ${YELLOW}!${NC} No billing events yet - start testing!"
fi

# Check for failed jobs
FAILED_JOBS=$(psql "$DB_URL" -t -c "SELECT COUNT(*) FROM oban_jobs WHERE queue = 'webhooks' AND state = 'discarded';" | tr -d ' ')
if [ "$FAILED_JOBS" -eq 0 ]; then
  echo -e "  ${GREEN}✓${NC} No failed webhook jobs"
else
  echo -e "  ${RED}✗${NC} ${FAILED_JOBS} failed webhook jobs - check logs!"
fi

# Check for duplicate events
DUPLICATES=$(psql "$DB_URL" -t -c "SELECT COUNT(*) FROM (SELECT stripe_event_id FROM billing_events GROUP BY stripe_event_id HAVING COUNT(*) > 1) AS dupes;" | tr -d ' ')
if [ "$DUPLICATES" -eq 0 ]; then
  echo -e "  ${GREEN}✓${NC} No duplicate events (idempotency working)"
else
  echo -e "  ${RED}✗${NC} ${DUPLICATES} duplicate event IDs found - idempotency issue!"
fi

echo ""
echo -e "${BLUE}─────────────────────────────────────────────────────────${NC}"
echo -e "${GREEN}Next Steps:${NC}"
echo ""
echo "1. If customer doesn't exist:"
echo "   Run: psql \$DATABASE_URL < setup_test_customer.sql"
echo ""
echo "2. To trigger events:"
echo "   See: STRIPE_WEBHOOK_TESTING_GUIDE.md"
echo ""
echo "3. To watch logs in real-time:"
echo "   Terminal 1: mix phx.server"
echo "   Terminal 2: stripe listen --forward-to http://localhost:4000/api/webhooks/stripe"
echo ""
echo "4. Re-run this script after each event:"
echo "   ./verify_webhooks.sh"
echo ""
