# Stripe Webhook Testing Guide

This guide provides instructions for testing Stripe webhook processing using Stripe CLI.

## Overview

RSOLV uses Stripe webhooks to handle billing events asynchronously. This guide covers manual testing of the webhook implementation.

### Architecture

- **Endpoint**: `POST /api/webhooks/stripe`
- **Controller**: `lib/rsolv_web/controllers/webhook_controller.ex`
- **Worker**: `lib/rsolv/workers/stripe_webhook_worker.ex` (Oban)
- **Processor**: `lib/rsolv/billing/webhook_processor.ex`

### Supported Events

1. `invoice.payment_succeeded` - Credits account for Pro subscription payments (+60 credits)
2. `invoice.payment_failed` - Marks subscription as past_due
3. `customer.subscription.created` - Records new subscription
4. `customer.subscription.deleted` - Downgrades to pay-as-you-go
5. `customer.subscription.updated` - Updates subscription state

### Idempotency

Duplicate events are prevented via unique constraint on `billing_events.stripe_event_id`. Duplicate events return `{:ok, :duplicate}` without reprocessing.

## Prerequisites

### Stripe CLI Installation

```bash
# macOS
brew install stripe/stripe-cli/stripe

# Linux
curl -s https://packages.stripe.com/api/security/keypair/stripe-cli-gpg/public | gpg --dearmor | sudo tee /usr/share/keyrings/stripe.gpg
echo "deb [signed-by=/usr/share/keyrings/stripe.gpg] https://packages.stripe.com/stripe-cli-debian-local stable main" | sudo tee -a /etc/apt/sources.list.d/stripe.list
sudo apt update
sudo apt install stripe

# Verify
stripe --version
```

### Authentication

```bash
stripe login
stripe config --list
```

## Setup

### 1. Create Test Customer

```bash
mix run --no-start test/scripts/setup_webhook_test_customer.exs
```

This creates a customer using Ecto with:
- Email: `webhook-test@example.com`
- Fresh Stripe customer ID
- Proper password hashing and schema validation

**Save the Stripe customer ID** shown in the output for use in test commands.

### 2. Terminal Setup

You need 3 terminals:

#### Terminal 1: Phoenix Server
```bash
mix phx.server
```

#### Terminal 2: Stripe CLI
```bash
stripe listen --forward-to http://localhost:4000/api/webhooks/stripe
```

**Important**: Copy the webhook signing secret (starts with `whsec_`) shown in the output:

```bash
export STRIPE_WEBHOOK_SECRET=whsec_xxxxxxxxxxxxxxxxxxxxx
```

Then restart the Phoenix server for the environment variable to take effect.

#### Terminal 3: Test Commands
This is where you'll trigger events (see next section).

## Testing Events

Replace `cus_test_XXXX` with your actual Stripe customer ID from setup.

### invoice.payment_succeeded

```bash
stripe trigger invoice.payment_succeeded --override customer=cus_test_XXXX
```

**Expected**:
- +60 credits added to `credit_balance`
- Billing event recorded
- Oban job completes successfully

**Verify**:
```bash
./test/scripts/verify_webhooks.sh
```

### invoice.payment_failed

```bash
stripe trigger invoice.payment_failed --override customer=cus_test_XXXX
```

**Expected**:
- `subscription_state` set to `past_due`
- Warning logged

### customer.subscription.created

```bash
stripe trigger customer.subscription.created --override customer=cus_test_XXXX
```

**Expected**:
- `stripe_subscription_id` populated
- `subscription_type` set to `pro`
- `subscription_state` set to `active` or `trialing`

### customer.subscription.deleted

```bash
stripe trigger customer.subscription.deleted --override customer=cus_test_XXXX
```

**Expected**:
- `subscription_type` changed to `pay_as_you_go`
- `subscription_state` cleared (NULL)
- `stripe_subscription_id` cleared
- **`credit_balance` preserved** (critical!)

### customer.subscription.updated

```bash
stripe trigger customer.subscription.updated \
  --override customer=cus_test_XXXX \
  --override cancel_at_period_end=true
```

**Expected**:
- `subscription_cancel_at_period_end` set to `true`
- `subscription_state` updated

## Verification

After each test, run the verification script:

```bash
./test/scripts/verify_webhooks.sh
```

This checks:
- Customer state
- Billing events
- Oban jobs
- Duplicate detection
- Event type summary

### Manual Verification Queries

```sql
-- Check customer state
SELECT id, credit_balance, subscription_type, subscription_state
FROM customers
WHERE email = 'webhook-test@example.com';

-- Check billing events
SELECT event_type, stripe_event_id, amount_cents, inserted_at
FROM billing_events
WHERE customer_id = (SELECT id FROM customers WHERE email = 'webhook-test@example.com')
ORDER BY inserted_at DESC;

-- Check Oban jobs
SELECT state, worker, args->>'event_type' as event_type
FROM oban_jobs
WHERE queue = 'webhooks'
ORDER BY inserted_at DESC
LIMIT 10;
```

## Expected State Transitions

Starting state:
```
credit_balance: 0
subscription_type: pay_as_you_go
subscription_state: NULL
```

After `subscription.created`:
```
subscription_type: pro
subscription_state: active
stripe_subscription_id: sub_xxxxx
```

After `payment_succeeded`:
```
credit_balance: 60
```

After `subscription.deleted`:
```
credit_balance: 60  ← PRESERVED
subscription_type: pay_as_you_go
subscription_state: NULL
stripe_subscription_id: NULL
```

## Troubleshooting

### Webhook not received
- Verify Phoenix is running on port 4000
- Check Stripe CLI shows "webhook received" messages
- Confirm `--forward-to` URL is correct

### Signature verification failed
- Ensure `STRIPE_WEBHOOK_SECRET` is set correctly
- Restart Phoenix server after setting the variable
- Verify secret matches the one shown by Stripe CLI

### Customer not found
- Check customer exists: `SELECT * FROM customers WHERE email = 'webhook-test@example.com';`
- Verify `stripe_customer_id` matches the trigger command
- Re-run setup script if needed

### Jobs failing
- Check Oban dashboard: http://localhost:4000/dev/dashboard
- Query failed jobs: `SELECT * FROM oban_jobs WHERE state = 'discarded' AND queue = 'webhooks';`
- Review Phoenix logs for error details

## Security

Webhook security features:
- HMAC-SHA256 signature verification
- Constant-time string comparison (prevents timing attacks)
- Timestamp validation (5-minute tolerance)
- Webhook secret from environment variable
- Async processing (prevents timeout attacks)

## Success Criteria

All tests pass when:
- ✅ All 5 event types process successfully
- ✅ All Oban jobs complete (state=completed)
- ✅ Database state matches expected values
- ✅ No duplicate events (idempotency works)
- ✅ All webhooks return 200 to Stripe
- ✅ Credits preserved during subscription cancellation

## Cleanup

```sql
-- Remove test data
DELETE FROM billing_events
WHERE customer_id = (SELECT id FROM customers WHERE email = 'webhook-test@example.com');

DELETE FROM customers WHERE email = 'webhook-test@example.com';
```

## Related Documentation

- Test Scripts: `test/scripts/README.md`
- Billing Architecture: `RFCs/RFC-065-billing-core.md`
- Stripe Integration: `RFCs/RFC-066-billing-integration.md`
- Webhook Integration: `docs/WEBHOOK-INTEGRATION.md`
