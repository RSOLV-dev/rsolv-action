# Stripe Webhook Simulation Scripts

Scripts to simulate Stripe webhooks for testing billing integrations.

## Overview

These scripts generate properly signed webhook payloads and send them to your local
or staging RSOLV instance, allowing you to test webhook handling without triggering
real Stripe events.

## Prerequisites

```bash
# Install dependencies
mix deps.get

# Set environment variables
export WEBHOOK_SECRET=whsec_test_secret_at_least_32_chars
export WEBHOOK_URL=http://localhost:4000/api/webhooks/stripe
```

## Scripts

### simulate_invoice_paid.exs
Simulates a successful invoice payment event.

```bash
mix run scripts/webhooks/simulate_invoice_paid.exs
```

### simulate_invoice_failed.exs
Simulates a failed invoice payment event.

```bash
mix run scripts/webhooks/simulate_invoice_failed.exs
```

### simulate_subscription_deleted.exs
Simulates a subscription cancellation event.

```bash
mix run scripts/webhooks/simulate_subscription_deleted.exs
```

### simulate_subscription_updated.exs
Simulates a subscription update event (plan change, quantity change, etc.).

```bash
mix run scripts/webhooks/simulate_subscription_updated.exs
```

## Usage Examples

### Test Invoice Payment Success
```bash
CUSTOMER_ID=cus_test123 \
SUBSCRIPTION_ID=sub_test456 \
AMOUNT=1500 \
mix run scripts/webhooks/simulate_invoice_paid.exs
```

### Test Payment Failure
```bash
CUSTOMER_ID=cus_test123 \
FAILURE_CODE=card_declined \
mix run scripts/webhooks/simulate_invoice_failed.exs
```

### Test Subscription Cancellation
```bash
CUSTOMER_ID=cus_test123 \
SUBSCRIPTION_ID=sub_test456 \
mix run scripts/webhooks/simulate_subscription_deleted.exs
```

### Test Plan Change
```bash
CUSTOMER_ID=cus_test123 \
SUBSCRIPTION_ID=sub_test456 \
NEW_PLAN=price_enterprise_monthly \
mix run scripts/webhooks/simulate_subscription_updated.exs
```

## Running All Webhooks

```bash
# Test all webhook types in sequence
./scripts/webhooks/test_all_webhooks.sh
```

## Signature Verification

All scripts generate valid Stripe signatures using HMAC-SHA256:

1. Construct signed payload: `{timestamp}.{json_body}`
2. Compute HMAC-SHA256 hash using webhook secret
3. Format signature header: `t={timestamp},v1={signature}`

Your webhook endpoint should verify signatures using the same process.

## Troubleshooting

### Invalid Signature Errors
- Ensure `WEBHOOK_SECRET` matches the secret configured in your application
- Check that the timestamp isn't too old (Stripe rejects signatures > 5 minutes old)

### Connection Refused
- Verify your application is running: `mix phx.server`
- Check `WEBHOOK_URL` points to correct endpoint

### Webhook Not Processing
- Check application logs for errors
- Verify webhook event type is supported
- Ensure database has matching customer/subscription records

## Integration with Stripe CLI

For testing with real Stripe events in test mode:

```bash
# Install Stripe CLI
brew install stripe/stripe-cli/stripe

# Login to Stripe
stripe login

# Forward webhooks to local server
stripe listen --forward-to localhost:4000/api/webhooks/stripe

# Trigger test events
stripe trigger invoice.payment_succeeded
stripe trigger invoice.payment_failed
stripe trigger customer.subscription.deleted
stripe trigger customer.subscription.updated
```

## See Also

- [Stripe Webhooks Documentation](https://stripe.com/docs/webhooks)
- [Stripe Event Types](https://stripe.com/docs/api/events/types)
- [Testing Webhooks](https://stripe.com/docs/webhooks/test)
