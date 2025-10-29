# Webhook Integration Guide

This document provides operational guidance for Stripe webhook integration, testing, and troubleshooting.

## Overview

The platform integrates with Stripe webhooks to handle billing events asynchronously. Webhooks are processed via Oban workers to ensure reliability and meet Stripe's response time requirements.

## Architecture

```
Stripe Webhook → Signature Verification → Queue to Oban → Return 200
                        ↓
                  Async Worker
                        ↓
              WebhookProcessor
                        ↓
              Database Updates
```

### Components

**WebhookController** (`lib/rsolv_web/controllers/webhook_controller.ex`)
- Verifies Stripe signatures using HMAC-SHA256
- Queues events to Oban immediately
- Returns 200 within Stripe's 30-second requirement

**StripeWebhookWorker** (`lib/rsolv/workers/stripe_webhook_worker.ex`)
- Oban worker processing events asynchronously
- 3 retry attempts with exponential backoff
- Dedicated `:webhooks` queue

**WebhookProcessor** (`lib/rsolv/billing/webhook_processor.ex`)
- Pattern matches on event types
- Implements idempotency via unique constraint
- Updates customer billing state

## Supported Events

| Event | Action | Database Updates |
|-------|--------|------------------|
| `invoice.payment_succeeded` | Credits customer account | `credit_balance += 60`, creates credit transaction |
| `invoice.payment_failed` | Marks payment failure | `subscription_state = "past_due"` |
| `customer.subscription.created` | Records new subscription | Sets `stripe_subscription_id`, `subscription_type = "pro"` |
| `customer.subscription.deleted` | Downgrades to PAYG | `subscription_type = "pay_as_you_go"`, preserves credits |
| `customer.subscription.updated` | Handles subscription changes | Updates `subscription_state`, `cancel_at_period_end` flag |

## Configuration

### Environment Variables

```bash
# Stripe API credentials
STRIPE_API_KEY=sk_live_xxx  # or sk_test_xxx for testing

# Webhook signature verification
STRIPE_WEBHOOK_SECRET=whsec_xxx
```

### Stripe Dashboard Setup

1. Navigate to: **Developers → Webhooks**
2. Add endpoint: `https://your-domain.com/api/webhooks/stripe`
3. Select events to send:
   - `invoice.payment_succeeded`
   - `invoice.payment_failed`
   - `customer.subscription.created`
   - `customer.subscription.deleted`
   - `customer.subscription.updated`
4. Copy signing secret to `STRIPE_WEBHOOK_SECRET` environment variable

## Testing

### Local Testing with Stripe CLI

**Prerequisites:**
- Stripe CLI installed: `brew install stripe/stripe-cli/stripe` (macOS)
- Authenticated: `stripe login`

**Forward webhooks to local server:**

```bash
# Terminal 1: Start Phoenix
mix phx.server

# Terminal 2: Forward webhooks
stripe listen --forward-to http://localhost:4000/api/webhooks/stripe

# Terminal 3: Trigger test events
stripe trigger invoice.payment_succeeded
stripe trigger invoice.payment_failed
stripe trigger customer.subscription.created
stripe trigger customer.subscription.deleted
```

### Manual Event Triggering

Create custom payloads for specific scenarios:

```bash
curl -X POST http://localhost:4000/api/webhooks/stripe \
  -H "Content-Type: application/json" \
  -H "stripe-signature: t=$(date +%s),v1=<computed_signature>" \
  -d '{
    "id": "evt_test_123",
    "type": "invoice.payment_succeeded",
    "data": {
      "object": {
        "id": "in_test_123",
        "customer": "cus_test_webhook_123",
        "amount_paid": 59900,
        "lines": {
          "data": [{
            "price": {
              "lookup_key": "pro_monthly"
            }
          }]
        }
      }
    }
  }'
```

## Monitoring

### Key Metrics

Monitor these metrics via Prometheus/PromEx:

- `webhook_processing_duration_ms` - Time to process webhooks
- `webhook_success_total` - Successfully processed webhooks
- `webhook_failure_total` - Failed webhook processing
- `oban_job_queue_depth{queue="webhooks"}` - Webhook queue backlog

### Database Queries

**Check recent webhook events:**

```sql
SELECT stripe_event_id, event_type, amount_cents, inserted_at
FROM billing_events
ORDER BY inserted_at DESC
LIMIT 20;
```

**Verify customer state after webhook:**

```sql
SELECT id, email, subscription_type, subscription_state,
       credit_balance, stripe_subscription_id
FROM customers
WHERE stripe_customer_id = 'cus_xxx';
```

**Check credit transactions:**

```sql
SELECT amount, balance_after, source, metadata, inserted_at
FROM credit_transactions
WHERE customer_id = XXX
ORDER BY inserted_at DESC
LIMIT 10;
```

## Troubleshooting

### Webhook Returns 401 Unauthorized

**Cause**: Invalid signature or signature verification failure

**Solutions**:
1. Verify `STRIPE_WEBHOOK_SECRET` matches Stripe Dashboard
2. Check webhook endpoint URL is correct
3. Ensure payload hasn't been modified by proxy/CDN
4. Verify timestamp tolerance (5 minutes by default)

```elixir
# Check logs for signature verification errors
grep "Invalid signature" /var/log/phoenix.log
```

### Webhook Returns 500 Internal Server Error

**Cause**: Processing error in WebhookProcessor

**Solutions**:
1. Check Phoenix logs for error details
2. Verify customer exists with correct `stripe_customer_id`
3. Check database connectivity
4. Ensure Oban is running and healthy

```bash
# Check Oban status
iex -S mix
iex> Oban.check_queue(:webhooks)
```

### Duplicate Events Being Processed

**Should not happen** - Idempotency is guaranteed via unique constraint on `billing_events.stripe_event_id`

If duplicates occur:
1. Check database constraint exists: `\d billing_events` (psql)
2. Verify migration ran successfully
3. Check for race conditions in high-volume scenarios

### Events Not Processing

**Cause**: Oban worker not running or queue paused

**Solutions**:
1. Check Oban configuration in `config/runtime.exs`
2. Verify `:webhooks` queue is enabled
3. Check for paused queues: `Oban.check_queue(:webhooks)`
4. Restart workers if needed: `Oban.resume_queue(:webhooks)`

### Credit Balance Not Updating

**Cause**: Event not matching Pro subscription pattern

**Debug**:
1. Check event payload in `billing_events.metadata`
2. Verify `price.lookup_key` or `price.metadata.plan` contains "pro"
3. Check `WebhookProcessor.pro_subscription?/1` logic

```sql
-- Check what was actually received
SELECT metadata FROM billing_events
WHERE stripe_event_id = 'evt_xxx';
```

## Security Considerations

### Signature Verification

All webhooks **must** pass HMAC-SHA256 signature verification before processing:

1. Extract timestamp and signature from `stripe-signature` header
2. Compute HMAC: `HMAC-SHA256(timestamp.payload, webhook_secret)`
3. Compare using constant-time comparison (prevents timing attacks)
4. Reject if timestamp older than 5 minutes (prevents replay attacks)

**Never disable signature verification in production.**

### Webhook Secret Rotation

When rotating webhook secrets:

1. Add new endpoint in Stripe Dashboard (don't delete old one)
2. Deploy code with new `STRIPE_WEBHOOK_SECRET`
3. Verify new endpoint receives events successfully
4. Delete old endpoint after 24 hours of successful operation

### Idempotency

Events are idempotent - reprocessing the same event has no effect:

- `billing_events.stripe_event_id` has UNIQUE constraint
- Duplicate events return `{:ok, :duplicate}` with no side effects
- Safe to retry failed events manually

## Performance

### Expected Response Times

- **Webhook endpoint**: < 500ms (signature verification + queue)
- **Worker processing**: < 5s (database updates + credit ledger)

### Scaling Considerations

- Oban `:webhooks` queue can process multiple events concurrently
- Default: 10 concurrent workers
- Increase `concurrency` in `config/runtime.exs` if queue builds up
- Monitor `oban_job_queue_depth` metric

### Rate Limits

Stripe may send webhook bursts during:
- Monthly subscription renewals
- Failed payment retries
- Bulk subscription updates

Ensure Oban queue can handle spikes without blocking other jobs.

## References

- **Stripe Webhooks Documentation**: https://stripe.com/docs/webhooks
- **Stripe Event Types**: https://stripe.com/docs/api/events/types
- **Oban Documentation**: https://hexdocs.pm/oban/Oban.html
- **Implementation**: See `lib/rsolv/billing/webhook_processor.ex`
- **Tests**: See `test/rsolv/billing/webhook_processor_test.exs`

## See Also

- [API-PATTERNS.md](./API-PATTERNS.md) - General API integration patterns
- [OBSERVABILITY.md](./OBSERVABILITY.md) - Monitoring and metrics
- [SECURITY-ARCHITECTURE.md](./SECURITY-ARCHITECTURE.md) - Security best practices
