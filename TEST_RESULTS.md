# Payment Failure Webhook Test Results

**Date:** 2025-11-05
**Branch:** `vk/416f-test-webhook-pay`
**Status:** ✅ All Tests Passing

## Test Coverage

This test suite verifies the complete dunning email flow for failed invoice payments (RFC-066).

### Tested Scenarios

1. **Customer State Update** ✅
   - Customer `subscription_state` correctly updated from "active" to "past_due"
   - State persists in database

2. **Email Job Queueing** ✅
   - EmailWorker job created with type "payment_failed"
   - Job queued in `:emails` queue
   - Job contains all required data:
     - `customer_id`
     - `invoice_id`
     - `amount_due` (in cents)
     - `attempt_count`
     - `next_payment_attempt` (unix timestamp)

3. **Billing Event Creation** ✅
   - BillingEvent record created for audit trail
   - Event type: "invoice.payment_failed"
   - Amount correctly extracted (2900 cents = $29.00)
   - Customer ID properly linked

4. **Webhook Idempotency** ✅
   - Duplicate webhooks correctly detected
   - No additional jobs or events created on duplicate
   - Returns `{:ok, :duplicate}` status

5. **Logging** ✅
   - Warning log emitted: "Payment failed for customer"
   - Includes metadata (customer_id, stripe_invoice_id, amount)

## Test File

**Location:** `test/billing/webhook_processor_payment_failure_test.exs`

**Command:** `mix test test/billing/webhook_processor_payment_failure_test.exs`

**Results:**
```
Finished in 0.9 seconds (0.00s async, 0.9s sync)
5 tests, 0 failures
```

## Code Changes

### 1. Fixed Amount Extraction (webhook_processor.ex:243)

**Problem:** For failed payments, `amount_paid` is 0, but the relevant amount is `amount_due`. The extractor was checking `amount_paid` first, resulting in BillingEvent.amount_cents = 0.

**Solution:** Prioritize `amount_due` when it's > 0:

```elixir
# Extract amount for event recording
# Check amount_due first (for failed payments where amount_paid may be 0)
defp extract_amount(%{"object" => %{"amount_due" => amount}}) when amount > 0, do: amount
defp extract_amount(%{"object" => %{"amount_paid" => amount}}), do: amount
defp extract_amount(%{"object" => %{"amount_due" => amount}}), do: amount
defp extract_amount(_), do: nil
```

### 2. Test Setup

**Oban Testing Mode:** Used `Oban.Testing.with_testing_mode(:manual)` to prevent inline job execution during the job verification test. This allows the test to inspect the queued job before it's processed.

## Manual Verification Steps

For manual testing in IEx:

```elixir
# 1. Check customers with past_due state
alias Rsolv.Customers
import Ecto.Query

Customers.Customer
|> where([c], c.subscription_state == "past_due")
|> Rsolv.Repo.all()

# 2. Check payment_failed email jobs
from(j in Oban.Job,
  where: j.worker == "Rsolv.Workers.EmailWorker",
  where: fragment("?->>'type' = ?", j.args, "payment_failed"),
  order_by: [desc: j.inserted_at],
  limit: 5
)
|> Rsolv.Repo.all()

# 3. Check billing events
alias Rsolv.Billing.BillingEvent

BillingEvent
|> where([e], e.event_type == "invoice.payment_failed")
|> order_by([e], desc: e.inserted_at)
|> limit(5)
|> Rsolv.Repo.all()

# 4. Process email queue
Oban.drain_queue(queue: :emails)
```

## Integration with Stripe CLI

To test with real Stripe webhooks:

```bash
# Trigger invoice.payment_failed event
stripe trigger invoice.payment_failed \
  --override customer:id=<stripe_customer_id>

# Monitor webhook delivery
stripe listen --forward-to localhost:4000/api/webhooks/stripe
```

## Related Files

- **Implementation:** `lib/rsolv/billing/webhook_processor.ex` (lines 92-126)
- **Email Worker:** `lib/rsolv/workers/email_worker.ex` (lines 16-85)
- **Test Suite:** `test/billing/webhook_processor_payment_failure_test.exs`
- **RFC:** `RFCs/RFC-066-dunning-emails.md`

## Next Steps

1. ✅ Webhook handler correctly updates customer state
2. ✅ Email job queued with correct data
3. ✅ Billing event created for audit
4. ✅ Idempotency working
5. ⏳ **Email template implementation** - EmailService.send_payment_failed_email/5 needs to be implemented with proper template
6. ⏳ **Postmark template** - Create dunning email template in Postmark account
7. ⏳ **Staging testing** - Test with Stripe test mode on staging environment
8. ⏳ **Production deployment** - Deploy with feature flag

## Notes

- All tests use `async: false` due to database transactions
- EmailWorker uses Oban's built-in retry mechanism (max_attempts: 3)
- Webhook idempotency is enforced by unique constraint on `billing_events.stripe_event_id`
- Email jobs are processed asynchronously in production via Oban queue
