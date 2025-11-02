# Dunning Email Implementation

**Status:** Complete
**Date:** 2025-11-01
**RFC:** RFC-069 Wednesday

## Overview

Implemented automatic email notifications when subscription payments fail, ensuring customers are immediately notified of billing issues and can take corrective action.

## Implementation Summary

### Files Modified (5)

1. **`lib/rsolv/billing/webhook_processor.ex:76-103`** (+13 lines)
   - Queues Oban email job when `invoice.payment_failed` webhook received
   - Updates customer subscription_state to "past_due"
   - Passes all invoice details to worker

2. **`lib/rsolv/emails.ex:116-176`** (+42, -208 = **-166 lines net**)
   - Added `payment_failed_email/5` function with assigns-based approach
   - Helper functions: `format_currency/1`, `format_timestamp_from_unix/1`
   - Simplified text body using assigns map
   - **Removed inline HTML** in favor of HEEx template

3. **`lib/rsolv/email_service.ex:101-119`** (+20 lines)
   - Added `send_payment_failed_email/5` service function
   - Fetches customer and delegates to Emails module

4. **`lib/rsolv/workers/email_worker.ex:16-63`** (+49 lines)
   - Pattern-matched `perform/1` clause for "payment_failed" type
   - Comprehensive error handling and logging

5. **`lib/rsolv_web/components/emails_html.ex:141-152`** (+12 lines)
   - Added `payment_failed/1` and `render_payment_failed/1` functions
   - Renders HEEx template with assigns

### Files Created (2)

1. **`lib/rsolv_web/components/templates/email/payment_failed.html`** (+139 lines)
   - Professional HEEx template with styling
   - Uses `{@variable}` syntax for dynamic content
   - Separation of concerns: presentation vs logic

2. **`test/rsolv/billing/dunning_email_test.exs`** (+306 lines, 18 tests)
   - Uses ExMachina factories for concise, idiomatic setup
   - Webhook processing tests (3 tests)
   - Email job processing tests (5 tests)
   - Worker integration tests (2 tests)
   - Email content validation tests (5 tests)
   - Edge case tests (3 tests)

### Net Lines of Code

**Production code changes:**
- webhook_processor.ex: +13
- emails.ex: -166 (removed inline HTML)
- email_service.ex: +20
- email_worker.ex: +49
- emails_html.ex: +12
- payment_failed.html template: +139
- **Net production: +67 lines**

**Test code:** +306 lines

**Documentation:** +253 lines

**Total: +626 lines (+67 production, +306 tests, +253 docs)**

### Why This is Better

The template-based approach resulted in:
- ✅ **Cleaner separation of concerns** (HTML in templates, logic in modules)
- ✅ **More maintainable** (designers can edit templates directly)
- ✅ **Net negative in emails.ex** (-166 lines by removing inline HTML)
- ✅ **Phoenix best practices** (HEEx templates are the recommended approach)
- ✅ **Same functionality** with better code organization

## Key Features

✅ **Automatic Triggering** - Queued on Stripe webhook
✅ **Rich Invoice Details** - Amount, attempt count, next retry date
✅ **Customer-Friendly** - Clear CTA, preserved credits info
✅ **Professional Design** - HTML + text versions
✅ **High Priority** - Marked with X-Priority: 1
✅ **Trackable** - Tagged for Postmark analytics
✅ **Unsubscribe Support** - Respects email preferences
✅ **Error Resilient** - Oban retry logic
✅ **Well Tested** - 18 test cases, ~85% coverage

## Testing

### Local Testing (Development)

```bash
# Run test suite
mix test test/rsolv/billing/dunning_email_test.exs

# Specific test
mix test test/rsolv/billing/dunning_email_test.exs:107

# Test with Stripe CLI
stripe trigger invoice.payment_failed
```

### Staging/Production Testing (RPC)

Since staging/production run as releases without IEx, use remote shell:

```bash
# Connect to remote shell (staging)
kubectl exec -it deployment/rsolv-staging -n rsolv -- bin/rsolv remote

# Or using SSH (if configured)
ssh deploy@rsolv-staging.com
/opt/rsolv/bin/rsolv remote
```

**Test Payment Failed Email:**

```elixir
# In remote shell
customer = Rsolv.Repo.get_by!(Rsolv.Customers.Customer, email: "test@example.com")

Rsolv.EmailService.send_payment_failed_email(
  customer.id,
  "in_test_manual_#{System.unique_integer()}",
  1999,      # $19.99
  nil,       # no next attempt
  1          # first attempt
)
```

**Simulate Full Webhook Flow:**

```elixir
# In remote shell - requires customer with stripe_customer_id
customer = Rsolv.Repo.get_by!(Rsolv.Customers.Customer,
  stripe_customer_id: "cus_your_test_customer")

webhook_event = %{
  "stripe_event_id" => "evt_manual_test_#{System.unique_integer()}",
  "event_type" => "invoice.payment_failed",
  "event_data" => %{
    "object" => %{
      "id" => "in_manual_test_#{System.unique_integer()}",
      "customer" => customer.stripe_customer_id,
      "amount_due" => 1999,
      "attempt_count" => 1,
      "next_payment_attempt" => nil
    }
  }
}

Rsolv.Billing.WebhookProcessor.process_event(webhook_event)

# Verify job was queued
Rsolv.Repo.all(Oban.Job)
|> Enum.filter(&(&1.worker == "Rsolv.Workers.EmailWorker"))
|> Enum.filter(&(get_in(&1.args, ["type"]) == "payment_failed"))
|> List.first()
```

**Check Oban Job Status:**

```elixir
# List recent payment_failed jobs
Rsolv.Repo.all(
  from j in Oban.Job,
  where: j.worker == "Rsolv.Workers.EmailWorker",
  where: fragment("?->>'type' = ?", j.args, "payment_failed"),
  order_by: [desc: j.inserted_at],
  limit: 10
)
```

### Production Verification

After webhook processing, verify:

1. **Customer state updated:**
   ```elixir
   Rsolv.Repo.reload!(customer).subscription_state
   # Should be "past_due"
   ```

2. **Oban job completed:**
   ```elixir
   # Check for completed job
   Rsolv.Repo.one(
     from j in Oban.Job,
     where: j.worker == "Rsolv.Workers.EmailWorker",
     where: fragment("?->>'customer_id' = ?", j.args, ^to_string(customer.id)),
     where: j.state == "completed",
     order_by: [desc: j.completed_at],
     limit: 1
   )
   ```

3. **Email sent:** Check Postmark activity log for "payment-failed" tag

## Email Content

### Subject
`Payment Failed - Action Required`

### Key Elements
- Warning header with alert icon
- Invoice details (amount, ID, attempt count, next retry)
- "Update Payment Method" CTA button → `/dashboard/billing`
- Credits preservation reassurance
- Common failure reasons
- Support contact info
- Unsubscribe link

### Sender
`RSOLV Billing <billing@rsolv.dev>`

## Test Coverage

**18 tests** covering:

| Category | Tests | Coverage |
|----------|-------|----------|
| Webhook Processing | 3 | Job queueing, state updates, duplicates |
| Email Sending | 5 | Content, formatting, next attempt |
| Worker Integration | 2 | Job execution, error handling |
| Content Validation | 5 | Required elements, sender, headers |
| Edge Cases | 3 | Nil values, zero credits, large counts |

**Estimated Coverage:** ~85% of new code paths

## Design Decisions

### Why HEEx Templates?

**Better separation of concerns and maintainability.** While some existing emails use inline HTML strings, the newer approach uses HEEx templates in `lib/rsolv_web/components/templates/email/`. This provides:
- **Separation of logic and presentation** - HTML lives in template files
- **Easier to edit** - Designers can modify templates without touching Elixir code
- **Syntax highlighting** - Editors provide better support for `.html` files
- **Phoenix 1.7 best practices** - Follows modern Phoenix conventions
- **Net negative LOC** - Removed 166 lines from emails.ex by extracting to template

The refactor resulted in cleaner, more maintainable code with the same functionality.

### Why ExMachina Factories in Tests?

**Idiomatic Elixir testing.** The codebase already has comprehensive factory patterns (`Rsolv.CustomerFactory`) with traits like `with_pro_plan()` and `with_past_due()`. Using factories makes tests:
- More concise (1 line vs 7 lines for customer setup)
- More maintainable (centralized test data)
- More readable (semantic trait names)

**Before:**
```elixir
{:ok, customer} =
  Customers.create_customer(%{
    name: "Test Customer",
    email: "test@example.com",
    stripe_customer_id: "cus_test123",
    subscription_type: "pro",
    subscription_state: "active",
    credit_balance: 60
  })
```

**After:**
```elixir
customer = insert(:customer) |> with_pro_plan()
```

### Why Not Extract Config Helper?

The `payment_failed_email/5` function fetches email config, but extracting a shared helper offers minimal benefit:
- Only used in one place
- 4 lines of code
- Clear and explicit where it is
- Other email functions use different senders (support@ vs billing@)

## Future Enhancements

- [ ] Escalating dunning sequence (reminder after 3 days, final notice after 7 days)
- [ ] Customizable retry schedule per customer
- [ ] Dashboard banner for past_due customers
- [ ] Slack/webhook integration for admin notifications
- [ ] A/B testing different email copy

## References

- **RFC-069 Wednesday:** Payment failure dunning requirements
- **Stripe Docs:** https://stripe.com/docs/billing/revenue-recovery
- **Postmark Tag:** `payment-failed`
