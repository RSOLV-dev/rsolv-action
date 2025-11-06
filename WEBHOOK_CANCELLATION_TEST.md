# Webhook Subscription Cancellation Test Guide

## Overview
This guide tests that subscription cancellations via `customer.subscription.deleted` webhook properly downgrade customers to PAYG while preserving their credit balance.

## Test Implementation
Location: `lib/rsolv/billing/webhook_processor.ex:148-166`

Expected behavior:
1. Webhook receives `customer.subscription.deleted` event
2. Customer updated with:
   - `subscription_type: "pay_as_you_go"`
   - `subscription_state: nil`
   - `stripe_subscription_id: nil`
   - `subscription_cancel_at_period_end: false`
3. **Credit balance PRESERVED** (not reset to zero)
4. Log message: "Subscription canceled, downgraded to PAYG" with customer_id and credits_remaining

## Quick Test (Automated)

### Option 1: Using IEx (Recommended)

1. Start IEx:
```bash
cd /var/tmp/vibe-kanban/worktrees/2ec2-test-webhook-sub
iex -S mix phx.server
```

2. Copy and paste the entire contents of `test_webhook_iex.exs`

3. Look for output showing:
   - ✅ Customer created with Pro subscription
   - ✅ Credits added (1000)
   - ✅ Webhook processed
   - ✅ Customer downgraded to PAYG
   - ✅ Credits preserved (still 1000)
   - ✅ Billing event recorded

### Option 2: Using mix run (if compiled)

```bash
mix run test_webhook_cancellation.exs
```

## Manual Test (Step-by-Step)

### Setup

1. Start IEx with Phoenix:
```bash
iex -S mix phx.server
```

2. Load required modules:
```elixir
alias Rsolv.Repo
alias Rsolv.Customers
alias Rsolv.Customers.Customer
alias Rsolv.Billing.{WebhookProcessor, CreditLedger, BillingEvent}
import Ecto.Query
```

### Step 1: Create Test Customer with Pro Subscription

```elixir
# Create unique IDs
stripe_customer_id = "cus_test_webhook_cancel_#{System.system_time(:second)}"
stripe_subscription_id = "sub_test_webhook_cancel_#{System.system_time(:second)}"

# Create customer
{:ok, customer} = Customers.register_customer(%{
  name: "Webhook Cancel Test Customer",
  email: "webhook-test-#{System.system_time(:second)}@example.com",
  password: "TestP@ssw0rd2025!",
  subscription_type: "pro",
  subscription_state: "active",
  stripe_customer_id: stripe_customer_id,
  stripe_subscription_id: stripe_subscription_id,
  metadata: %{"type" => "test", "purpose" => "webhook_cancellation_test"}
})

# Verify creation
IO.inspect(customer, label: "Created customer")
```

**Expected:**
- Customer has `subscription_type: "pro"`
- Customer has `subscription_state: "active"`
- Customer has stripe_customer_id and stripe_subscription_id set

### Step 2: Add Credit Balance

```elixir
# Add initial credits
initial_credits = 1000
{:ok, _ledger_entry} = CreditLedger.credit(customer, initial_credits, "manual_test_credit", %{
  note: "Initial credits for cancellation test"
})

# Refresh customer
customer = Repo.get!(Customer, customer.id)
IO.puts("Credit balance: #{customer.credit_balance}")
```

**Expected:**
- Customer has `credit_balance: 1000`

### Step 3: Trigger Subscription Cancellation Webhook

```elixir
# Simulate Stripe sending customer.subscription.deleted webhook
webhook_event = %{
  "stripe_event_id" => "evt_test_webhook_cancel_#{System.system_time(:second)}",
  "event_type" => "customer.subscription.deleted",
  "event_data" => %{
    "object" => %{
      "id" => stripe_subscription_id,
      "customer" => stripe_customer_id,
      "status" => "canceled",
      "cancel_at_period_end" => false,
      "canceled_at" => System.system_time(:second)
    }
  }
}

# Process webhook
{:ok, status} = WebhookProcessor.process_event(webhook_event)
IO.puts("Webhook processing status: #{status}")
```

**Expected:**
- Returns `{:ok, :processed}`
- Log message in console: "Subscription canceled, downgraded to PAYG"

### Step 4: Verify Customer Downgraded to PAYG

```elixir
# Refresh customer from database
customer = Repo.get!(Customer, customer.id)

# Check all fields
IO.puts("Subscription type: #{customer.subscription_type}")
IO.puts("Subscription state: #{inspect(customer.subscription_state)}")
IO.puts("Stripe subscription ID: #{inspect(customer.stripe_subscription_id)}")
IO.puts("Cancel at period end: #{customer.subscription_cancel_at_period_end}")
```

**Expected:**
- ✅ `subscription_type: "pay_as_you_go"`
- ✅ `subscription_state: nil`
- ✅ `stripe_subscription_id: nil`
- ✅ `subscription_cancel_at_period_end: false`

### Step 5: Verify Credits Preserved

```elixir
# Check balance
balance = CreditLedger.get_balance(customer)
IO.puts("Current credit balance: #{balance}")
IO.puts("Initial credits: #{initial_credits}")
IO.puts("Credits preserved: #{balance == initial_credits}")

# Check transaction history
transactions = CreditLedger.list_transactions(customer)
IO.inspect(transactions, label: "Credit transactions")
```

**Expected:**
- ✅ `balance == 1000` (credits not reset)
- ✅ Transaction history shows the initial credit
- ✅ No debit transaction from cancellation

### Step 6: Check Billing Event Recorded

```elixir
# Find billing event
billing_event = BillingEvent
  |> where([e], e.stripe_event_id == ^webhook_event["stripe_event_id"])
  |> Repo.one()

IO.inspect(billing_event, label: "Billing event")
```

**Expected:**
- ✅ BillingEvent record exists
- ✅ `event_type: "customer.subscription.deleted"`
- ✅ `customer_id` matches test customer
- ✅ `metadata` contains webhook data

## Cleanup

```elixir
# Delete test customer (cascades to API keys, billing events, etc.)
Repo.delete(Repo.get!(Customer, customer.id))
```

## Testing with Real Stripe Webhook

### Option 1: Stripe CLI

```bash
# Install Stripe CLI if needed
# https://stripe.com/docs/stripe-cli

# Forward webhooks to local server
stripe listen --forward-to localhost:4000/api/v1/webhooks/stripe

# In another terminal, cancel a test subscription
stripe subscriptions cancel sub_xxxxx
```

### Option 2: Stripe Dashboard

1. Create test customer with Pro subscription in Stripe Dashboard
2. Note the customer ID and subscription ID
3. Create corresponding customer in RSOLV database with matching IDs
4. Cancel subscription in Stripe Dashboard
5. Verify webhook received and processed

## Edge Cases to Test

### Test 1: Customer with Rollover Credits
```elixir
# Add credits from multiple sources
CreditLedger.credit(customer, 500, "pro_subscription_payment", %{})
CreditLedger.credit(customer, 300, "payg_credit_purchase", %{})
CreditLedger.credit(customer, 200, "rollover_credit", %{})

# Trigger cancellation webhook
# Verify: All 1000 credits preserved
```

### Test 2: Customer with Used Credits
```elixir
# Add credits, then use some
CreditLedger.credit(customer, 1000, "pro_subscription_payment", %{})
CreditLedger.debit(customer, 400, "fix_execution", %{})

# Balance before: 600
# Trigger cancellation webhook
# Verify: Balance after still 600 (not reset)
```

### Test 3: Duplicate Webhook
```elixir
# Process same webhook twice
WebhookProcessor.process_event(webhook_event)
WebhookProcessor.process_event(webhook_event)

# Verify: Second call returns {:ok, :duplicate}
# Verify: Credits still correct (no double-processing)
```

### Test 4: Already PAYG Customer
```elixir
# Create customer already on PAYG
{:ok, customer} = Customers.register_customer(%{
  subscription_type: "pay_as_you_go",
  # ...
})

# Trigger cancellation webhook (should be idempotent)
# Verify: No errors, customer unchanged
```

## Success Criteria

All of the following must be true:

- [x] Customer `subscription_type` changed to "pay_as_you_go"
- [x] Customer `subscription_state` set to nil
- [x] Customer `stripe_subscription_id` set to nil
- [x] Customer `subscription_cancel_at_period_end` set to false
- [x] **Credit balance PRESERVED** (not reset)
- [x] BillingEvent record created
- [x] Log message includes customer_id and credits_remaining
- [x] Idempotency works (duplicate webhook returns :duplicate)
- [x] No errors when processing the webhook

## Related Files

- `lib/rsolv/billing/webhook_processor.ex` - Main webhook handling logic
- `lib/rsolv/customers.ex` - Customer update functions
- `lib/rsolv/billing/credit_ledger.ex` - Credit management
- `lib/rsolv/billing/billing_event.ex` - Event recording schema
- `priv/repo/migrations/*_add_billing_events.exs` - Database schema

## Related RFCs

- RFC-065: Credit-Based Billing System
- RFC-066: Billing Automation and Webhooks
- RFC-067: Pro Subscription Management

## Troubleshooting

### Webhook not processing
- Check `stripe_customer_id` matches between Stripe and RSOLV
- Verify customer exists in database before webhook
- Check logs for error messages

### Credits reset to zero
- Bug! This is exactly what we're testing against
- Check `CreditLedger` for any debit transactions during cancellation
- Verify `webhook_processor.ex:152-157` doesn't include `credit_balance: 0`

### Duplicate billing events
- This is expected behavior (Stripe sends duplicates)
- Second webhook should return `{:ok, :duplicate}`
- Check unique constraint on `billing_events.stripe_event_id`
