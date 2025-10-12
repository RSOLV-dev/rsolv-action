# RFC-066: Stripe Billing Integration

**Status**: Draft
**Created**: 2025-10-12
**Timeline**: 3 weeks
**Dependencies**: Stripe account (have credentials)

## Quick Start

**Stripe Test Keys** (ready to use):
- Publishable: `pk_Prw2ZQauqnSEnJNq7BR7ZsbychP2t`
- Secret: `sk_test_7upzEpVpOJlEJr4HwfSHObSe`

**Pricing** (confirmed):
- PAYG: $15/fix
- Teams: $499/month (60 fixes included)
- Overage: $8/fix after 60

**Files to Create/Modify**:
- `lib/rsolv/billing/stripe.ex` - New Stripe service
- `lib/rsolv/billing.ex` - Existing, needs Stripe integration
- `lib/rsolv_web/controllers/webhook_controller.ex` - Stripe webhooks
- `mix.exs` - Add stripity_stripe dependency

## Summary

Implement Stripe for payment processing, subscription management, and usage-based billing. Zero Stripe code exists despite database fields being ready.

## Integration Notes

### RFC-060 Amendment 001 (Validation Changes)
**Integration Point:** The `track_fix_deployed()` function is triggered after the VALIDATE/MITIGATE phases complete successfully.

**Key Considerations:**
- The validation test location changes (from `.rsolv/tests/` to framework-specific directories) do NOT affect billing
- PhaseDataClient must confirm successful fix deployment before billing usage is tracked
- This is the ONLY touchpoint between the validation and billing workstreams
- Both RFCs can proceed in parallel without conflicts

**Action Required:** When implementing `track_fix_deployed()`, ensure it receives confirmation from PhaseDataClient that the fix was successfully deployed and validated.

## Problem

Cannot collect payments or convert trial users. Database has `stripe_customer_id` fields but no integration code. Manual billing would be unsustainable.

## Solution

### Core Architecture

```
Customer → Stripe Customer → Subscription/PAYG → Usage Tracking → Billing
                ↓                                      ↓
           Payment Method                        Webhooks → Database
```

### Stripe Service Module

```elixir
defmodule Rsolv.Billing.Stripe do
  def create_customer(customer) do
    Stripe.Customer.create(%{
      email: customer.email,
      name: customer.name,
      metadata: %{rsolv_id: customer.id}
    })
  end

  def create_subscription(customer, plan) do
    Stripe.Subscription.create(%{
      customer: customer.stripe_customer_id,
      items: [%{price: price_id(plan)}],
      trial_period_days: trial_days(plan)
    })
  end

  def record_usage(customer, quantity) do
    # For PAYG and overage tracking
    Stripe.UsageRecord.create(
      subscription_item_id(customer),
      %{quantity: quantity, action: "increment"}
    )
  end
end
```

### Billing Context Updates

```elixir
defmodule Rsolv.Billing do
  # INTEGRATION POINT: RFC-060 Amendment 001
  # This function is called after validation/mitigation phases complete.
  # The validation changes (test location/integration) don't affect this,
  # but ensure PhaseDataClient reports fix deployment success before calling.
  def track_fix_deployed(customer, fix) do
    case customer.subscription_plan do
      "trial" ->
        increment_trial_usage(customer)
      "pay_as_you_go" ->
        Stripe.record_usage(customer, 1)
        charge_customer(customer, 15.00)
      "teams" ->
        track_teams_usage(customer)
    end
  end

  def convert_to_paid(customer, plan, payment_method) do
    with {:ok, _} <- Stripe.create_customer(customer),
         {:ok, _} <- Stripe.attach_payment(customer, payment_method),
         {:ok, sub} <- Stripe.create_subscription(customer, plan) do
      update_customer(customer, %{
        stripe_customer_id: sub.customer,
        subscription_plan: plan
      })
    end
  end
end
```

### Webhook Handler

```elixir
defmodule RsolvWeb.WebhookController do
  def stripe(conn, _params) do
    with {:ok, event} <- verify_signature(conn),
         {:ok, _} <- process_event(event) do
      send_resp(conn, 200, "OK")
    end
  end

  defp process_event(%{type: type} = event) do
    case type do
      "invoice.payment_succeeded" -> handle_payment(event)
      "customer.subscription.deleted" -> handle_cancellation(event)
      "invoice.payment_failed" -> handle_failure(event)
      _ -> {:ok, :ignored}
    end
  end
end
```

### Database Schema

```sql
CREATE TABLE subscriptions (
  id UUID PRIMARY KEY,
  customer_id INTEGER REFERENCES customers(id),
  stripe_subscription_id VARCHAR(255) UNIQUE,
  plan VARCHAR(50),
  status VARCHAR(50),
  current_period_end TIMESTAMP
);

CREATE TABLE billing_events (
  id UUID PRIMARY KEY,
  customer_id INTEGER REFERENCES customers(id),
  stripe_event_id VARCHAR(255) UNIQUE,
  event_type VARCHAR(100),
  amount_cents INTEGER,
  metadata JSONB,
  created_at TIMESTAMP DEFAULT NOW()
);
```

## TDD Implementation Tasks

### Week 1: Core Integration (RED-GREEN-REFACTOR)
- [ ] Write failing test: "creates Stripe customer on signup"
- [ ] Add `{:stripity_stripe, "~> 2.17"}` to mix.exs
- [ ] Configure Stripe API keys in runtime.exs
- [ ] Create `lib/rsolv/billing/stripe.ex` service module
- [ ] Write failing test: "validates webhook signatures"
- [ ] Add webhook endpoint at `/webhook/stripe`
- [ ] Set up webhook signature verification
- [ ] Write failing test: "handles Stripe API errors gracefully"
- [ ] Implement customer creation with error handling

### Week 2: Subscription Management (TDD)
- [ ] Create subscription plans in Stripe dashboard
- [ ] Write test: "creates subscription with trial period"
- [ ] Implement subscription creation flow
- [ ] Write test: "attaches payment method to customer"
- [ ] Add payment method management
- [ ] Write test: "handles subscription cancellation"
- [ ] Handle plan changes and cancellations
- [ ] Write test: "processes webhooks idempotently"
- [ ] Process webhook events (payment, cancellation)
- [ ] Create billing_events and subscriptions tables

### Week 3: Usage & Dashboard (TDD)
- [ ] Write test: "tracks usage for PAYG customers"
- [ ] Implement usage tracking for PAYG
- [ ] Write test: "calculates Teams overage correctly"
- [ ] Add Teams plan overage calculation
- [ ] Write test: "dashboard displays current subscription"
- [ ] Create customer billing dashboard at `/billing`
- [ ] Write test: "shows invoice history"
- [ ] Display invoices and payment history
- [ ] Add payment method update UI
- [ ] Test with Stripe test cards

## Testing Requirements

### Test Cards
```
Success: 4242 4242 4242 4242
Decline: 4000 0000 0000 0002
3D Secure: 4000 0025 0000 3155
```

### Unit Tests
```elixir
test "creates Stripe customer on signup"
test "attaches payment method"
test "creates subscription with trial"
test "records usage for PAYG"
test "handles webhook signatures"
```

### Integration Tests
```elixir
test "complete payment flow in test mode"
test "subscription lifecycle (create → cancel)"
test "usage tracking → invoice generation"
```

## Security Measures

1. **PCI Compliance**: Use Stripe Checkout, never touch card data
2. **Webhook Security**: Verify signatures, implement idempotency
3. **API Keys**: Environment variables, separate test/prod
4. **Audit Trail**: Log all billing operations

## Success Metrics

- **Payment Success**: > 95%
- **Webhook Processing**: < 1 second
- **Failed Payment Recovery**: > 50%
- **Zero Security Incidents**

## Risks & Mitigation

| Risk | Impact | Mitigation |
|------|--------|------------|
| Payment failures | High | Retry logic, dunning process |
| Webhook downtime | High | Queue, retry, monitoring |
| Overcharging | Critical | Extensive testing, safeguards |

## Rollout Plan

1. **Test Mode**: Complete integration with test keys (Week 1-2)
2. **Beta Testing**: 5 customers with discounts (Week 3)
3. **Production**: Enable for all customers (Week 4)

## Next Steps

1. Add stripity_stripe to dependencies
2. Configure test API keys
3. Create Stripe service module
4. Deploy webhook endpoint to staging