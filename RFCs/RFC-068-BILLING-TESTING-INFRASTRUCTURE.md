# RFC-068: Billing Testing Infrastructure

**Status**: Draft
**Created**: 2025-10-12
**Timeline**: Parallel with development
**Purpose**: Ensure billing reliability through comprehensive testing

## Quick Start

**Stripe Test Credentials**:
- API Key: `sk_test_7upzEpVpOJlEJr4HwfSHObSe`
- Publishable: `pk_Prw2ZQauqnSEnJNq7BR7ZsbychP2t`

**Test Cards**:
- Success: `4242 4242 4242 4242`
- Decline: `4000 0000 0000 0002`

## Summary

Build comprehensive testing for billing system. Must achieve 95% coverage for billing code, 100% for webhooks.

## Testing Architecture

```
Unit Tests → Integration Tests → Staging → Production
     ↓              ↓                ↓          ↓
  Mocks         Test DB         Stripe Test   Monitoring
```

## Monitoring & Telemetry Testing

Following patterns established in RFC-060-MONITORING-COMPLETION-REPORT:

### Required Test Cases

```elixir
test "emits telemetry on subscription creation"
test "emits telemetry on payment success"
test "emits telemetry on payment failure"
test "tracks usage in Prometheus metrics"
test "Grafana dashboard displays billing metrics"
test "billing event metrics have correct tags"
```

### Implementation Pattern

Use the same `:telemetry.execute/3` pattern established for test integration:

```elixir
:telemetry.execute(
  [:rsolv, :billing, :subscription_created],
  %{amount: amount, duration: duration},
  %{customer_id: customer.id, plan: plan, status: "success"}
)

:telemetry.execute(
  [:rsolv, :billing, :payment_processed],
  %{amount_cents: amount, duration: duration},
  %{customer_id: customer.id, status: status, payment_method: method}
)

:telemetry.execute(
  [:rsolv, :billing, :usage_tracked],
  %{quantity: quantity},
  %{customer_id: customer.id, plan: plan, resource_type: "fix"}
)
```

### Metric Definition Pattern

Create `lib/rsolv/prom_ex/billing_plugin.ex` following the structure in `validation_plugin.ex`:

```elixir
defmodule Rsolv.PromEx.BillingPlugin do
  use PromEx.Plugin

  @impl true
  def event_metrics(_opts) do
    Event.build(:billing_metrics, [
      counter(
        [:rsolv, :billing, :subscription_created, :total],
        event_name: [:rsolv, :billing, :subscription_created],
        description: "Total subscriptions created",
        tags: [:customer_id, :plan, :status]
      ),
      distribution(
        [:rsolv, :billing, :payment_processed, :amount, :cents],
        event_name: [:rsolv, :billing, :payment_processed],
        measurement: :amount_cents,
        description: "Payment amounts processed",
        tags: [:customer_id, :status, :payment_method],
        reporter_options: [buckets: [100, 500, 1500, 5000, 10_000, 50_000]]
      )
    ])
  end
end
```

### Dashboard Creation

See `/tmp/rfc060-test-integration-dashboard.json` for Grafana dashboard JSON structure. Create similar dashboard for billing with panels:
- Subscription creation rate
- Payment success/failure rate
- Revenue by plan
- Usage tracking metrics
- Customer conversion funnel

### Test Coverage Requirements

**Billing telemetry tests must achieve:**
- 100% coverage of telemetry emission points
- Verification that all billing events emit telemetry
- Validation of tag completeness and correctness
- Prometheus metric collection verification

**Reference Implementation:** `lib/rsolv_web/controllers/api/v1/test_integration_controller.ex` lines 89-134 for telemetry emission patterns.

## 1. Docker Compose Setup

```yaml
# docker-compose.test.yml
version: '3.8'
services:
  postgres_test:
    image: postgres:14
    environment:
      POSTGRES_DB: rsolv_test
    ports: ["5433:5432"]

  stripe_cli:
    image: stripe/stripe-cli
    command: listen --forward-to localhost:4000/webhook/stripe
    environment:
      STRIPE_API_KEY: sk_test_7upzEpVpOJlEJr4HwfSHObSe

  mailcatcher:
    image: sj26/mailcatcher
    ports: ["1080:1080", "1025:1025"]
```

## 2. Test Suites Required

### Unit Tests
- Creates Stripe customer on signup
- Attaches payment method
- Creates subscription with trial
- Records usage for PAYG
- Calculates Teams overage correctly
- Handles payment failures gracefully

### Integration Tests
- Trial to paid conversion journey
- Webhook processing and idempotency
- Usage billing for PAYG/Teams

### Load Tests
- 100 concurrent provisioning requests
- 1000 webhooks per minute
- 10000 active subscriptions

### Security Tests
- Never logs payment card numbers
- Prevents SQL injection
- Enforces rate limiting
- Validates webhook signatures
- Encrypts sensitive data

## 3. Stripe Mock Service

```elixir
defmodule Rsolv.StripeMock do
  def create_customer(%{email: "fail@test.com"}), do: {:error, "Card declined"}
  def create_customer(_), do: {:ok, customer_fixture()}

  def create_subscription(%{customer: "cus_no_payment"}), do: {:error, "No payment method"}
  def create_subscription(_), do: {:ok, subscription_fixture()}
end
```

## 4. Staging Environment

Test customers in various states:
- Trial customer (3/10 fixes used)
- Trial expired (10/10 fixes)
- PAYG active
- Teams with usage
- Past due subscription
- Cancelled subscription

## 5. Coverage Requirements

| Module | Required | Priority |
|--------|----------|----------|
| Billing.Stripe | 95% | Critical |
| Webhook Handlers | 100% | Critical |
| Usage Tracking | 95% | Critical |
| Provisioning | 95% | Critical |

## Implementation Tasks

### Week 1: Foundation
- [ ] Set up docker-compose.test.yml
- [ ] Create test factories and fixtures
- [ ] Implement StripeMock service
- [ ] Configure test environment variables
- [ ] Write first unit tests
- [ ] Set up coverage reporting

### Week 2: Test Development
- [ ] Complete unit test suite (50+ tests)
- [ ] Write integration test scenarios
- [ ] Implement webhook testing
- [ ] Add security test suite
- [ ] Create load testing scripts
- [ ] Set up CI pipeline

### Week 3: Staging & Monitoring
- [ ] Deploy staging environment
- [ ] Configure Stripe test mode
- [ ] Create staging test data
- [ ] Implement test monitoring
- [ ] Add alerting for failures
- [ ] Document test procedures

## Success Metrics

- **Coverage**: 95% for billing, 100% for webhooks
- **CI Speed**: < 5 minutes
- **Test Reliability**: < 1% flakiness
- **Staging Uptime**: 99.9%

## Testing Checklist

Before any billing deployment:
- [ ] All unit tests passing
- [ ] Integration tests passing
- [ ] Staging tests complete
- [ ] Coverage targets met
- [ ] Security scan clean
- [ ] Load test passed

## Next Steps

1. Create docker-compose.test.yml
2. Implement StripeMock
3. Write first test suite
4. Deploy staging environment