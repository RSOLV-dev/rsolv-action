# RFC-068: Billing Testing Infrastructure

**Status**: Draft
**Created**: 2025-01-12
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