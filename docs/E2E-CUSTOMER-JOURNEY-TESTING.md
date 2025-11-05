# E2E Customer Journey Testing

**Status**: ✅ Implemented and Passing
**Test File**: `test/e2e/customer_journey_test.exs`
**Last Updated**: 2025-11-04
**RFC Reference**: RFC-064 Week 5 - E2E Test Suite Implementation

## Overview

The E2E Customer Journey Test Suite provides comprehensive testing of the complete customer lifecycle from signup through billing, covering all critical user flows including trial signup, payment method addition, Pro subscription management, and subscription cancellations.

## Test Coverage

### 1. Trial Signup to First Fix (2 tests)
- ✅ Complete trial journey: signup → provision → first fix deployment
- ✅ Trial customer blocked when no credits and no billing

**Verification Points**:
- Customer creation with correct attributes
- API key generation (starts with `rsolv_`)
- Stripe customer creation
- Credit allocation (5 trial credits)
- Credit transaction recording
- Fix deployment and credit consumption
- Usage summary API

### 2. Trial to Paid Conversion (1 test)
- ✅ Trial customer adds payment method and gets charged when credits exhausted

**Verification Points**:
- Payment method addition with billing consent
- Stripe customer creation on payment add
- Bonus credits granted (5 additional credits)
- Subscription type transition (trial → pay_as_you_go)
- Credit consumption tracking
- Stripe charge creation ($29 PAYG rate)
- Transaction recording

### 3. Marketplace Installation Flow (1 test)
- ✅ Customer installs from GitHub Marketplace and completes onboarding

**Verification Points**:
- Marketplace source tracking
- Standard provisioning flow
- API key delivery for GitHub Actions
- Metadata tracking

### 4. Payment Method Addition (2 tests)
- ✅ Customer adds payment method with explicit billing consent
- ✅ Payment addition without consent is rejected

**Verification Points**:
- Consent requirement enforcement
- Payment method attachment
- Bonus credit allocation
- State preservation on rejection

### 5. Pro Subscription Creation and Renewal (3 tests)
- ✅ Customer subscribes to Pro plan and receives credits on payment
- ✅ Pro subscription renewal grants another 60 credits
- ✅ Pro customer charges $15 for additional fixes beyond credits

**Verification Points**:
- Subscription creation
- Credit allocation (60 credits per month)
- Renewal credit grants
- Pro overage rate ($15 vs $29 PAYG)
- Transaction metadata

### 6. Subscription Cancellation (2 tests)
- ✅ Immediate cancellation downgrades to PAYG and changes rate to $29
- ✅ End-of-period cancellation maintains Pro pricing until period ends

**Verification Points**:
- Immediate vs scheduled cancellation
- Rate changes (Pro $15 → PAYG $29)
- Credit preservation
- Subscription state tracking
- Cancellation timing logic

## Test Statistics

- **Total Tests**: 11 (covering 6 test scenarios)
- **Current Status**: 11/11 passing (100%)
- **Test Duration**: ~0.6 seconds
- **Test Mode**: `async: false` (sequential execution for state isolation)

## Running the Tests

### Local Development

**Prerequisites**:
- PostgreSQL running and accessible
- Elixir 1.18+ installed
- Dependencies installed (`mix deps.get`)
- Test database created and migrated

**Run E2E tests only**:
```bash
# From project root
mix test test/e2e/customer_journey_test.exs
```

**Run with trace output** (detailed test execution):
```bash
mix test test/e2e/customer_journey_test.exs --trace
```

**Run specific test**:
```bash
# By line number
mix test test/e2e/customer_journey_test.exs:131

# By test name pattern
mix test test/e2e/customer_journey_test.exs --only "trial customer blocked"
```

### In Git Worktrees

**IMPORTANT**: When working in a git worktree, always install dependencies first:

```bash
# REQUIRED - worktrees have independent _build/ and deps/ directories
mix deps.get

# Compile dependencies
mix compile

# Run tests
mix test test/e2e/customer_journey_test.exs
```

See `CLAUDE.md` Git Worktree Workflow section for more details.

### In CI/CD Pipeline

Tests run automatically in GitHub Actions as part of the main test suite:

```yaml
# .github/workflows/elixir-ci.yml
- name: Run tests (partition ${{ matrix.partition }}/4)
  run: mix test --trace --partitions 4 --cover
```

**CI Configuration**:
- Uses PostgreSQL 16 service container
- Runs tests in 4 parallel partitions for speed
- Collects coverage data
- Test failures are **BLOCKING** (must be 100% green to merge)

**View CI Results**:
- Go to: https://github.com/RSOLV-dev/rsolv/actions
- Select workflow run for your branch
- View "Test Suite" job results
- Download test artifacts if failures occur

## Test Architecture

### Test Setup

**Test Framework**: ExUnit with DataCase
**Database**: Isolated test database with Ecto.Sandbox
**Mocking**: Mox for Stripe API (using StripeTestStub)
**Email**: ConvertKit stubs for email delivery

**Setup Flow**:
```elixir
setup do
  # Stripe API mocking
  stub_with(Rsolv.Billing.StripeMock, Rsolv.Billing.StripeTestStub)

  # Stripe charge mock
  stub(Rsolv.Billing.StripeChargeMock, :create, ...)

  # Payment method mock
  stub(Rsolv.Billing.StripePaymentMethodMock, :attach, ...)

  # Subscription mock
  stub(Rsolv.Billing.StripeSubscriptionMock, :create, ...)

  # Email mocking
  stub_convertkit_success()

  :ok
end
```

### Factory Usage

Tests use `insert/1` and `insert_with_trait/1` from ExMachina:

```elixir
# Insert customer with trait
customer = insert_with_trait(:customer, &with_trial_credits/1)
customer = insert_with_trait(:customer, &with_billing_added/1)
customer = insert_with_trait(:customer, &with_pro_plan/1)

# Available traits (from Rsolv.CustomerFactory)
- with_trial_credits/1      # 5 credits, trial state
- with_billing_added/1      # 10 credits, has payment method
- with_pro_plan/1           # 60 credits, Pro subscription active
- with_payg/1               # 0 credits, pay-as-you-go
- with_past_due/1           # Payment failed state
```

### Helper Functions

**Persistent Factory Trait Helper**:
```elixir
# Factory traits return maps, not persisted records
# Use this helper to persist trait changes to database
defp insert_with_trait(factory_name, trait_fun) do
  customer = insert(factory_name)
  trait_customer = trait_fun.(customer)

  changes = Map.take(trait_customer, [:credit_balance, :subscription_type, ...])
  Repo.update!(Ecto.Changeset.change(customer, changes))
end
```

This ensures factory trait modifications (like setting credit_balance) are actually saved to the database.

## Test Data

### Test Credentials (from seeds)
```elixir
# These exist in test database after seeds run
admin@rsolv.dev          / AdminP@ssw0rd2025!
staff@rsolv.dev          / StaffP@ssw0rd2025!
test@example.com         / TestP@ssw0rd2025!
demo@example.com         / DemoP@ssw0rd2025!
enterprise@bigcorp.com   / EnterpriseP@ssw0rd2025!
```

### Test Stripe Objects

All Stripe test objects use the `test_` prefix:
- Customers: `cus_test_*`
- Subscriptions: `sub_test_*`
- Payment methods: `pm_test_*`
- Charges: `ch_test_*`

**Example**:
```json
{
  "stripe_customer_id": "cus_test_d9cAK2QBVlA",
  "stripe_subscription_id": "sub_test_abc123",
  "stripe_payment_method_id": "pm_test_456def"
}
```

### Pricing Constants

```elixir
# Trial credits
trial_signup: 5 credits
trial_billing_added: 5 credits (bonus)

# Subscription types
trial: 5 credits initial
pay_as_you_go: $29.00 per fix
pro: 60 credits/month + $15.00 per additional fix

# Pro subscription
monthly_cost: $599.00
monthly_credits: 60
overage_rate: $15.00 per fix
```

## Troubleshooting

### Common Issues

**1. Test Failures Due to Missing Dependencies**

```bash
# Error: "the dependency is not available, run mix deps.get"
# Solution: Install dependencies (especially in git worktrees)
mix deps.get
mix compile
```

**2. Database Connection Errors**

```bash
# Error: "connection not available and request was dropped"
# Solution: Ensure PostgreSQL is running
brew services start postgresql@16    # macOS
sudo systemctl start postgresql      # Linux
docker-compose up -d postgres        # Docker
```

**3. Test Pollution (State Leaking Between Tests)**

```elixir
# E2E tests use async: false to prevent state conflicts
# If seeing unexpected state, verify:
# 1. Tests are sequential (async: false)
# 2. Factory traits are properly isolated
# 3. Database is cleaned between test runs
```

**4. Stripe Mock Errors**

```bash
# Error: "Mox.UnexpectedCallError"
# Solution: Verify Stripe mocks are stubbed in setup block
# Check: lib/rsolv/billing/stripe_test_stub.ex
```

**5. Factory Trait Not Persisting**

```elixir
# Problem: trait_customer changes not in database
# Wrong:
customer = with_trial_credits(insert(:customer))

# Correct:
customer = insert_with_trait(:customer, &with_trial_credits/1)
```

### Debug Tips

**Enable verbose logging**:
```bash
# Run with trace output
mix test test/e2e/customer_journey_test.exs --trace

# Check database state mid-test
require IEx; IEx.pry()
Rsolv.Repo.all(Rsolv.Customers.Customer)
```

**Check test isolation**:
```bash
# Run single test to isolate issue
mix test test/e2e/customer_journey_test.exs:131

# Run tests in different order
mix test test/e2e/customer_journey_test.exs --seed 12345
```

**Verify Stripe mocks**:
```bash
# Check mock expectations are set
require IEx; IEx.pry()
Mox.verify!()
```

## Maintenance

### Adding New E2E Tests

1. **Identify the user journey** to test (e.g., "Free trial to Pro upgrade")

2. **Write the test following TDD**:
```elixir
describe "New Journey" do
  test "user flow description" do
    # ARRANGE: Setup test data
    customer = insert_with_trait(:customer, &with_trial_credits/1)

    # ACT: Perform the action
    assert {:ok, result} = YourModule.your_function(customer, params)

    # ASSERT: Verify the outcome
    assert result.new_state == expected_value

    # ASSERT: Verify side effects
    transactions = CreditLedger.list_transactions(customer)
    assert length(transactions) == expected_count
  end
end
```

3. **Update this documentation** with:
   - Test name and description
   - Verification points
   - Expected behavior
   - Any new test data requirements

### Updating Test Data

**When changing pricing**:
1. Update test assertions for new rates
2. Update this documentation's Pricing Constants
3. Update factory traits if needed
4. Verify all charge assertions match new rates

**When adding new subscription types**:
1. Add factory trait (e.g., `with_enterprise_plan/1`)
2. Add test cases for new type
3. Update test data section in docs

### Test Performance

Current benchmarks (as of 2025-11-04):
- Total duration: ~0.6 seconds
- Average per test: ~55ms
- Slowest test: "complete trial journey" (~163ms)

If tests slow down significantly:
1. Check for N+1 database queries
2. Verify Stripe mocks aren't making real API calls
3. Consider parallelization (currently sequential)
4. Profile with `mix profile.fprof`

## Integration with RFC-064 Week 5

This test suite satisfies all RFC-064 Week 5 requirements:

✅ **Test Flow**:
1. Customer signup via `/api/v1/customers/onboard` ✓
2. API key generation and return ✓
3. Simulate RSOLV-action scan using API key ✓
4. Credit deduction for scan ✓
5. Fix deployment tracking ✓
6. Billing charge creation ✓
7. Usage summary API verification ✓

✅ **Implementation**:
- Location: `test/e2e/customer_journey_test.exs` ✓
- Uses Stripe test mode (via mocks) ✓
- Tests both trial and Pro plan customers ✓
- Verifies credit balance updates correctly ✓
- Verifies Stripe charges created ✓

✅ **Acceptance Criteria**:
- Tests run in CI pipeline ✓
- Covers happy path end-to-end ✓
- Tests fail appropriately on billing errors ✓
- Documentation for running locally ✓ (this document)

✅ **Launch Gate**:
- E2E tests must pass for Week 6 public launch ✓
- Current status: 11/11 passing (100%) ✓

## Related Documentation

- [RFC-064: Billing & Provisioning Master Plan](../RFCs/RFC-064-BILLING-PROVISIONING-MASTER-PLAN.md)
- [RFC-065: Automated Customer Provisioning](../RFCs/RFC-065-AUTOMATED-CUSTOMER-PROVISIONING.md)
- [RFC-066: Stripe Billing Integration](../RFCs/RFC-066-STRIPE-BILLING-INTEGRATION.md)
- [RFC-069: Integration Week Plan](../RFCs/RFC-069-INTEGRATION-WEEK-PLAN.md)
- [Week 3 E2E Findings](../projects/go-to-market-2025-10/WEEK-3-DAY-1-E2E-FINDINGS.md)
- [Integration Test Status](./E2E-INTEGRATION-STATUS.md)

## Support

**Questions or Issues?**
- Check existing test failures in CI: https://github.com/RSOLV-dev/rsolv/actions
- Review troubleshooting section above
- Check Vibe Kanban for related tasks
- See CLAUDE.md for development best practices

**Test Improvements?**
- Open discussion in RFC-069 issue
- Follow TDD methodology (RED → GREEN → REFACTOR)
- Ensure new tests are isolated and deterministic
- Update this documentation with changes

---

**Last Updated**: 2025-11-04
**Test Suite Version**: v1.0
**Status**: ✅ Production Ready
