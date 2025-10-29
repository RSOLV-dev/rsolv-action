# Test Support Documentation

This directory contains test helpers, factories, and utilities for the RSOLV test suite.

## Factory Usage

We use [ExMachina](https://hexdocs.pm/ex_machina/readme.html) for test data generation. The factories are located in `test/support/factories/`.

### Customer Factory Traits (RFC-068)

The `CustomerFactory` module provides traits for creating customers in different billing states. These traits implement the test customer states specified in RFC-068.

#### Available Traits

| Trait                | Credits | Payment Method | Subscription | Use Case                    |
|----------------------|---------|----------------|--------------|------------------------------|
| `with_trial_credits` | 5       | No             | Trial        | New signup, no billing      |
| `with_payg`          | 0       | Yes            | PAYG         | Pay-per-fix customer        |
| `with_pro_plan`      | 60      | Yes            | Pro/Active   | Active Pro subscription     |
| `with_past_due`      | Varies  | Yes            | Past Due     | Payment failed (delinquent) |

#### Usage Examples

```elixir
# Import factory functions in your test module
use Rsolv.DataCase
import Rsolv.CustomerFactory

# Basic customer (no credits, no billing)
customer = insert(:customer)

# RFC-068 Trait: Trial customer (5 credits, no payment method)
trial_customer = insert(:customer) |> with_trial_credits()

# RFC-068 Trait: PAYG customer (0 credits, payment method attached)
payg_customer = insert(:customer) |> with_payg()

# RFC-068 Trait: Pro customer (60 credits, active subscription)
pro_customer = insert(:customer) |> with_pro_plan()

# RFC-068 Trait: Delinquent customer (payment failed)
delinquent_customer = insert(:customer) |> with_pro_plan() |> with_past_due()

# Additional helpers
customer_with_billing = insert(:customer) |> with_billing_added()  # 10 credits
partially_used = insert(:customer) |> with_pro_plan_partial_usage()  # 45 credits
```

#### Credit System (RFC-066)

All factory traits now properly set the `credit_balance` field according to RFC-066's unified credit system:

- **Signup**: 5 credits (`with_trial_credits`)
- **Billing added**: +5 bonus credits = 10 total (`with_billing_added`)
- **Pro plan**: 60 credits per billing cycle (`with_pro_plan`)
- **PAYG**: 0 credits, charges per fix (`with_payg`)

Legacy fields (`trial_fixes_limit`, `fixes_quota_this_month`) are also set for backward compatibility during the transition period.

### Additional Helpers

#### Rollover Credits

```elixir
# Pro customer with 10 rollover credits from previous month
customer = insert(:customer) |> with_rollover_credits(10)
```

#### Staff Access

```elixir
# Staff customer for internal testing
staff = insert(:customer) |> with_staff_access()
```

#### Cancellation Scenarios

```elixir
# Scheduled cancellation (cancel_at_period_end)
canceling = insert(:customer) |> with_pro_plan() |> with_cancel_scheduled()

# Immediate cancellation (credits preserved)
cancelled = insert(:customer) |> with_pro_plan() |> with_cancelled_pro()
```

#### Expired Trial

```elixir
# Customer who exhausted trial without adding billing
expired = insert(:customer) |> with_expired_trial()
```

## Test Categories

### DataCase Tests

Use `Rsolv.DataCase` for tests that need database access:

```elixir
defmodule Rsolv.Billing.SubscriptionTest do
  use Rsolv.DataCase  # Provides database transaction and rollback
  import Rsolv.CustomerFactory

  test "creates subscription for customer" do
    customer = insert(:customer) |> with_trial_credits()
    # Your test code here
  end
end
```

### ConnCase Tests

Use `RsolvWeb.ConnCase` for controller/API tests:

```elixir
defmodule RsolvWeb.BillingControllerTest do
  use RsolvWeb.ConnCase
  import Rsolv.CustomerFactory

  test "GET /api/v1/billing/status", %{conn: conn} do
    customer = insert(:customer) |> with_pro_plan()
    # Your test code here
  end
end
```

## Best Practices

1. **Use traits instead of manual setup**: Prefer `insert(:customer) |> with_pro_plan()` over manually setting fields
2. **Test isolation**: Each test gets a clean database transaction (automatically rolled back)
3. **Unique emails**: Factory automatically generates unique emails for parallel tests
4. **Stripe IDs**: Test Stripe IDs are auto-generated with unique integers to prevent conflicts
5. **Timestamps**: Use `DateTime.utc_now()` for consistency

## References

- [ExMachina Documentation](https://hexdocs.pm/ex_machina/readme.html)
- RFC-066: Unified Credit System
- RFC-068: Billing Testing Infrastructure
- `test/support/factories/customer_factory.ex`: Full factory implementation
