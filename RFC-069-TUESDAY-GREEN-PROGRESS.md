# RFC-069 Tuesday GREEN Phase Progress

**Date**: 2025-10-31
**TDD Phase**: GREEN (In Progress)
**Status**: 6/11 tests passing (54%)

## Overview

Moved from RED phase (10/11 tests failing) to GREEN phase with significant progress on Mox best practices and factory trait persistence.

## Test Status

### ✅ Passing Tests (6)

1. **Trial Signup to First Fix**: Complete journey from signup → provision → first fix deployment
2. **Marketplace Installation Flow**: GitHub Marketplace customer provisioning
3. **Payment Method Addition with Consent**: Customer adds payment method, receives bonus credits
4. **Payment Addition without Consent Rejected**: Proper error handling for missing consent
5. **Pro Subscription Creation and Renewal**: Customer subscribes to Pro, receives 60 credits
6. **Pro Subscription Renewal**: Additional 60 credits on monthly renewal

### ❌ Failing Tests (5)

#### 1. Trial Customer Blocked When No Credits
**File**: `test/e2e/customer_journey_test.exs:151`
**Issue**: Customer has 4 credits instead of expected 0
**Root Cause**: Factory trait sets credit_balance: 5, then test tries to override to 0, but credit persists
**Expected**: `{:error, :no_billing_info}`
**Actual**: `{:ok, transaction}` with balance_after: 4

#### 2. Trial to Paid Conversion
**File**: `test/e2e/customer_journey_test.exs:169`
**Issue**: Source assertion mismatch - looking for "stripe_charge" but implementation uses "purchased"
**Status**: Partially fixed (source names corrected) but still failing on charge detection

#### 3. Pro Customer Charges $15
**File**: `test/e2e/customer_journey_test.exs:204`
**Issue**: needs investigation
**Status**: Test setup appears correct, need to verify charge flow

#### 4. Immediate Cancellation
**File**: `test/e2e/customer_journey_test.exs:357`
**Issue**: Enum.each loop consuming 45 credits leaves balance > 0
**Expected**: balance == 0 after consuming all 45 credits
**Actual**: balance still has credits remaining

#### 5. End-of-Period Cancellation
**File**: `test/e2e/customer_journey_test.exs:409`
**Issue**: Similar to #4 - loop leaves 15 credits instead of 0
**Expected**: balance == 0
**Actual**: balance == 15

## Key Achievements

### Mox Best Practices Applied

- ✅ Removed ALL redundant `expect()` calls
- ✅ Using `stub_with()` exclusively for default implementations
- ✅ Understanding: `expect()` should ONLY assert function calls, not provide return values

### Stripe Mock Implementation

- ✅ Added raw Stripe API methods to `StripeClientBehaviour`:
  - `create/1`, `retrieve/1`, `update/2`, `attach/1`, `cancel/1`
- ✅ Updated `StripeTestStub` to implement both:
  - Behaviour interface methods (`create_customer/1`, etc.)
  - Raw API methods (Stripe.Customer.create/1, etc.)
- ✅ Fixed polymorphic `create/1` to handle both Customer and Subscription creation

### Factory Trait Persistence

- ✅ Created `insert_with_trait/2` helper to properly persist factory changes
- ✅ Fixed DateTime precision issues (microseconds → seconds)
- ✅ Truncates `payment_method_added_at` and `billing_consent_at` for DB compatibility

### Source Name Corrections

- ✅ "subscription_payment" → "pro_subscription_payment"
- ✅ "consumed" → "fix_deployed"
- ✅ "billing_added" → "trial_billing_added"
- ✅ Charge source: "purchased" (verified in UsageTracking implementation)

### Email Domain Fixes

- ✅ example.com → test.rsolv.dev (avoids Burnex disposable email detection)

## Remaining Issues

### 1. Factory Trait Credit Persistence

**Problem**: `insert_with_trait` sets credit_balance, then `Map.put` overrides in-memory but DB value persists

**Current Pattern** (problematic):
```elixir
customer = insert_with_trait(:customer, &with_trial_credits/1) |> Map.put(:credit_balance, 0)
customer = Repo.update!(Ecto.Changeset.change(customer, credit_balance: 0))
```

**Solution**: Skip trait application and set credits directly in insert_with_trait, OR create separate factory trait for zero-credit customers

### 2. Enum.each Credit Consumption Loops

**Problem**: Loops designed to consume N credits are leaving credits remaining

**Pattern**:
```elixir
Enum.each(1..45, fn i ->
  fix = %{id: i, vulnerability_id: "VULN-#{i}", status: "merged"}
  assert {:ok, %{customer: updated_customer}} = Billing.track_fix_deployed(customer_ref, fix)
  customer_ref = updated_customer
end)
```

**Issue**: `customer_ref` reassignment inside `Enum.each` doesn't update outer scope variable
**Solution**: Use `Enum.reduce` instead to properly thread state:
```elixir
customer_ref = Enum.reduce(1..45, downgraded_customer, fn i, acc_customer ->
  fix = %{id: i, vulnerability_id: "VULN-#{i}", status: "merged"}
  {:ok, %{customer: updated_customer}} = Billing.track_fix_deployed(acc_customer, fix)
  updated_customer
end)
```

### 3. Source Assertion Mismatches

**Status**: Mostly fixed
**Remaining**: Verify "stripe_charge" vs "purchased" in trial-to-paid conversion test

## Git Commit History

```bash
e19dd004 - [RFC-069 Tuesday GREEN] Fix Mox testing patterns and factory trait persistence
```

## Next Steps

1. **Fix Enum.reduce loops** - Replace all `Enum.each` with `Enum.reduce` for state threading
2. **Fix factory trait overrides** - Create zero-credit factory trait or modify insert pattern
3. **Verify charge source** - Confirm "purchased" is correct source in all charge assertions
4. **Add @impl annotations** - Clean up remaining compiler warnings
5. **Run full suite** - Verify 11/11 tests passing
6. **Document GREEN completion** - Create final summary document

## Testing Commands

```bash
# Run all E2E tests
mix test test/e2e/customer_journey_test.exs

# Run specific test
mix test test/e2e/customer_journey_test.exs:151

# Run with trace
mix test test/e2e/customer_journey_test.exs:151 --trace
```

## Key Learnings

1. **Mox Expectations**: `expect()` is for assertions, `stub_with()` for defaults
2. **Factory Traits**: Don't persist automatically - need explicit helper
3. **DateTime Precision**: PostgreSQL :utc_datetime doesn't support microseconds
4. **Enum.each State**: Doesn't update outer scope variables - use reduce
5. **Behaviour Completeness**: Mock behaviour must include ALL methods called by production code
