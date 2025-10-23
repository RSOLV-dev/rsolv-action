# Week 0: Database Schema Verification

**Status**: ✅ Complete
**Date**: 2025-10-23
**Purpose**: Verify current schema and identify potential conflicts between RFC-065 and RFC-066

## Executive Summary

**Approach**: Each RFC creates its own migration in its respective workstream.

**Why separate migrations work**:
- ✅ Migrations have unique timestamps - no filename conflicts
- ✅ Each RFC owns its schema changes independently
- ✅ Easier to review per-RFC
- ✅ Can be merged in any order
- ✅ Clear separation of concerns

**Critical Finding**: **One naming conflict identified and resolved below**

---

## Current Database Schema

### `customers` table

**Existing fields** (from `20250909163203_consolidate_customer_schema.exs`):
- `subscription_plan` (string) - **⚠️ RFC-066 wants to rename this**
- `subscription_status` (string) - **⚠️ RFC-066 wants to rename this**
- `trial_fixes_used` (integer)
- `trial_fixes_limit` (integer)
- `stripe_customer_id` (string)
- `rollover_fixes` (integer)
- `payment_method_added_at` (utc_datetime)
- `trial_expired_at` (utc_datetime)
- `fixes_used_this_month` (integer)
- `fixes_quota_this_month` (integer)
- `has_payment_method` (boolean)
- `password_hash` (string)
- `is_staff` (boolean)
- `admin_level` (string)
- `name`, `email`, `monthly_limit`, `current_usage`, `active`, `metadata`

### `api_keys` table

**Existing fields** (from `20250703021615_create_api_keys.exs`):
- `key` (string) - **⚠️ RFC-065 wants to rename this**
- `name` (string)
- `customer_id` (references customers)
- `permissions` (array of strings)
- `last_used_at` (naive_datetime)
- `expires_at` (naive_datetime)
- `active` (boolean)

---

## RFC-065 Changes (Customer Provisioning)

**Migration will add to `customers` table**:
- `auto_provisioned` (boolean, default: false)
- `wizard_preference` (string, default: "auto")
- `first_scan_at` (utc_datetime)

**Migration will modify `api_keys` table**:
- Add `key_hash` column (string)
- Backfill: `key_hash = SHA256(key)` for existing keys
- Drop `key` column (plaintext removed)

**Migration will create**:
- `customer_onboarding_events` table

**No conflicts** - RFC-065 adds new fields only.

---

## RFC-066 Changes (Stripe Billing)

**Migration will rename on `customers` table**:
- `subscription_plan` → `subscription_type` ⚠️
- `subscription_status` → `subscription_state` ⚠️

**Migration will add to `customers` table**:
- `credit_balance` (integer, default: 0)
- `stripe_payment_method_id` (string)
- `stripe_subscription_id` (string)
- `billing_consent_given` (boolean, default: false)
- `billing_consent_at` (utc_datetime)
- `subscription_cancel_at_period_end` (boolean, default: false)

**Migration will create**:
- `credit_transactions` table
- `subscriptions` table
- `billing_events` table

**No conflicts** - RFC-066 renames existing fields and adds new ones.

---

## Critical Conflict Identified & Resolved

### ⚠️ Naming Conflict: `subscription_plan` vs `subscription_type`

**Current schema** uses `subscription_plan` (from earlier migration).
**RFC-066** wants to rename it to `subscription_type`.

**Problem**: If RFC-065 code references `subscription_plan` and RFC-066 renames it, code will break.

### ✅ Resolution Strategy

**Option 1: RFC-066 migration runs first** (RECOMMENDED)
- RFC-066 migration has earlier timestamp
- Renames `subscription_plan` → `subscription_type`
- Renames `subscription_status` → `subscription_state`
- RFC-065 code uses `subscription_type` in its implementation
- Both RFCs coordinate on field names

**Option 2: Update Ecto schema simultaneously**
- Both RFCs update `lib/rsolv/customers/customer.ex` to use new names
- Merge order doesn't matter because schema changes are in application code

**Recommended: Option 1**
- Cleaner separation
- Database schema matches RFC-066 naming
- RFC-065 uses correct names from the start

---

## Coordination Guidelines for RFC Teams

### RFC-065 Team (Customer Provisioning)

**Safe to proceed with**:
- Creating `customer_onboarding_events` table
- Adding `auto_provisioned`, `wizard_preference`, `first_scan_at` to customers
- Modifying `api_keys` table (hashing)

**Must coordinate on**:
- Use `subscription_type` (not `subscription_plan`) in code
- Use `subscription_state` (not `subscription_status`) in code
- Set `subscription_type: "trial"` for new customers (RFC-066 terminology)

**Reference in code**:
```elixir
# RFC-065 customer provisioning code should use:
%{
  subscription_type: "trial",  # NOT subscription_plan
  subscription_state: nil,      # NOT subscription_status
  credit_balance: 5             # RFC-066 will add this field
}
```

### RFC-066 Team (Stripe Billing)

**Safe to proceed with**:
- Renaming `subscription_plan` → `subscription_type`
- Renaming `subscription_status` → `subscription_state`
- Creating `credit_transactions`, `subscriptions`, `billing_events` tables
- Adding billing fields to customers

**Must coordinate on**:
- Rename migrations should run before RFC-065 code deployment
- Document that `subscription_type` values are: "trial", "pay_as_you_go", "pro"
- Document that `subscription_state` is NULL for trial/PAYG, Stripe states for Pro

**Reference in code**:
```elixir
# RFC-066 billing code uses:
%{
  subscription_type: "trial" | "pay_as_you_go" | "pro",
  subscription_state: nil | "active" | "past_due" | "canceled" | ...,
  credit_balance: 5  # Unified credit system
}
```

---

## Migration Execution Order

### Development Environment
Either order works, but **recommended**:

1. **RFC-066 migration first** (renames fields)
   - Timestamp: `202510XX_create_billing_tables.exs`
   - Renames: `subscription_plan` → `subscription_type`
   - Renames: `subscription_status` → `subscription_state`
   - Adds billing fields and tables

2. **RFC-065 migration second** (adds provisioning fields)
   - Timestamp: `202510YY_add_customer_onboarding_fields.exs` (where YY > XX)
   - Adds provisioning fields
   - Modifies api_keys (hashing)
   - Uses `subscription_type` in backfill

### Integration (Week 5 - RFC-069)
When merging to main:
- Migrations run in timestamp order automatically
- No manual coordination needed
- Both teams' changes apply cleanly

---

## Schema After Both Migrations

### `customers` table (final state)

**Renamed fields**:
- `subscription_type` (was subscription_plan) - Values: "trial", "pay_as_you_go", "pro"
- `subscription_state` (was subscription_status) - Values: NULL, "active", "past_due", etc.

**New fields from RFC-066**:
- `credit_balance` (integer)
- `stripe_customer_id` (string, unique)
- `stripe_payment_method_id` (string)
- `stripe_subscription_id` (string)
- `billing_consent_given` (boolean)
- `billing_consent_at` (utc_datetime)
- `subscription_cancel_at_period_end` (boolean)

**New fields from RFC-065**:
- `auto_provisioned` (boolean)
- `wizard_preference` (string)
- `first_scan_at` (utc_datetime)

### `api_keys` table (final state)

**Modified by RFC-065**:
- `key_hash` (string, unique) - SHA256 hashes (was `key` plaintext)
- All other fields unchanged

### New tables

**From RFC-066**:
- `credit_transactions` - Audit trail for credits
- `subscriptions` - Pro subscription tracking
- `billing_events` - Webhook processing (idempotency)

**From RFC-065**:
- `customer_onboarding_events` - Provisioning audit trail

---

## Backfill Strategy

### RFC-066 Backfill (in migration)
```sql
-- Set default values for existing customers
UPDATE customers
SET credit_balance = 5,
    subscription_type = COALESCE(subscription_type, 'trial'),
    subscription_state = NULL
WHERE credit_balance = 0;
```

### RFC-065 Backfill (in migration)
```sql
-- Hash existing API keys
UPDATE api_keys
SET key_hash = ENCODE(SHA256(key::bytea), 'hex')
WHERE key_hash IS NULL;

-- Set existing customers as not auto-provisioned
UPDATE customers
SET auto_provisioned = false
WHERE auto_provisioned IS NULL;
```

---

## Testing Strategy

### Each RFC Tests Independently

**RFC-065 tests**:
- Create customer with `subscription_type: "trial"`
- API key hashing works
- Onboarding events recorded

**RFC-066 tests**:
- Credit transactions work
- Billing events processed
- Subscription management works

### Integration Tests (Week 5)
- Customer provisioning → credit balance = 5
- Add billing → credit balance = 10
- Subscribe to Pro → credit balance = 70 (60 + 10)
- Deploy fix → credit balance decrements

---

## No Merge Conflicts Expected

### Why migrations won't conflict

1. **Different filenames**: Timestamps ensure uniqueness
   - RFC-065: `202510XX_add_customer_onboarding_fields.exs`
   - RFC-066: `202510YY_create_billing_tables.exs`

2. **Different tables created**: No overlap
   - RFC-065: `customer_onboarding_events`
   - RFC-066: `credit_transactions`, `subscriptions`, `billing_events`

3. **Different fields added**: No overlap on `customers` table
   - RFC-065: `auto_provisioned`, `wizard_preference`, `first_scan_at`
   - RFC-066: `credit_balance`, `stripe_*`, `billing_*`

4. **Only RFC-066 renames**: RFC-065 doesn't rename anything
   - RFC-066: `subscription_plan` → `subscription_type`
   - RFC-066: `subscription_status` → `subscription_state`

### Ecto Schema Coordination

**Both RFCs must update** `lib/rsolv/customers/customer.ex`:

```elixir
schema "customers" do
  # Existing fields
  field :name, :string
  field :email, :string

  # RFC-066 renamed these:
  field :subscription_type, :string, default: "trial"  # was subscription_plan
  field :subscription_state, :string                   # was subscription_status

  # RFC-066 added these:
  field :credit_balance, :integer, default: 0
  field :stripe_customer_id, :string
  field :stripe_payment_method_id, :string
  field :stripe_subscription_id, :string
  field :billing_consent_given, :boolean, default: false
  field :billing_consent_at, :utc_datetime
  field :subscription_cancel_at_period_end, :boolean, default: false

  # RFC-065 added these:
  field :auto_provisioned, :boolean, default: false
  field :wizard_preference, :string, default: "auto"
  field :first_scan_at, :utc_datetime

  # ... rest of schema
end
```

**Merge strategy**: Last merge wins, but changes don't overlap so git will auto-merge cleanly.

---

## Action Items for Week 1

### RFC-065 Team
- [ ] Create migration: `add_customer_onboarding_fields.exs`
- [ ] Use `subscription_type` and `subscription_state` in code (not old names)
- [ ] Update `Customer` schema with new fields
- [ ] Test with `subscription_type: "trial"` values

### RFC-066 Team
- [ ] Create migration: `create_billing_tables.exs` (with renames)
- [ ] Update `Customer` schema with new fields and renamed fields
- [ ] Document `subscription_type` values: trial, pay_as_you_go, pro
- [ ] Document `subscription_state` values: NULL, active, past_due, canceled, etc.

### Both Teams
- [ ] Review this document
- [ ] Coordinate on `subscription_type` naming in code reviews
- [ ] Ensure migrations have different timestamps

---

## Summary

✅ **Current schema verified**
✅ **One naming conflict identified and resolved** (use `subscription_type`/`subscription_state`)
✅ **Separate migrations recommended** (unique timestamps prevent conflicts)
✅ **Coordination guidelines documented** (field naming, backfill strategy)
✅ **Both RFCs can proceed independently** in Week 1

**Next Steps**: Each RFC creates its own migration file in its respective workstream.

---

**Document Status**: Complete
**Next Review**: After both migrations are created
**Owner**: Dylan (Week 0 Database Team)
