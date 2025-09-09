# RFC-055: Customer Schema Consolidation (Phase 0)

**RFC Number**: 055  
**Title**: Customer Schema Consolidation - Critical Blocker Resolution  
**Author**: Platform Team  
**Status**: Approved  
**Created**: 2025-09-09  
**Approved**: 2025-09-09  
**Prerequisites**: None (This blocks RFC-049 and RFC-054)  
**Priority**: CRITICAL - Must complete before any other work

## Summary

Consolidate two incomplete Elixir Customer schemas (`Rsolv.Customers.Customer` and `Rsolv.Billing.Customer`) into a single, complete schema using Test-Driven Development (TDD). The consolidated schema will include all necessary database fields while dropping two unused fields (`plan` and `payment_method_added`). This RFC uses a red-green-refactor approach to ensure no functionality breaks during consolidation.

## Motivation

### The Critical Problem

We have discovered a blocking issue in production:
1. **Database**: The `customers` table has ~24 fields including billing, trial, and subscription fields
2. **Rsolv.Customers.Customer schema**: Missing 11 billing fields (trial_fixes_used, stripe_customer_id, etc.)
3. **Rsolv.Billing.Customer schema**: Missing relationships (user, api_keys, fix_attempts) and core fields

This means:
- Code using `Customers.Customer` cannot access billing fields that exist in the database
- Code using `Billing.Customer` cannot access relationships or core fields
- **This breaks functionality** - the application cannot properly use data that exists

### Why This Blocks Everything

- **RFC-049** (Customer Management): Can't consolidate customer management with broken schemas
- **RFC-054** (Rate Limiter): Can't add authentication features to incomplete schemas
- **All future work**: Any code touching customers is potentially broken

## Proposed Solution

**TDD Approach**: Use red-green-refactor methodology to safely consolidate schemas while dropping unused fields. Write tests first that define expected behavior, then implement to make tests pass.

### Strategy

1. **Write Failing Tests (RED)**: Define expected schema structure including what fields should and shouldn't exist
2. **Consolidate Schemas (GREEN)**: Merge necessary fields from both schemas, drop unused ones
3. **Refactor & Clean (REFACTOR)**: Update all references, remove old schema file
4. **Verify Safety**: Ensure no functionality breaks through comprehensive test coverage

### Branch Strategy (Required)

Use a feature branch for safe implementation:

```bash
# Create feature branch
git checkout -b feature/rfc-055-schema-consolidation

# After completion
git tag -a post-rfc-055 -m "Schema consolidation complete"
```

Or work directly on main if brief disruption is acceptable.

### Consolidated Schema Structure

```elixir
defmodule Rsolv.Customers.Customer do
  use Ecto.Schema
  import Ecto.Changeset
  
  schema "customers" do
    # Core fields (ESSENTIAL)
    field :name, :string
    field :email, :string
    # api_key - DROPPED (use api_keys relationship instead)
    field :active, :boolean, default: true
    field :metadata, :map, default: %{}
    # github_org - DROPPED (use forge_accounts relationship instead)
    
    # Usage tracking (KEEP - needed for rate limiting)
    field :monthly_limit, :integer, default: 100
    field :current_usage, :integer, default: 0
    
    # Trial tracking
    field :trial_fixes_used, :integer, default: 0
    field :trial_fixes_limit, :integer, default: 10
    # trial_expired - DROPPED (derive from trial_expired_at using helper function)
    field :trial_expired_at, :utc_datetime
    
    # Payment/Billing (KEEP - Stripe integration)
    # payment_method_added - DROPPED (not used in application code)
    field :payment_method_added_at, :utc_datetime
    field :stripe_customer_id, :string
    field :subscription_plan, :string, default: "pay_as_you_go"
    field :subscription_status, :string, default: "trial"
    # monthly_fix_quota - DROPPED (duplicate of monthly_limit, never used)
    field :rollover_fixes, :integer, default: 0  # Rarely used, consider dropping later
    
    # plan - DROPPED (duplicate of subscription_plan, minimally used)
    
    # Relationships (user_id kept until RFC-049)
    belongs_to :user, Rsolv.Accounts.User  # KEEP for now - required field, remove in RFC-049
    has_many :api_keys, Rsolv.Customers.ApiKey
    has_many :fix_attempts, Rsolv.Billing.FixAttempt
    has_many :forge_accounts, Rsolv.Customers.ForgeAccount  # Move from Phases context
    
    timestamps()
  end
end
```

**Helper Functions** (in Customer module or context):
```elixir
# Check if trial has expired based on trial_expired_at
def trial_expired?(%Customer{trial_expired_at: nil}), do: false
def trial_expired?(%Customer{trial_expired_at: expired_at}) do
  DateTime.compare(expired_at, DateTime.utc_now()) == :lt
end

# Use directly wherever needed:
if Customer.trial_expired?(customer) do
  # Handle expired trial
end
```

## Implementation Plan (Simplified - 1 Day Total)

### Morning: Consolidation (3-4 hours)

#### 0. Establish Test Baseline (CRITICAL)
```bash
# BEFORE making any changes, ensure all tests pass
mix test

# If any tests fail, STOP and fix them first
# We need a green baseline to ensure our changes don't break existing functionality
# Save the output for reference
mix test > test-baseline-$(date +%Y%m%d-%H%M%S).log
```

#### 1. Search for Field Usage (CRITICAL)
```bash
# Search for usage of fields we're dropping to avoid breaking code
echo "=== Checking api_key field usage (not api_keys) ==="
rg "\.api_key\b" --type elixir | grep -v "api_keys"

echo "=== Checking github_org usage ==="
rg "\.github_org" --type elixir

echo "=== Checking plan field usage ==="
rg "\.plan\b" --type elixir

echo "=== Checking other dropped fields ==="
rg "\.payment_method_added|\.trial_expired\b|\.monthly_fix_quota" --type elixir

# If any usage found, update that code FIRST before dropping fields
```

#### 2. Update Existing Test Files

**Note**: Instead of creating a new test file, we'll update existing tests that already use these schemas:
- `test/rsolv/consolidation_schema_test.exs` - Already tests Customer schema
- `test/rsolv/phases/phase_storage_test.exs` - Tests ForgeAccount usage
- `test/rsolv/phases/repositories_test.exs` - Tests forge relationships

#### 3. Add Failing Tests to Existing Files

**Note**: The existing `consolidation_schema_test.exs` has tests expecting `customer.api_key` (lines 46-47) that will need updating when we drop that field.

##### In `test/rsolv/consolidation_schema_test.exs`, add:

```elixir
  describe "consolidated customer schema" do
    test "has all required billing fields" do
      customer = %Customer{}
      
      # These will FAIL initially - proving the problem
      assert Map.has_key?(customer, :trial_fixes_used)
      assert Map.has_key?(customer, :trial_fixes_limit)
      assert Map.has_key?(customer, :stripe_customer_id)
      assert Map.has_key?(customer, :subscription_plan)
      assert Map.has_key?(customer, :subscription_status)
      assert Map.has_key?(customer, :rollover_fixes)
      assert Map.has_key?(customer, :payment_method_added_at)
      assert Map.has_key?(customer, :trial_expired_at)
    end
    
    test "does NOT have dropped fields" do
      customer = %Customer{}
      
      # These fields should not exist in schema
      refute Map.has_key?(customer, :plan)
      refute Map.has_key?(customer, :payment_method_added)
      refute Map.has_key?(customer, :trial_expired)
      refute Map.has_key?(customer, :monthly_fix_quota)
      refute Map.has_key?(customer, :api_key)  # Use api_keys relationship instead
      refute Map.has_key?(customer, :github_org)  # Use forge_accounts relationship instead
    end
    
    test "has proper relationships" do
      customer = %Customer{}
      
      # Should have these relationships
      assert %Ecto.Association.Has{} = Customer.__schema__(:association, :api_keys)
      assert %Ecto.Association.Has{} = Customer.__schema__(:association, :forge_accounts)
      assert %Ecto.Association.Has{} = Customer.__schema__(:association, :fix_attempts)
    end
    
  end
```

##### In `test/rsolv/phases/phase_storage_test.exs`, add:

```elixir
  describe "ForgeAccount in correct context" do
    test "ForgeAccount is in Customers context not Phases" do
      # This will FAIL initially - ForgeAccount is in wrong context
      assert Code.ensure_loaded?(Rsolv.Customers.ForgeAccount)
      
      # Should NOT be in Phases context after refactor
      refute Code.ensure_loaded?(Rsolv.Phases.ForgeAccount)
    end
    
    test "ForgeAccount belongs to Customer" do
      # Ensure the relationship is properly defined
      assert %Ecto.Association.BelongsTo{} = 
        Rsolv.Customers.ForgeAccount.__schema__(:association, :customer)
      
      # Ensure it points to the right schema
      assoc = Rsolv.Customers.ForgeAccount.__schema__(:association, :customer)
      assert assoc.related == Rsolv.Customers.Customer
    end
  end
    
```

##### Back in `test/rsolv/consolidation_schema_test.exs`, add trial_expired test:

```elixir
    test "derives trial_expired from trial_expired_at" do
      # Not expired - no date set
      customer1 = %Customer{trial_expired_at: nil}
      refute Customer.trial_expired?(customer1)
      
      # Not expired - future date
      future = DateTime.add(DateTime.utc_now(), 3600, :second)
      customer2 = %Customer{trial_expired_at: future}
      refute Customer.trial_expired?(customer2)
      
      # Expired - past date
      past = DateTime.add(DateTime.utc_now(), -3600, :second)
      customer3 = %Customer{trial_expired_at: past}
      assert Customer.trial_expired?(customer3)
    end
    
    test "changeset handles billing fields" do
      attrs = %{
        name: "Test",
        email: "test@example.com",
        user_id: 1,  # Required until RFC-049
        stripe_customer_id: "cus_123",
        subscription_plan: "pro",
        trial_fixes_used: 5
      }
      
      changeset = Customer.changeset(%Customer{}, attrs)
      
      # Will FAIL initially - changeset doesn't know these fields
      assert changeset.changes.stripe_customer_id == "cus_123"
      assert changeset.changes.subscription_plan == "pro"
      assert changeset.changes.trial_fixes_used == 5
    end
    
    test "changeset rejects dropped fields" do
      attrs = %{
        name: "Test",
        email: "test@example.com",
        user_id: 1,
        plan: "old_plan",  # Dropped field
        payment_method_added: true  # Dropped field
      }
      
      changeset = Customer.changeset(%Customer{}, attrs)
      
      # These fields should be ignored, not in changes
      refute Map.has_key?(changeset.changes, :plan)
      refute Map.has_key?(changeset.changes, :payment_method_added)
    end
    
    test "can query billing fields from database" do
      # Insert test customer with billing fields
      {:ok, customer} = %Customer{}
        |> Customer.changeset(%{
          name: "Test Customer",
          email: "test@example.com",
          user_id: 1,
          stripe_customer_id: "cus_test",
          subscription_status: "active"
        })
        |> Repo.insert()
      
      # Reload from database
      loaded = Repo.get!(Customer, customer.id)
      
      # Should have all consolidated fields
      assert loaded.stripe_customer_id == "cus_test"
      assert loaded.subscription_status == "active"
    end
  end # End of consolidated customer schema describe block
```

#### 4. Verify Tests Fail
```bash
# Run the updated test files
mix test test/rsolv/consolidation_schema_test.exs
mix test test/rsolv/phases/phase_storage_test.exs

# Should see RED - multiple failures in both files

# Commit the failing tests
git add -A
git commit -m "test(rfc-055): Add failing tests for schema consolidation (RED phase)"
```

### Afternoon: Cleanup and Deploy (3-4 hours)

#### 1. Update Customer Schema
- Add ALL missing billing fields (except dropped ones)
- Remove `plan` and `payment_method_added` fields
- Update changeset to handle new fields:
  ```elixir
  def changeset(customer, attrs) do
    customer
    |> cast(attrs, [:name, :email, :monthly_limit, :current_usage, 
                    :active, :metadata, :user_id,
                    :trial_fixes_used, :trial_fixes_limit,
                    :trial_expired_at, :payment_method_added_at, 
                    :stripe_customer_id, :subscription_plan, :subscription_status,
                    :rollover_fixes])
    |> validate_required([:name, :email, :user_id])  # user_id stays required until RFC-049
    # ... existing validations (remove generate_api_key_if_missing)
  end
  ```
- Note: Do NOT include `plan` or `payment_method_added` in cast list
- Commit changes

#### 2. Update References and Move ForgeAccount (GREEN phase)

##### 2a. Update Billing.Customer References
```bash
# Find and replace all Billing.Customer references
rg "Billing\.Customer" --type elixir
# Update to use Customers.Customer
```

##### 2b. Move ForgeAccount to Correct Context (TDD)
```bash
# Run the ForgeAccount context test - it should FAIL
mix test test/rsolv/phases/phase_storage_test.exs --only "ForgeAccount is in Customers context not Phases"

# Move the file
mv lib/rsolv/phases/forge_account.ex lib/rsolv/customers/forge_account.ex

# Update the module declaration
sed -i 's/defmodule Rsolv.Phases.ForgeAccount/defmodule Rsolv.Customers.ForgeAccount/' \
  lib/rsolv/customers/forge_account.ex

# Find all references to update
rg "Rsolv\.Phases\.ForgeAccount" --type elixir
rg "alias.*Phases.*ForgeAccount" --type elixir

# Update all references (examples):
# - In lib/rsolv/phases.ex
# - In lib/rsolv/phases/repositories.ex
# - In any controllers or contexts using it

# Run the test again - should now PASS
mix test test/rsolv/phases/phase_storage_test.exs --only "ForgeAccount is in Customers context not Phases"
```

#### 3. Delete Old Schema
```bash
rm lib/rsolv/billing/customer.ex
```

#### 4. Create Migration for Dropped Fields
```elixir
# Create migration to drop unused columns
defmodule Rsolv.Repo.Migrations.DropUnusedCustomerFields do
  use Ecto.Migration
  
  alias Rsolv.Repo
  import Ecto.Query

  def up do
    # First, migrate any existing api_keys from customer.api_key to api_keys table
    execute """
    INSERT INTO api_keys (key, name, customer_id, active, inserted_at, updated_at)
    SELECT api_key, 'Legacy Key', id, true, NOW(), NOW()
    FROM customers
    WHERE api_key IS NOT NULL
    AND NOT EXISTS (
      SELECT 1 FROM api_keys WHERE api_keys.key = customers.api_key
    )
    """
    
    # Migrate github_org to forge_accounts
    execute """
    INSERT INTO forge_accounts (customer_id, forge_type, namespace, inserted_at, updated_at)
    SELECT id, 'github', github_org, NOW(), NOW()
    FROM customers
    WHERE github_org IS NOT NULL
    AND NOT EXISTS (
      SELECT 1 FROM forge_accounts 
      WHERE forge_accounts.customer_id = customers.id 
      AND forge_accounts.namespace = customers.github_org
    )
    """
    
    # Then drop the columns
    alter table(:customers) do
      remove :plan
      remove :payment_method_added
      remove :trial_expired
      remove :monthly_fix_quota
      remove :api_key  # Use api_keys table instead
      remove :github_org  # Use forge_accounts table instead
    end
    
    drop_if_exists index(:customers, [:trial_expired])
    drop_if_exists index(:customers, [:api_key])
  end
  
  def down do
    alter table(:customers) do
      add :plan, :string, default: "trial"
      add :payment_method_added, :boolean, default: false
      add :trial_expired, :boolean, default: false
      add :monthly_fix_quota, :integer
      add :api_key, :string
    end
    
    create index(:customers, [:trial_expired])
    create unique_index(:customers, [:api_key])
  end
end
```

#### 5. Test and Deploy
```bash
# Run migration
mix ecto.migrate

# Run tests
mix test

# Deploy to staging
# Verify functionality
```

## Success Criteria

1. **All tests pass** - Both new consolidation tests and existing test suite
2. **Zero references** to `Billing.Customer` remain in codebase
3. **ForgeAccount moved** - `Rsolv.Customers.ForgeAccount` exists, `Rsolv.Phases.ForgeAccount` does not
4. **All fields accessible** - Can read/write all necessary customer fields
5. **No data loss** - Existing api_keys and github_org data migrated to proper tables
6. **Clean rollback** - Can revert to pre-rfc-055 tag if issues arise

## Rollback Strategy

Rollback requires both code and database changes:

```bash
# 1. Rollback database migration FIRST
mix ecto.rollback

# 2. Then revert code changes
git revert HEAD

# 3. Or restore from tag
git checkout pre-rfc-055

# Note: Data in api_keys and forge_accounts tables will need manual recovery
# if rollback happens after production deployment
```

## Testing Requirements

### Unit Tests
- Schema field presence tests
- Changeset validation tests
- Relationship loading tests

### Integration Tests
- Database query tests
- API endpoint tests (verify dropped fields don't break responses)
- Context function tests
- Authentication with api_keys relationship
- Forge account verification

### Smoke Tests
- Can load customer from production
- Can update customer fields
- Can query by billing fields

## Security Considerations

- **Database migrations required** - Dropping columns and migrating data
- Data preservation critical - api_keys and github_org migrated to proper tables
- API compatibility check needed - dropped fields may break existing clients
- Authentication still works - api_keys relationship maintains functionality
- Rollback requires database migration reversal

## Timeline

**Total Duration**: 1 day

- **Morning**: Write tests and consolidate schemas (3-4 hours)
- **Afternoon**: Update references, cleanup, and deploy (3-4 hours)

## Dependencies

None - this is Phase 0 that unblocks other work

## Blocked Work

This blocks:
- RFC-049: Customer Management Consolidation
- RFC-054: Distributed Rate Limiter
- All future customer-related features

## Field Deprecation Plan

### Phase 0 (This RFC - Immediate)
Fields dropped during consolidation:
- `plan` - Duplicate of `subscription_plan`, minimally used
- `payment_method_added` - Not used in application code
- `trial_expired` - Replaced with helper function using `trial_expired_at`
- `monthly_fix_quota` - Duplicate of `monthly_limit`, never used in code
- `api_key` - Redundant, use `api_keys` relationship for multiple keys with proper tracking
- `github_org` - Platform-specific, use `forge_accounts` relationship for forge-agnostic design

### Phase 1 (RFC-049 - Customer Management)
- `user_id` - Required field currently, but Users table is empty. Will be removed as part of RFC-049

### Future Consideration
- `rollover_fixes` - Rarely used, may be removable after understanding business logic
- All other fields kept for production compatibility

## Alternatives Considered

1. **Keep both schemas**: Would require complex coordination and duplicate code
2. **Database migration to remove fields**: Too risky without understanding field usage
3. **Gradual migration**: Would extend the period of broken functionality
4. **Optimize fields now**: Would delay unblocking critical work

Pragmatic consolidation unblocks work immediately with minimal risk.

## Architectural Considerations

### Module Naming Convention
Based on Phoenix best practices for bounded contexts:
- **Current**: `Rsolv.Customers.Customer` follows the standard Phoenix context pattern
- **Recommendation**: Keep current naming. The `Customers` context correctly groups Customer, ApiKey, and related schemas
- **Note**: If we later need user types like Admin, they should be in an `Accounts` or `Users` context, not mixed with customers

**Issue Found**: `ForgeAccount` is currently in `Rsolv.Phases` context but should be in `Rsolv.Customers`:
- ForgeAccount is a customer account concept, not a phase execution concept
- Should be moved: `Rsolv.Phases.ForgeAccount` → `Rsolv.Customers.ForgeAccount`
- This aligns with DDD bounded contexts (customer domain vs phase execution domain)

### API Key Migration
**Discovery**: We already have a proper `api_keys` table with:
- Multiple keys per customer support
- Active/inactive status
- Expiry dates
- Last used tracking
- Metadata fields

**Recommendation**: 
- Drop the redundant `api_key` field from customers table
- The existing `has_many :api_keys` relationship is correct
- This allows proper key rotation, revocation, and audit trails

### Git Forge Integration
**Discovery**: We have a proper forge abstraction via `forge_accounts` table:
- Supports multiple forge types (GitHub now, GitLab/Bitbucket later)
- Platform-agnostic design with `forge_type` enum
- Allows multiple forge accounts per customer
- Proper namespace tracking per forge

**Recommendation**:
- Drop `github_org` from Customer schema
- Use `forge_accounts` relationship for all forge integrations
- Migration will move existing `github_org` values to forge_accounts
- FixAttempt keeps its `github_org` field for historical tracking

## Implementation Considerations

### Things to Watch For

1. **Scripts Using api_key Field**:
   - Several create-customer scripts expect `customer.api_key` to exist
   - Update to use `api_keys` relationship after migration
   - Scripts affected: `create-demo-api-key-prod.exs`, `create-test-customer.exs`, etc.

2. **ForgeAccount Import Updates**:
   - 10+ test files import `Rsolv.Phases.ForgeAccount`
   - All need updating to `Rsolv.Customers.ForgeAccount`
   - Use: `rg "Phases\.ForgeAccount" --type elixir` to find all

3. **Customer Creation in Tests**:
   - Tests expect `customer.api_key` to be auto-generated (consolidation_schema_test.exs lines 46-47)
   - Update to create ApiKey separately or use relationship
   - `Rsolv.Customers.create_customer/2` may need adjustment

4. **Existing Test Breakage**:
   - `consolidation_schema_test.exs` expects `customer.api_key`
   - Multiple validation cache tests use ForgeAccount
   - Phase tests heavily use ForgeAccount

## Open Questions

1. Should we enforce that customers can only have fixes for their registered forge namespaces?
2. How do we handle customers with existing data in the dropped fields?
3. Should `rollover_fixes` be dropped now or wait for better understanding of business logic?

## References

- RFC-049: Customer Management Consolidation
- RFC-054: Distributed Rate Limiter
- Production database analysis: 2025-09-09
- Current schema files: `lib/rsolv/customers/customer.ex`, `lib/rsolv/billing/customer.ex`