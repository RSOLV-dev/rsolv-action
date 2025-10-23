# Account Consolidation Test Plan

**Date**: 2025-09-03  
**Purpose**: Ensure safe consolidation of three parallel customer systems into one  
**Approach**: TDD - Write tests first, then implement consolidation

## Test Coverage Status

### Current State
- ✅ **529 doctests** passing across the codebase
- ✅ **Rsolv.AccountsTest** - 4 tests passing (LegacyAccounts wrapper)
- ❌ **Rsolv.Customers** - NO TESTS
- ❌ **Rsolv.Billing.Customer** - NO TESTS
- ⚠️ **Rsolv.LegacyAccounts** - Minimal indirect testing

## Phase 1: Pre-Consolidation Tests (Safety Net)

### 1.1 Document Current Behavior
```elixir
# test/rsolv/customers_test.exs
defmodule Rsolv.CustomersTest do
  use Rsolv.DataCase
  
  describe "current state documentation" do
    test "Customer belongs to User" do
      # Document the User → Customer relationship
    end
    
    test "Customer has many ApiKeys" do
      # Document the Customer → ApiKey relationship
    end
    
    test "ForgeAccount belongs to Customer" do
      # Document the Customer → ForgeAccount relationship
    end
  end
end
```

### 1.2 Billing Customer Behavior
```elixir
# test/rsolv/billing/customer_test.exs
defmodule Rsolv.Billing.CustomerTest do
  use Rsolv.DataCase
  
  describe "billing fields" do
    test "tracks trial usage correctly" do
      # Document trial_fixes_used/limit behavior
    end
    
    test "manages subscription plans" do
      # Document subscription_plan transitions
    end
    
    test "handles Stripe customer ID" do
      # Document stripe_customer_id usage
    end
  end
end
```

### 1.3 Cross-System Duplicate Detection
```elixir
# test/rsolv/account_consolidation_test.exs
defmodule Rsolv.AccountConsolidationTest do
  use Rsolv.DataCase
  
  describe "duplicate detection" do
    test "finds customers with same API key across systems" do
      # Create customer in Customers context
      # Create customer in Billing context with same API key
      # Verify we can detect the duplicate
    end
    
    test "finds customers with same email across systems" do
      # Similar test for email duplicates
    end
  end
end
```

## Phase 2: Migration Tests (Before Implementation)

### 2.1 Schema Migration
```elixir
describe "schema consolidation" do
  test "merged Customer has all required fields" do
    # Verify new schema has:
    # - All fields from Customers.Customer
    # - All fields from Billing.Customer
    # - Proper relationships maintained
  end
  
  test "billing fields added to main Customer" do
    fields_to_add = [
      :trial_fixes_used,
      :trial_fixes_limit,
      :trial_expired,
      :subscription_plan,
      :rollover_fixes,
      :stripe_customer_id
    ]
    # Verify each field exists and has correct type
  end
end
```

### 2.2 Data Migration
```elixir
describe "data migration" do
  test "migrates Billing.Customer to Customers.Customer" do
    # Create Billing.Customer record
    # Run migration
    # Verify data transferred correctly
    # Verify User relationship created/maintained
  end
  
  test "handles conflicting records gracefully" do
    # Create conflicts (same API key in both systems)
    # Run migration
    # Verify conflict resolution strategy
  end
  
  test "preserves all relationships during migration" do
    # Create complex setup with ApiKeys, ForgeAccounts
    # Run migration
    # Verify all relationships intact
  end
end
```

## Phase 3: API Endpoint Tests

### 3.1 Customer Management API
```elixir
# test/rsolv_web/controllers/api/customer_controller_test.exs
defmodule RsolvWeb.Api.CustomerControllerTest do
  use RsolvWeb.ConnCase
  
  describe "POST /api/v1/customers" do
    test "creates customer with valid data" do
      # Admin-only endpoint
    end
    
    test "rejects invalid API keys" do
      # Validation tests
    end
  end
  
  describe "GET /api/v1/customers/:id" do
    test "returns customer details" do
      # Including all consolidated fields
    end
  end
  
  describe "PATCH /api/v1/customers/:id" do
    test "updates customer fields" do
      # Including billing fields
    end
  end
end
```

### 3.2 Credential Vending Integration
```elixir
describe "credential vending with consolidated customer" do
  test "vends credentials for migrated customer" do
    # Create consolidated customer
    # Request credentials with API key
    # Verify vending works correctly
  end
  
  test "respects billing limits after consolidation" do
    # Create customer with trial limits
    # Verify vending respects those limits
  end
end
```

## Phase 4: Legacy Removal Tests

### 4.1 LegacyAccounts Replacement
```elixir
describe "legacy accounts removal" do
  test "test fixtures replace hardcoded accounts" do
    # Verify all hardcoded test accounts have fixture equivalents
    test_accounts = [
      "rsolv_test_abc123",
      "rsolv_test_regular_def456",
      "rsolv_test_enterprise_xyz789"
    ]
    # Each should exist as proper database fixture
  end
  
  test "environment-based keys work through Customers context" do
    # INTERNAL_API_KEY, DEMO_API_KEY, etc.
    # Should be created as database records on app start
  end
  
  test "no more :persistent_term usage" do
    # Verify we're not using in-memory storage
  end
end
```

## Phase 5: Performance & Load Tests

### 5.1 Query Performance
```elixir
describe "consolidated schema performance" do
  test "customer lookup performance acceptable" do
    # Benchmark API key lookups
    # Should be < 10ms for 10,000 customers
  end
  
  test "relationship queries optimized" do
    # Test N+1 query prevention
    # Customer with ApiKeys, ForgeAccounts should be 1-2 queries
  end
end
```

## Phase 6: Rollback Safety Tests

### 6.1 Rollback Capability
```elixir
describe "rollback safety" do
  test "can rollback migration if needed" do
    # Document rollback procedure
    # Test that data can be split back if necessary
  end
  
  test "audit trail of consolidation" do
    # Verify we track what was merged
    # Important for debugging production issues
  end
end
```

## Test Execution Plan

1. **Write all Phase 1 tests first** - Document current behavior
2. **Run and ensure passing** - Baseline established
3. **Write Phase 2 migration tests** - These will fail initially
4. **Implement consolidation** - Make Phase 2 tests pass
5. **Write and implement Phase 3-4** - API and legacy removal
6. **Run Phase 5** - Performance validation
7. **Document Phase 6** - Rollback procedures

## Success Criteria

- [ ] All existing tests still pass
- [ ] 100% test coverage for consolidated Customer schema
- [ ] Migration tests cover all edge cases
- [ ] Performance benchmarks met
- [ ] No hardcoded test data in production code
- [ ] Rollback procedure documented and tested

## Doctest Requirements

Add doctests for all public functions:
```elixir
@doc """
Gets a customer by API key.

## Examples

    iex> {:ok, customer} = Customers.create_customer(%{api_key: "test_key_123"})
    iex> Customers.get_customer_by_api_key("test_key_123")
    %Customer{api_key: "test_key_123"}
    
    iex> Customers.get_customer_by_api_key("nonexistent")
    nil
"""
def get_customer_by_api_key(api_key) do
  # Implementation
end
```

## Next Steps

1. Start with Phase 1.1 - Document current Customers behavior
2. Create test/rsolv/customers_test.exs
3. Run tests to establish baseline
4. Move to Phase 1.2 for Billing.Customer
5. Continue through phases systematically