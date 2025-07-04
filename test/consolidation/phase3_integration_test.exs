defmodule Rsolv.Phase3IntegrationTest do
  use Rsolv.DataCase

  @moduledoc """
  Phase 3 integration tests to verify that controllers work with unified contexts.
  These tests define the expected behavior after migrating from LegacyAccounts to 
  the new Accounts/Customers context structure.
  """

  describe "authentication integration" do
    test "controllers can authenticate customers via API keys" do
      # Create a user and customer using new contexts
      {:ok, user} = Rsolv.Accounts.register_user(%{
        email: "api@example.com",
        password: "password123456"
      })
      
      {:ok, customer} = Rsolv.Customers.create_customer(user, %{
        name: "API Test Customer",
        email: "api@example.com"
      })
      
      # Test that customer can be found by API key
      found_customer = Rsolv.Customers.get_customer_by_api_key(customer.api_key)
      assert found_customer.id == customer.id
      assert found_customer.name == "API Test Customer"
      assert found_customer.user_id == user.id
    end

    test "controllers work with multiple API keys per customer" do
      {:ok, user} = Rsolv.Accounts.register_user(%{
        email: "multiapi@example.com", 
        password: "password123456"
      })
      
      {:ok, customer} = Rsolv.Customers.create_customer(user, %{
        name: "Multi-API Customer",
        email: "multiapi@example.com"
      })
      
      # Create additional API keys
      {:ok, prod_key} = Rsolv.Customers.create_api_key(customer, %{
        name: "Production Key"
      })
      
      {:ok, dev_key} = Rsolv.Customers.create_api_key(customer, %{
        name: "Development Key"
      })
      
      # Test that customer can be found by any API key
      found_by_customer_key = Rsolv.Customers.get_customer_by_api_key(customer.api_key)
      found_by_prod_key = Rsolv.Customers.get_customer_by_api_key(prod_key.key)
      found_by_dev_key = Rsolv.Customers.get_customer_by_api_key(dev_key.key)
      
      assert found_by_customer_key.id == customer.id
      assert found_by_prod_key.id == customer.id  
      assert found_by_dev_key.id == customer.id
    end

    test "legacy API keys still work during transition" do
      # Test that environment-based API keys still work
      # This ensures compatibility during migration
      found_customer = Rsolv.LegacyAccounts.get_customer_by_api_key("rsolv_test_abc123")
      assert found_customer != nil
      assert found_customer.name == "Test Customer"
    end
  end

  describe "usage tracking integration" do
    test "customer usage is properly tracked" do
      {:ok, user} = Rsolv.Accounts.register_user(%{
        email: "usage@example.com",
        password: "password123456"
      })
      
      {:ok, customer} = Rsolv.Customers.create_customer(user, %{
        name: "Usage Test Customer", 
        email: "usage@example.com",
        monthly_limit: 100
      })
      
      # Test usage tracking
      assert customer.current_usage == 0
      
      {:ok, updated_customer} = Rsolv.Customers.increment_usage(customer, 5)
      assert updated_customer.current_usage == 5
      
      # Test usage within limits
      assert updated_customer.current_usage < customer.monthly_limit
    end
  end

  describe "feature flags integration" do
    test "feature flags work with new customer structure" do
      {:ok, user} = Rsolv.Accounts.register_user(%{
        email: "flags@example.com",
        password: "password123456"
      })
      
      {:ok, customer} = Rsolv.Customers.create_customer(user, %{
        name: "Feature Test Customer",
        email: "flags@example.com"
      })
      
      # Test feature flag enabling
      flag_name = :test_feature_integration
      :ok = Rsolv.FeatureFlags.enable(flag_name)
      
      assert Rsolv.FeatureFlags.enabled?(flag_name)
    end
  end
end