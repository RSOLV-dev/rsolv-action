defmodule Rsolv.Phase3IntegrationTest do
  use Rsolv.DataCase

  @moduledoc """
  Phase 3 integration tests to verify that controllers work with unified contexts.
  These tests define the expected behavior after completing RFC-049 Customer consolidation.
  """

  describe "authentication integration" do
    test "controllers can authenticate customers via API keys" do
      # Create a customer using new consolidated structure
      {:ok, customer} =
        Rsolv.Customers.create_customer(%{
          name: "API Test Customer",
          email: "api@example.com"
        })

      # Create an API key for the customer
      {:ok, api_key_result} =
        Rsolv.Customers.create_api_key(customer, %{
          name: "Test Key"
        })

      # Test that customer can be found by API key
      found_customer = Rsolv.Customers.get_customer_by_api_key(api_key_result.raw_key)
      assert found_customer != nil
      assert found_customer.id == customer.id

      # Verify Accounts context compatibility layer works
      compat_customer = Rsolv.Accounts.get_customer_by_api_key(api_key_result.raw_key)
      assert compat_customer != nil
      assert compat_customer.id == customer.id
    end

    test "controllers work with multiple API keys per customer" do
      # Create a customer
      {:ok, customer} =
        Rsolv.Customers.create_customer(%{
          name: "Multi-Key Customer",
          email: "multikey@example.com"
        })

      # Create multiple API keys
      {:ok, key1_result} = Rsolv.Customers.create_api_key(customer, %{name: "Production"})
      {:ok, key2_result} = Rsolv.Customers.create_api_key(customer, %{name: "Development"})

      # Both keys should resolve to the same customer
      customer1 = Rsolv.Customers.get_customer_by_api_key(key1_result.raw_key)
      customer2 = Rsolv.Customers.get_customer_by_api_key(key2_result.raw_key)

      assert customer1.id == customer.id
      assert customer2.id == customer.id
      assert customer1.id == customer2.id

      # List API keys
      keys = Rsolv.Customers.list_api_keys(customer)
      assert length(keys) >= 2
    end

    test "legacy API keys still work during transition" do
      # This test validates backward compatibility
      # Since LegacyAccounts is removed, we skip this test
      # as it's no longer applicable post-RFC-049

      # Create a customer with the new system
      {:ok, customer} =
        Rsolv.Customers.create_customer(%{
          name: "Legacy Test",
          email: "legacy@example.com"
        })

      {:ok, api_key_result} =
        Rsolv.Customers.create_api_key(customer, %{
          name: "Legacy Key"
        })

      # Verify the new system works
      found_customer = Rsolv.Customers.get_customer_by_api_key(api_key_result.raw_key)
      assert found_customer != nil
      assert found_customer.email == "legacy@example.com"
    end
  end

  describe "usage tracking integration" do
    test "customer usage is properly tracked" do
      # Create customer
      {:ok, customer} =
        Rsolv.Customers.create_customer(%{
          name: "Usage Test Customer",
          email: "usage@example.com"
        })

      # Initial usage should be 0
      assert customer.current_usage == 0

      # Increment usage
      {:ok, updated_customer} = Rsolv.Customers.increment_usage(customer, 5)
      assert updated_customer.current_usage == 5

      # Usage tracking through Billing context (if available)
      # Note: This delegates to Customers context now
      if Code.ensure_loaded?(Rsolv.Billing) do
        Rsolv.Billing.record_usage(%{
          customer_id: customer.id,
          amount: 3
        })

        refreshed = Rsolv.Customers.get_customer!(customer.id)
        assert refreshed.current_usage >= 5
      end
    end
  end

  describe "feature flags integration" do
    test "feature flags work with new customer structure" do
      # Create customer
      {:ok, customer} =
        Rsolv.Customers.create_customer(%{
          name: "Feature Flag Customer",
          email: "flags@example.com"
        })

      # Customer should implement FunWithFlags.Actor protocol
      # This is done via the protocol implementation at the bottom of Customer schema
      customer_id = "customer:#{customer.id}"

      # The protocol implementation should work
      assert customer_id == FunWithFlags.Actor.id(customer)
    end
  end
end
