defmodule Rsolv.AccountsTest do
  use Rsolv.DataCase
  
  alias Rsolv.Accounts
  alias Rsolv.Customers

  describe "get_customer_by_api_key/1" do
    test "returns nil for non-existent keys" do
      assert Accounts.get_customer_by_api_key("random_key_xyz") == nil
      assert Accounts.get_customer_by_api_key("") == nil
      assert Accounts.get_customer_by_api_key(nil) == nil
    end

    test "returns customer for valid database API key" do
      # Create a customer with an API key
      {:ok, customer} = Customers.create_customer(%{
        name: "Test Customer",
        email: "test@example.com",
        subscription_plan: "enterprise",
        metadata: %{"flags" => ["ai_access", "enterprise_access"]},
        monthly_limit: 100,
        active: true
      })
      
      {:ok, api_key} = Customers.create_api_key(customer, %{
        name: "Test API Key",
        permissions: ["full_access"]
      })
      
      # Should return the customer when using the valid key
      found_customer = Accounts.get_customer_by_api_key(api_key.key)
      assert found_customer != nil
      assert found_customer.id == customer.id
      assert found_customer.name == "Test Customer"
      assert found_customer.email == "test@example.com"
      assert found_customer.subscription_plan == "enterprise"
      assert found_customer.metadata["flags"] == ["ai_access", "enterprise_access"]
      assert found_customer.monthly_limit == 100
      assert found_customer.active == true
    end

    @tag :skip  # revoke_api_key function not implemented yet
    test "returns nil for revoked API key" do
      # Skip - revoke_api_key function not implemented yet
    end

    test "returns nil for inactive customer" do
      # Create an inactive customer
      {:ok, customer} = Customers.create_customer(%{
        name: "Inactive Customer",
        email: "inactive@example.com",
        active: false
      })
      
      {:ok, api_key} = Customers.create_api_key(customer, %{
        name: "Test API Key",
        permissions: ["full_access"]
      })
      
      # Should return nil for inactive customer
      assert Accounts.get_customer_by_api_key(api_key.key) == nil
    end
  end
end