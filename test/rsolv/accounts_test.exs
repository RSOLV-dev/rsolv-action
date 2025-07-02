defmodule RSOLV.AccountsTest do
  use RsolvApi.DataCase
  
  alias RSOLV.Accounts

  describe "get_customer_by_api_key/1" do
    test "returns nil for hardcoded keys when not in allowed list" do
      # These should NOT work because they're hardcoded
      assert Accounts.get_customer_by_api_key("rsolv_internal_a08e4f8ffb58ba44b2cb4d3b30f28e99") == nil
      assert Accounts.get_customer_by_api_key("rsolv_internal_1cbadb7c6436697f3cf0411576abe323") == nil
      assert Accounts.get_customer_by_api_key("rsolv_prod_demo_key") == nil
      assert Accounts.get_customer_by_api_key("rsolv_master_key_984c92f8c96d95167a2cf9bc8de288bb") == nil
    end

    test "returns customer for keys that match environment variables" do
      # Set up test environment variables
      System.put_env("INTERNAL_API_KEY", "test_internal_key_123")
      System.put_env("DEMO_API_KEY", "test_demo_key_456")
      
      # These should work because they match env vars
      internal = Accounts.get_customer_by_api_key("test_internal_key_123")
      assert internal != nil
      assert internal.id == "internal"
      assert internal.name == "Internal Testing"
      
      demo = Accounts.get_customer_by_api_key("test_demo_key_456")
      assert demo != nil
      assert demo.id == "demo"
      assert demo.name == "Demo Account"
      
      # Clean up
      System.delete_env("INTERNAL_API_KEY")
      System.delete_env("DEMO_API_KEY")
    end

    test "returns nil for non-existent keys" do
      assert Accounts.get_customer_by_api_key("random_key_xyz") == nil
      assert Accounts.get_customer_by_api_key("") == nil
      assert Accounts.get_customer_by_api_key(nil) == nil
    end
    
    test "test customer has enterprise tier and flags" do
      customer = Accounts.get_customer_by_api_key("rsolv_test_abc123")
      
      assert customer != nil
      assert customer.id == "test_customer_1"
      assert customer.name == "Test Customer"
      assert customer.email == "test@example.com"
      assert customer.tier == "enterprise"
      assert customer.flags == ["ai_access", "enterprise_access"]
      assert customer.monthly_limit == 100
      assert customer.active == true
      assert customer.trial == true
    end
  end
end