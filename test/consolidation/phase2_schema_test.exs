defmodule Rsolv.Consolidation.Phase2SchemaTest do
  use Rsolv.DataCase
  
  @moduledoc """
  TDD tests for Phase 2: Database Schema Consolidation.
  These tests define the expected unified schema structure.
  """
  
  describe "unified user and customer relationship" do
    @tag :skip
    test "users table exists with auth fields" do
      # This test expects a users table with authentication fields
      # from phx.gen.auth
      
      user_attrs = %{
        email: "test@example.com",
        password: "password123456"
      }
      
      {:ok, user} = Rsolv.Accounts.register_user(user_attrs)
      
      assert user.email == "test@example.com"
      assert user.hashed_password != nil
      assert user.confirmed_at == nil
      refute user.password
    end
    
    @tag :skip
    test "customers table references users table" do
      # First create a user
      {:ok, user} = Rsolv.Accounts.register_user(%{
        email: "customer@example.com",
        password: "password123456"
      })
      
      # Then create a customer linked to that user
      customer_attrs = %{
        name: "Test Customer",
        github_org: "test-org"
      }
      
      {:ok, customer} = Rsolv.Customers.create_customer(user, customer_attrs)
      
      assert customer.user_id == user.id
      assert customer.name == "Test Customer"
      assert customer.github_org == "test-org"
      assert "test_" <> Ecto.UUID.generate() != nil
      assert String.starts_with?("test_" <> Ecto.UUID.generate(), "rsolv_")
    end
    
    @tag :skip
    test "api_keys table for multiple keys per customer" do
      {:ok, user} = Rsolv.Accounts.register_user(%{
        email: "multikey@example.com",
        password: "password123456"
      })
      
      {:ok, customer} = Rsolv.Customers.create_customer(user, %{
        name: "Multi-Key Customer"
      })
      
      # Create additional API keys
      {:ok, key1} = Rsolv.Customers.create_api_key(customer, %{
        name: "Production Key",
        permissions: ["read", "write"]
      })
      
      {:ok, key2} = Rsolv.Customers.create_api_key(customer, %{
        name: "Read-Only Key",
        permissions: ["read"]
      })
      
      assert key1.customer_id == customer.id
      assert key2.customer_id == customer.id
      assert key1.name == "Production Key"
      assert key2.name == "Read-Only Key"
      assert String.starts_with?(key1.key, "rsolv_")
      assert String.starts_with?(key2.key, "rsolv_")
    end
  end
  
  describe "feature flags integration" do
    @tag :skip
    test "feature_flags table exists for FunWithFlags" do
      # This should work with the existing FunWithFlags setup
      flag_name = "test_feature"
      
      {:ok, _} = Rsolv.FeatureFlags.enable(flag_name)
      assert Rsolv.FeatureFlags.enabled?(flag_name)
      
      {:ok, _} = Rsolv.FeatureFlags.disable(flag_name)
      refute Rsolv.FeatureFlags.enabled?(flag_name)
    end
    
    @tag :skip
    test "feature flags can be scoped to customers" do
      {:ok, user} = Rsolv.Accounts.register_user(%{
        email: "feature@example.com",
        password: "password123456"
      })
      
      {:ok, customer} = Rsolv.Customers.create_customer(user, %{
        name: "Feature Test Customer"
      })
      
      flag_name = "beta_feature"
      
      # Enable for specific customer
      {:ok, _} = Rsolv.FeatureFlags.enable_for_customer(flag_name, customer)
      
      assert Rsolv.FeatureFlags.enabled?(flag_name, for: customer)
      refute Rsolv.FeatureFlags.enabled?(flag_name) # Not enabled globally
    end
  end
  
  describe "email subscriptions" do
    @tag :skip
    test "email_subscriptions table for marketing emails" do
      {:ok, subscription} = Rsolv.Marketing.subscribe_email(%{
        email: "subscriber@example.com",
        source: "landing_page",
        tags: ["early_access", "newsletter"]
      })
      
      assert subscription.email == "subscriber@example.com"
      assert subscription.source == "landing_page"
      assert subscription.status == "active"
      assert "early_access" in subscription.tags
      assert subscription.convertkit_subscriber_id == nil # Not synced yet
    end
    
    @tag :skip
    test "email subscriptions can be linked to users" do
      {:ok, user} = Rsolv.Accounts.register_user(%{
        email: "linked@example.com",
        password: "password123456"
      })
      
      {:ok, subscription} = Rsolv.Marketing.subscribe_email(%{
        email: user.email,
        user_id: user.id,
        source: "signup"
      })
      
      assert subscription.user_id == user.id
      assert subscription.email == user.email
    end
  end
  
  describe "billing and usage tracking" do
    @tag :skip
    test "fix_attempts table tracks usage" do
      {:ok, user} = Rsolv.Accounts.register_user(%{
        email: "billing@example.com",
        password: "password123456"
      })
      
      {:ok, customer} = Rsolv.Customers.create_customer(user, %{
        name: "Billing Test Customer"
      })
      
      fix_attempt_attrs = %{
        customer_id: customer.id,
        github_org: "test-org",
        repo_name: "test-repo",
        pr_number: "123",
        issue_number: "456",
        status: "pending",
        ai_provider: "anthropic",
        ai_model: "claude-3-opus"
      }
      
      {:ok, fix_attempt} = Rsolv.Billing.create_fix_attempt(fix_attempt_attrs)
      
      assert fix_attempt.customer_id == customer.id
      assert fix_attempt.status == "pending"
      assert fix_attempt.pr_number == "123"
    end
    
    @tag :skip
    test "customers have usage limits and tracking" do
      {:ok, user} = Rsolv.Accounts.register_user(%{
        email: "usage@example.com",
        password: "password123456"
      })
      
      {:ok, customer} = Rsolv.Customers.create_customer(user, %{
        name: "Usage Test Customer",
        monthly_limit: 100,
        plan: "starter"
      })
      
      assert customer.monthly_limit == 100
      assert customer.current_usage == 0
      assert customer.plan == "starter"
      
      # Track usage
      {:ok, updated_customer} = Rsolv.Customers.increment_usage(customer, 1)
      assert updated_customer.current_usage == 1
    end
  end
end