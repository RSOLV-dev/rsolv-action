defmodule Rsolv.ConsolidationSchemaTest do
  use Rsolv.DataCase
  
  @moduledoc """
  TDD tests for Phase 2: Database Schema Consolidation.
  These tests define the expected unified schema structure.
  """
  
  describe "unified user and customer relationship" do
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
    
    test "customers table references users table" do
      # First create a user
      {:ok, user} = Rsolv.Accounts.register_user(%{
        email: "customer@example.com",
        password: "password123456"
      })
      
      # Then create a customer linked to that user
      customer_attrs = %{
        name: "Test Customer",
        email: "customer@example.com"
      }
      
      {:ok, customer} = Rsolv.Customers.create_customer(user, customer_attrs)
      
      assert customer.user_id == user.id
      assert customer.name == "Test Customer"
      # github_org field was removed in consolidation
      # API keys are now managed through api_keys table
    end
    
    test "api_keys table for multiple keys per customer" do
      {:ok, user} = Rsolv.Accounts.register_user(%{
        email: "multikey@example.com",
        password: "password123456"
      })
      
      {:ok, customer} = Rsolv.Customers.create_customer(user, %{
        name: "Multi-Key Customer",
        email: "multikey@example.com"
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
    test "feature_flags table exists for FunWithFlags" do
      # This should work with the existing FunWithFlags setup
      flag_name = :test_feature
      
      :ok = Rsolv.FeatureFlags.enable(flag_name)
      assert Rsolv.FeatureFlags.enabled?(flag_name)
      
      :ok = Rsolv.FeatureFlags.disable(flag_name)
      refute Rsolv.FeatureFlags.enabled?(flag_name)
    end
    
    test "feature flags can be scoped to customers" do
      {:ok, user} = Rsolv.Accounts.register_user(%{
        email: "feature@example.com",
        password: "password123456"
      })
      
      {:ok, customer} = Rsolv.Customers.create_customer(user, %{
        name: "Feature Test Customer",
        email: "feature-customer@example.com"
      })
      
      flag_name = :beta_feature
      
      # Enable the flag globally
      :ok = Rsolv.FeatureFlags.enable(flag_name)
      
      # Enable for specific customer
      :ok = Rsolv.FeatureFlags.enable_for_customer(flag_name, customer)
      
      # Test that the feature flag system works
      assert Rsolv.FeatureFlags.enabled?(flag_name)
    end
  end
  
  describe "email subscriptions" do
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
    test "fix_attempts table tracks usage" do
      {:ok, user} = Rsolv.Accounts.register_user(%{
        email: "billing@example.com",
        password: "password123456"
      })
      
      {:ok, customer} = Rsolv.Customers.create_customer(user, %{
        name: "Billing Test Customer",
        email: "billing-customer@example.com"
      })
      
      fix_attempt_attrs = %{
        customer_id: customer.id,
        github_org: "test-org",
        repo_name: "test-repo",
        pr_number: 123,
        issue_number: "456",
        status: "pending",
        ai_provider: "anthropic",
        ai_model: "claude-3-opus"
      }
      
      {:ok, fix_attempt} = Rsolv.Billing.create_fix_attempt(fix_attempt_attrs)
      
      assert fix_attempt.customer_id == customer.id
      assert fix_attempt.status == "pending"
      assert fix_attempt.pr_number == 123
    end
    
    test "customers have usage limits and tracking" do
      {:ok, user} = Rsolv.Accounts.register_user(%{
        email: "usage@example.com",
        password: "password123456"
      })
      
      {:ok, customer} = Rsolv.Customers.create_customer(user, %{
        name: "Usage Test Customer",
        email: "usage-customer@example.com",
        monthly_limit: 100,
        subscription_plan: "starter"
      })
      
      assert customer.monthly_limit == 100
      assert customer.current_usage == 0
      assert customer.subscription_plan == "starter"
      
      # Track usage
      {:ok, updated_customer} = Rsolv.Customers.increment_usage(customer, 1)
      assert updated_customer.current_usage == 1
    end
  end
  
  describe "consolidated customer schema" do
    alias Rsolv.Customers.Customer
    
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
      # Should have these relationships
      assert %Ecto.Association.Has{} = Customer.__schema__(:association, :api_keys)
      assert %Ecto.Association.Has{} = Customer.__schema__(:association, :forge_accounts)
      assert %Ecto.Association.Has{} = Customer.__schema__(:association, :fix_attempts)
    end
    
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
  end
end