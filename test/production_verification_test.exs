defmodule RSOLV.ProductionVerificationTest do
  @moduledoc """
  Comprehensive test suite to verify production API functionality
  """
  use RsolvApi.DataCase
  import Ecto.Query
  
  alias RsolvApi.Repo
  
  @moduletag :integration
  
  describe "Database Schema Verification" do
    test "fix_attempts table exists with all required columns" do
      # Query to check table structure
      query = """
      SELECT column_name, data_type, is_nullable
      FROM information_schema.columns
      WHERE table_name = 'fix_attempts'
      ORDER BY ordinal_position;
      """
      
      result = Repo.query!(query)
      columns = Enum.map(result.rows, fn [name, type, nullable] -> 
        %{name: name, type: type, nullable: nullable}
      end)
      
      # Verify essential columns exist
      assert Enum.find(columns, &(&1.name == "github_org"))
      assert Enum.find(columns, &(&1.name == "repo_name"))
      assert Enum.find(columns, &(&1.name == "issue_number"))
      assert Enum.find(columns, &(&1.name == "pr_number"))
      assert Enum.find(columns, &(&1.name == "status"))
      assert Enum.find(columns, &(&1.name == "billing_status"))
      assert Enum.find(columns, &(&1.name == "customer_id"))
      assert Enum.find(columns, &(&1.name == "amount"))
      assert Enum.find(columns, &(&1.name == "requires_manual_approval"))
    end
    
    test "customers table has trial tracking fields" do
      query = """
      SELECT column_name
      FROM information_schema.columns
      WHERE table_name = 'customers'
      AND column_name IN ('trial_fixes_used', 'trial_fixes_limit', 'trial_expired', 
                          'subscription_plan', 'rollover_fixes', 'stripe_customer_id');
      """
      
      result = Repo.query!(query)
      column_names = Enum.map(result.rows, fn [name] -> name end)
      
      assert "trial_fixes_used" in column_names
      assert "trial_fixes_limit" in column_names
      assert "trial_expired" in column_names
      assert "subscription_plan" in column_names
      assert "rollover_fixes" in column_names
      assert "stripe_customer_id" in column_names
    end
    
    test "all required indexes exist" do
      query = """
      SELECT indexname
      FROM pg_indexes
      WHERE tablename IN ('fix_attempts', 'customers')
      AND schemaname = 'public';
      """
      
      result = Repo.query!(query)
      index_names = Enum.map(result.rows, fn [name] -> name end)
      
      # Fix attempts indexes
      assert "fix_attempts_github_org_repo_name_pr_number_index" in index_names
      assert "fix_attempts_customer_id_index" in index_names
      assert "fix_attempts_status_index" in index_names
      assert "fix_attempts_billing_status_index" in index_names
      
      # Customer indexes
      assert "customers_trial_expired_index" in index_names
      assert "customers_subscription_status_index" in index_names
    end
  end
  
  describe "Trial Limit Enforcement" do
    test "default trial limit is 10 fixes" do
      # Create a test customer
      {:ok, customer} = Repo.insert(%{
        name: "Test Org",
        email: "test@example.com",
        api_key: "test_#{:crypto.strong_rand_bytes(16) |> Base.encode16()}",
        active: true
      })
      
      # Verify default values
      assert customer.trial_fixes_limit == 10
      assert customer.trial_fixes_used == 0
      assert customer.trial_expired == false
      assert customer.subscription_plan == "pay_as_you_go"
    end
  end
  
  describe "Fix Attempt Tracking" do
    setup do
      # Create test customer
      {:ok, customer} = Repo.insert(%{
        name: "Test Customer",
        email: "test@example.com", 
        api_key: "test_key_#{System.unique_integer([:positive])}",
        active: true
      })
      
      {:ok, customer: customer}
    end
    
    test "can create and track fix attempt", %{customer: customer} do
      fix_attempt = %{
        github_org: "test-org",
        repo_name: "test-repo",
        issue_number: 123,
        pr_number: 456,
        customer_id: customer.id,
        status: "pending",
        billing_status: "not_billed",
        pr_title: "Fix security vulnerability",
        issue_title: "SQL injection in login",
        api_key_used: customer.api_key
      }
      
      {:ok, attempt} = Repo.insert(fix_attempt)
      
      assert attempt.status == "pending"
      assert attempt.billing_status == "not_billed"
      assert attempt.requires_manual_approval == true
    end
    
    test "unique constraint on org/repo/pr combination" do
      fix_attempt = %{
        github_org: "unique-org",
        repo_name: "unique-repo",
        issue_number: 1,
        pr_number: 2,
        status: "pending"
      }
      
      {:ok, _} = Repo.insert(fix_attempt)
      
      # Try to insert duplicate
      assert_raise Ecto.ConstraintError, fn ->
        Repo.insert!(fix_attempt)
      end
    end
  end
end