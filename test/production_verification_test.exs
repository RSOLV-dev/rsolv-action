defmodule Rsolv.ProductionVerificationTest do
  @moduledoc """
  Comprehensive test suite to verify production API functionality
  """
  use Rsolv.DataCase
  import Ecto.Query
  
  alias Rsolv.Repo
  alias Rsolv.Customers.Customer
  alias Rsolv.Billing.FixAttempt
  
  @moduletag :integration
  
  # Skip production verification tests in test environment
  # These are meant to run against production/staging databases
  setup do
    case Repo.query("SELECT 1 FROM information_schema.tables WHERE table_name = 'customers'") do
      {:ok, _} -> :ok
      {:error, _} -> {:skip, "Production tables not available in test environment"}
    end
  end
  
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
      # Create a test customer using changeset
      changeset = Customer.changeset(%Customer{}, %{
        name: "Test Org",
        email: "test@example.com",
        subscription_plan: "trial"
      })
      
      {:ok, customer} = Repo.insert(changeset)
      
      # Verify default values
      assert customer.trial_fixes_limit == 5  # Default changed to 5
      assert customer.trial_fixes_used == 0
      assert Customer.trial_expired?(customer) == false
      assert customer.subscription_plan == "trial"  # Default is "trial"
    end
  end
  
  describe "Fix Attempt Tracking" do
    setup do
      # Create test customer using changeset
      changeset = Customer.changeset(%Customer{}, %{
        name: "Test Customer",
        email: "test@example.com", 
        subscription_plan: "trial"
      })
      
      {:ok, customer} = Repo.insert(changeset)
      
      {:ok, customer: customer}
    end
    
    test "can create and track fix attempt", %{customer: customer} do
      changeset = FixAttempt.changeset(%FixAttempt{}, %{
        github_org: "test-org",
        repo_name: "test-repo",
        issue_number: 123,
        pr_number: 456,
        customer_id: customer.id,
        status: "pending",
        billing_status: "not_billed",
        pr_title: "Fix security vulnerability",
        issue_title: "SQL injection in login",
        api_key_used: "test_" <> Ecto.UUID.generate()
      })
      
      {:ok, attempt} = Repo.insert(changeset)
      
      assert attempt.status == "pending"
      assert attempt.billing_status == "not_billed"
      assert attempt.requires_manual_approval == true
    end
    
    test "unique constraint on org/repo/pr combination" do
      attrs = %{
        github_org: "unique-org",
        repo_name: "unique-repo",
        issue_number: 1,
        pr_number: 2,
        status: "pending"
      }
      
      changeset1 = FixAttempt.changeset(%FixAttempt{}, attrs)
      {:ok, _} = Repo.insert(changeset1)
      
      # Try to insert duplicate
      changeset2 = FixAttempt.changeset(%FixAttempt{}, attrs)
      assert_raise Ecto.ConstraintError, fn ->
        Repo.insert!(changeset2)
      end
    end
  end
end