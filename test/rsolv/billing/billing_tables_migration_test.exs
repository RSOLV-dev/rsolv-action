defmodule Rsolv.BillingTablesMigrationTest do
  use Rsolv.DataCase, async: false
  alias Rsolv.Repo
  alias Rsolv.Customers.Customer

  @moduletag :migration_test

  # Helper function to check if a column exists in a table
  defp assert_column_exists(table_name, column_name) do
    assert {:ok, result} =
             Repo.query("SELECT column_name FROM information_schema.columns
                WHERE table_name = '#{table_name}'
                AND column_name = '#{column_name}'")

    assert length(result.rows) == 1, "Column #{column_name} should exist in #{table_name}"
  end

  # Helper function to check multiple columns exist in a table
  defp assert_columns_exist(table_name, column_names) do
    for column <- column_names do
      assert_column_exists(table_name, column)
    end
  end

  describe "billing tables schema" do
    test "subscription_plan renamed to subscription_type" do
      # Verify old column doesn't exist and new column does
      assert {:ok, result} =
               Repo.query("SELECT column_name FROM information_schema.columns
                  WHERE table_name = 'customers'
                  AND column_name = 'subscription_type'")

      assert length(result.rows) == 1

      # Verify old column name is gone
      assert {:ok, result} =
               Repo.query("SELECT column_name FROM information_schema.columns
                  WHERE table_name = 'customers'
                  AND column_name = 'subscription_plan'")

      assert result.rows == []
    end

    test "subscription_status renamed to subscription_state" do
      assert {:ok, result} =
               Repo.query("SELECT column_name FROM information_schema.columns
                  WHERE table_name = 'customers'
                  AND column_name = 'subscription_state'")

      assert length(result.rows) == 1

      assert {:ok, result} =
               Repo.query("SELECT column_name FROM information_schema.columns
                  WHERE table_name = 'customers'
                  AND column_name = 'subscription_status'")

      assert result.rows == []
    end

    test "customers table has billing fields" do
      required_columns = [
        "credit_balance",
        "stripe_customer_id",
        "stripe_payment_method_id",
        "stripe_subscription_id",
        "billing_consent_given",
        "billing_consent_at",
        "subscription_cancel_at_period_end"
      ]

      assert_columns_exist("customers", required_columns)
    end

    test "credit_transactions table exists with correct structure" do
      assert {:ok, _} = Repo.query("SELECT * FROM credit_transactions LIMIT 0")

      required_columns = [
        "id",
        "customer_id",
        "amount",
        "balance_after",
        "source",
        "metadata",
        "inserted_at",
        "updated_at"
      ]

      assert_columns_exist("credit_transactions", required_columns)
    end

    test "subscriptions table exists with correct structure" do
      assert {:ok, _} = Repo.query("SELECT * FROM subscriptions LIMIT 0")

      required_columns = [
        "id",
        "customer_id",
        "stripe_subscription_id",
        "plan",
        "status",
        "current_period_start",
        "current_period_end",
        "cancel_at_period_end",
        "inserted_at",
        "updated_at"
      ]

      assert_columns_exist("subscriptions", required_columns)
    end

    test "billing_events table exists with correct structure" do
      assert {:ok, _} = Repo.query("SELECT * FROM billing_events LIMIT 0")

      required_columns = [
        "id",
        "customer_id",
        "stripe_event_id",
        "event_type",
        "amount_cents",
        "metadata",
        "inserted_at",
        "updated_at"
      ]

      assert_columns_exist("billing_events", required_columns)
    end

    test "stripe_customer_id has unique index" do
      assert {:ok, result} =
               Repo.query("SELECT indexname FROM pg_indexes
                  WHERE tablename = 'customers'
                  AND indexdef LIKE '%UNIQUE%'
                  AND indexdef LIKE '%stripe_customer_id%'")

      assert length(result.rows) >= 1
    end

    test "credit_transactions has customer_id index" do
      assert {:ok, result} =
               Repo.query("SELECT indexname FROM pg_indexes
                  WHERE tablename = 'credit_transactions'
                  AND indexdef LIKE '%customer_id%'")

      assert length(result.rows) >= 1
    end

    test "billing_events has unique index on stripe_event_id for idempotency" do
      assert {:ok, result} =
               Repo.query("SELECT indexname FROM pg_indexes
                  WHERE tablename = 'billing_events'
                  AND indexdef LIKE '%UNIQUE%'
                  AND indexdef LIKE '%stripe_event_id%'")

      assert length(result.rows) >= 1
    end
  end

  describe "subscription type values" do
    test "subscription_type can store trial, pay_as_you_go, and pro" do
      # This will be tested when we have the Customer schema and can insert records
      # For now, just verify the column exists
      assert {:ok, result} =
               Repo.query("SELECT data_type FROM information_schema.columns
                  WHERE table_name = 'customers'
                  AND column_name = 'subscription_type'")

      assert length(result.rows) == 1
      # Should be a string type that can store these values
      assert [["character varying"]] = result.rows
    end
  end

  describe "subscription state behavior" do
    test "subscription_state column allows null values" do
      assert {:ok, result} =
               Repo.query("SELECT is_nullable FROM information_schema.columns
                  WHERE table_name = 'customers'
                  AND column_name = 'subscription_state'")

      assert length(result.rows) == 1
      # subscription_state should be nullable (NULL for trial/PAYG customers)
      assert [["YES"]] = result.rows
    end

    test "subscription_state stores Stripe states for Pro customers" do
      # Create a test customer with subscription_state set to Stripe states
      customer = insert(:customer, subscription_type: "pro", subscription_state: "active")
      assert customer.subscription_state == "active"

      # Verify we can update to other Stripe states
      {:ok, updated} =
        Repo.update(Customer.changeset(customer, %{subscription_state: "past_due"}))

      assert updated.subscription_state == "past_due"

      # Verify the column can store typical Stripe subscription states
      stripe_states = ["active", "past_due", "canceled", "unpaid", "trialing", "incomplete"]

      for state <- stripe_states do
        {:ok, c} = Repo.update(Customer.changeset(customer, %{subscription_state: state}))
        assert c.subscription_state == state
      end
    end
  end
end
