defmodule Rsolv.BillingTablesMigrationTest do
  use Rsolv.DataCase, async: false
  alias Rsolv.Repo

  @moduletag :migration_test

  describe "billing tables schema" do
    test "subscription_plan renamed to subscription_type" do
      # Verify old column doesn't exist and new column does
      assert {:ok, result} =
               Repo.query(
                 "SELECT column_name FROM information_schema.columns
                  WHERE table_name = 'customers'
                  AND column_name = 'subscription_type'"
               )

      assert length(result.rows) == 1

      # Verify old column name is gone
      assert {:ok, result} =
               Repo.query(
                 "SELECT column_name FROM information_schema.columns
                  WHERE table_name = 'customers'
                  AND column_name = 'subscription_plan'"
               )

      assert length(result.rows) == 0
    end

    test "subscription_status renamed to subscription_state" do
      assert {:ok, result} =
               Repo.query(
                 "SELECT column_name FROM information_schema.columns
                  WHERE table_name = 'customers'
                  AND column_name = 'subscription_state'"
               )

      assert length(result.rows) == 1

      assert {:ok, result} =
               Repo.query(
                 "SELECT column_name FROM information_schema.columns
                  WHERE table_name = 'customers'
                  AND column_name = 'subscription_status'"
               )

      assert length(result.rows) == 0
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

      for column <- required_columns do
        assert {:ok, result} =
                 Repo.query(
                   "SELECT column_name FROM information_schema.columns
                    WHERE table_name = 'customers'
                    AND column_name = '#{column}'"
                 )

        assert length(result.rows) == 1, "Column #{column} should exist"
      end
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

      for column <- required_columns do
        assert {:ok, result} =
                 Repo.query(
                   "SELECT column_name FROM information_schema.columns
                    WHERE table_name = 'credit_transactions'
                    AND column_name = '#{column}'"
                 )

        assert length(result.rows) == 1, "Column #{column} should exist"
      end
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

      for column <- required_columns do
        assert {:ok, result} =
                 Repo.query(
                   "SELECT column_name FROM information_schema.columns
                    WHERE table_name = 'subscriptions'
                    AND column_name = '#{column}'"
                 )

        assert length(result.rows) == 1, "Column #{column} should exist"
      end
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

      for column <- required_columns do
        assert {:ok, result} =
                 Repo.query(
                   "SELECT column_name FROM information_schema.columns
                    WHERE table_name = 'billing_events'
                    AND column_name = '#{column}'"
                 )

        assert length(result.rows) == 1, "Column #{column} should exist"
      end
    end

    test "stripe_customer_id has unique index" do
      assert {:ok, result} =
               Repo.query(
                 "SELECT indexname FROM pg_indexes
                  WHERE tablename = 'customers'
                  AND indexdef LIKE '%UNIQUE%'
                  AND indexdef LIKE '%stripe_customer_id%'"
               )

      assert length(result.rows) >= 1
    end

    test "credit_transactions has customer_id index" do
      assert {:ok, result} =
               Repo.query(
                 "SELECT indexname FROM pg_indexes
                  WHERE tablename = 'credit_transactions'
                  AND indexdef LIKE '%customer_id%'"
               )

      assert length(result.rows) >= 1
    end

    test "billing_events has unique index on stripe_event_id for idempotency" do
      assert {:ok, result} =
               Repo.query(
                 "SELECT indexname FROM pg_indexes
                  WHERE tablename = 'billing_events'
                  AND indexdef LIKE '%UNIQUE%'
                  AND indexdef LIKE '%stripe_event_id%'"
               )

      assert length(result.rows) >= 1
    end
  end

  describe "subscription type values" do
    test "subscription_type can store trial, pay_as_you_go, and pro" do
      # This will be tested when we have the Customer schema and can insert records
      # For now, just verify the column exists
      assert {:ok, result} =
               Repo.query(
                 "SELECT data_type FROM information_schema.columns
                  WHERE table_name = 'customers'
                  AND column_name = 'subscription_type'"
               )

      assert length(result.rows) == 1
      # Should be a string type that can store these values
      assert [["character varying"]] = result.rows
    end
  end

  describe "subscription state behavior" do
    test "subscription_state column allows null values" do
      assert {:ok, result} =
               Repo.query(
                 "SELECT is_nullable FROM information_schema.columns
                  WHERE table_name = 'customers'
                  AND column_name = 'subscription_state'"
               )

      assert length(result.rows) == 1
      # subscription_state should be nullable (NULL for trial/PAYG customers)
      assert [["YES"]] = result.rows
    end
  end
end
