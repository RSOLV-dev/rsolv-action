defmodule Rsolv.Billing.CreditLedgerTest do
  use Rsolv.DataCase, async: true

  alias Rsolv.Billing.CreditLedger
  alias Rsolv.Customers.Customer
  alias Rsolv.Repo

  describe "credit/3" do
    test "credits customer account atomically" do
      customer = insert(:customer, credit_balance: 100)

      assert {:ok, %{customer: updated_customer, transaction: transaction}} =
               CreditLedger.credit(customer, 50, "purchased")

      assert updated_customer.credit_balance == 150
      assert transaction.amount == 50
      assert transaction.balance_after == 150
      assert transaction.source == "purchased"
      assert transaction.customer_id == customer.id
    end

    test "records transaction with metadata" do
      customer = insert(:customer, credit_balance: 100)
      metadata = %{"payment_id" => "pi_123", "invoice_id" => "inv_456"}

      assert {:ok, %{transaction: transaction}} =
               CreditLedger.credit(customer, 25, "pro_subscription_payment", metadata)

      assert transaction.metadata == metadata
    end

    test "updates balance and creates transaction in single database transaction" do
      customer = insert(:customer, credit_balance: 100)

      # Simulate failure during transaction by passing invalid metadata
      # This ensures atomicity - if transaction creation fails, balance update should rollback
      # For now, we'll just test the happy path and verify both records are created
      assert {:ok, result} = CreditLedger.credit(customer, 50, "purchased")

      # Verify both updates happened
      updated_customer = Repo.get!(Rsolv.Accounts.Customer, customer.id)
      assert updated_customer.credit_balance == 150

      # Verify transaction was created
      assert result.transaction.customer_id == customer.id
      assert result.transaction.amount == 50
    end

    test "allows crediting zero credits for audit trail" do
      customer = insert(:customer, credit_balance: 100)

      assert {:ok, %{customer: updated_customer, transaction: transaction}} =
               CreditLedger.credit(customer, 0, "adjustment")

      assert updated_customer.credit_balance == 100
      assert transaction.amount == 0
      assert transaction.balance_after == 100
    end
  end

  describe "consume/3" do
    test "prevents negative balance on consume" do
      customer = insert(:customer, credit_balance: 10)

      assert {:error, :insufficient_credits} = CreditLedger.consume(customer, 15, "consumed")

      # Verify balance unchanged
      updated_customer = Repo.get!(Rsolv.Accounts.Customer, customer.id)
      assert updated_customer.credit_balance == 10
    end

    test "consumes credits atomically with negative amount" do
      customer = insert(:customer, credit_balance: 100)

      assert {:ok, %{customer: updated_customer, transaction: transaction}} =
               CreditLedger.consume(customer, 25, "consumed")

      assert updated_customer.credit_balance == 75
      assert transaction.amount == -25
      assert transaction.balance_after == 75
      assert transaction.source == "consumed"
    end

    test "records transaction with source and metadata" do
      customer = insert(:customer, credit_balance: 100)
      metadata = %{"fix_attempt_id" => "fa_123", "repository" => "org/repo"}

      assert {:ok, %{transaction: transaction}} =
               CreditLedger.consume(customer, 1, "consumed", metadata)

      assert transaction.source == "consumed"
      assert transaction.metadata == metadata
      assert transaction.amount == -1
    end

    test "allows consuming exactly all credits" do
      customer = insert(:customer, credit_balance: 50)

      assert {:ok, %{customer: updated_customer, transaction: transaction}} =
               CreditLedger.consume(customer, 50, "consumed")

      assert updated_customer.credit_balance == 0
      assert transaction.amount == -50
      assert transaction.balance_after == 0
    end

    test "creates transaction record even when consuming 0 credits" do
      customer = insert(:customer, credit_balance: 100)

      assert {:ok, %{customer: updated_customer, transaction: transaction}} =
               CreditLedger.consume(customer, 0, "test")

      assert updated_customer.credit_balance == 100
      assert transaction.amount == 0
      assert transaction.balance_after == 100
    end
  end

  describe "get_balance/1" do
    test "returns current credit balance for customer" do
      customer = insert(:customer, credit_balance: 150)

      assert CreditLedger.get_balance(customer) == 150
    end
  end

  describe "transaction history" do
    test "list_transactions/1 returns all transactions for customer" do
      customer = insert(:customer, credit_balance: 0)
      other_customer = insert(:customer)

      {:ok, _} = CreditLedger.credit(customer, 100, "trial_signup")
      {:ok, _} = CreditLedger.consume(customer, 10, "consumed")
      {:ok, _} = CreditLedger.credit(other_customer, 50, "trial_signup")

      transactions = CreditLedger.list_transactions(customer)

      assert length(transactions) == 2
      assert Enum.all?(transactions, fn t -> t.customer_id == customer.id end)
    end

    test "list_transactions/1 orders by inserted_at descending" do
      customer = insert(:customer, credit_balance: 0)

      {:ok, %{transaction: t1}} = CreditLedger.credit(customer, 100, "trial_signup")
      Process.sleep(10)
      {:ok, %{transaction: t2}} = CreditLedger.consume(customer, 10, "consumed")
      Process.sleep(10)
      {:ok, %{transaction: t3}} = CreditLedger.credit(customer, 50, "purchased")

      transactions = CreditLedger.list_transactions(customer)

      assert length(transactions) == 3
      assert Enum.map(transactions, & &1.id) == [t3.id, t2.id, t1.id]
    end
  end
end
