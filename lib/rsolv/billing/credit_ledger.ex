defmodule Rsolv.Billing.CreditLedger do
  @moduledoc """
  Credit ledger for tracking customer credit balance and transactions.

  All credit operations are atomic using Ecto.Multi to ensure consistency
  between customer balance and transaction records.

  ## Examples

      # Credit customer account
      {:ok, %{customer: customer, transaction: txn}} =
        CreditLedger.credit(customer, 100, "trial_signup")

      # Consume credits (prevents negative balance)
      {:ok, %{customer: customer, transaction: txn}} =
        CreditLedger.consume(customer, 1, "consumed", %{"fix_attempt_id" => "123"})

      # Get current balance
      balance = CreditLedger.get_balance(customer)

  """

  import Ecto.Query
  alias Ecto.Multi
  alias Rsolv.Repo
  alias Rsolv.Customers.Customer
  alias Rsolv.Billing.CreditTransaction

  @doc """
  Credits a customer account and records the transaction.

  Atomically updates the customer's credit balance and creates a transaction record.

  ## Parameters

    * `customer` - The customer to credit
    * `amount` - The number of credits to add (must be >= 0)
    * `source` - Transaction source (e.g., "trial_signup", "purchased")
    * `metadata` - Optional metadata map (default: %{})

  ## Returns

    * `{:ok, %{customer: customer, transaction: transaction}}` on success
    * `{:error, failed_operation, failed_value, changes_so_far}` on failure

  """
  def credit(customer, amount, source, metadata \\ %{})
      when is_integer(amount) and amount >= 0 do
    new_balance = customer.credit_balance + amount

    Multi.new()
    |> Multi.update(:customer, fn _ ->
      Customer.changeset(customer, %{credit_balance: new_balance})
    end)
    |> Multi.insert(:transaction, fn _ ->
      CreditTransaction.changeset(%CreditTransaction{}, %{
        customer_id: customer.id,
        amount: amount,
        balance_after: new_balance,
        source: source,
        metadata: metadata
      })
    end)
    |> Repo.transaction()
  end

  @doc """
  Consumes credits from a customer account and records the transaction.

  Atomically updates the customer's credit balance and creates a transaction record
  with a negative amount. Prevents the balance from going negative.

  ## Parameters

    * `customer` - The customer to debit
    * `amount` - The number of credits to consume (must be >= 0)
    * `source` - Transaction source (typically "consumed")
    * `metadata` - Optional metadata map (default: %{})

  ## Returns

    * `{:ok, %{customer: customer, transaction: transaction}}` on success
    * `{:error, :insufficient_credits}` if customer doesn't have enough credits
    * `{:error, failed_operation, failed_value, changes_so_far}` on other failures

  """
  def consume(customer, amount, source, metadata \\ %{})
      when is_integer(amount) and amount >= 0 do
    new_balance = customer.credit_balance - amount

    if new_balance < 0 do
      {:error, :insufficient_credits}
    else
      Multi.new()
      |> Multi.update(:customer, fn _ ->
        Customer.changeset(customer, %{credit_balance: new_balance})
      end)
      |> Multi.insert(:transaction, fn _ ->
        CreditTransaction.changeset(%CreditTransaction{}, %{
          customer_id: customer.id,
          amount: -amount,
          balance_after: new_balance,
          source: source,
          metadata: metadata
        })
      end)
      |> Repo.transaction()
    end
  end

  @doc """
  Returns the current credit balance for a customer.
  """
  def get_balance(%Customer{credit_balance: balance}), do: balance

  @doc """
  Lists all credit transactions for a customer, ordered by inserted_at descending.
  """
  def list_transactions(%Customer{id: customer_id}) do
    CreditTransaction
    |> where([t], t.customer_id == ^customer_id)
    |> order_by([t], desc: t.inserted_at)
    |> Repo.all()
  end
end
