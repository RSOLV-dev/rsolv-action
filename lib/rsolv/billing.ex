defmodule Rsolv.Billing do
  @moduledoc """
  The Billing context for managing fix attempts, credits, subscriptions, and payments.

  This module provides a thin facade over specialized billing modules:
  - `Billing.CustomerSetup` - Customer onboarding and payment method setup
  - `Billing.SubscriptionManagement` - Subscription lifecycle management
  - `Billing.UsageTracking` - Fix deployment tracking and credit consumption
  - `Billing.CreditLedger` - Credit transaction management
  - `Billing.WebhookProcessor` - Stripe webhook handling
  """

  import Ecto.Query, warn: false

  alias Rsolv.Repo

  alias Rsolv.Billing.{
    FixAttempt,
    CreditLedger,
    Pricing,
    CustomerSetup,
    SubscriptionManagement,
    UsageTracking
  }

  alias Rsolv.Customers

  @doc """
  Returns the list of fix_attempts.

  ## Examples

      iex> list_fix_attempts()
      [%FixAttempt{}, ...]

  """
  def list_fix_attempts do
    Repo.all(FixAttempt)
  end

  @doc """
  Gets a single fix_attempt.

  Raises `Ecto.NoResultsError` if the Fix attempt does not exist.

  ## Examples

      iex> get_fix_attempt!(123)
      %FixAttempt{}

      iex> get_fix_attempt!(456)
      ** (Ecto.NoResultsError)

  """
  def get_fix_attempt!(id), do: Repo.get!(FixAttempt, id)

  @doc """
  Creates a fix_attempt.

  ## Examples

      iex> create_fix_attempt(%{field: value})
      {:ok, %FixAttempt{}}

      iex> create_fix_attempt(%{field: bad_value})
      {:error, %Ecto.Changeset{}}

  """
  def create_fix_attempt(attrs \\ %{}) do
    %FixAttempt{}
    |> FixAttempt.changeset(attrs)
    |> Repo.insert()
  end

  @doc """
  Updates a fix_attempt.

  ## Examples

      iex> update_fix_attempt(fix_attempt, %{field: new_value})
      {:ok, %FixAttempt{}}

      iex> update_fix_attempt(fix_attempt, %{field: bad_value})
      {:error, %Ecto.Changeset{}}

  """
  def update_fix_attempt(%FixAttempt{} = fix_attempt, attrs) do
    fix_attempt
    |> FixAttempt.changeset(attrs)
    |> Repo.update()
  end

  @doc """
  Deletes a fix_attempt.

  ## Examples

      iex> delete_fix_attempt(fix_attempt)
      {:ok, %FixAttempt{}}

      iex> delete_fix_attempt(fix_attempt)
      {:error, %Ecto.Changeset{}}

  """
  def delete_fix_attempt(%FixAttempt{} = fix_attempt) do
    Repo.delete(fix_attempt)
  end

  @doc """
  Returns an `%Ecto.Changeset{}` for tracking fix_attempt changes.

  ## Examples

      iex> change_fix_attempt(fix_attempt)
      %Ecto.Changeset{data: %FixAttempt{}}

  """
  def change_fix_attempt(%FixAttempt{} = fix_attempt, attrs \\ %{}) do
    FixAttempt.changeset(fix_attempt, attrs)
  end

  @doc """
  Lists fix attempts for a customer.

  ## Examples

      iex> list_fix_attempts_for_customer(customer_id)
      [%FixAttempt{}, ...]

  """
  def list_fix_attempts_for_customer(customer_id) do
    FixAttempt
    |> where([f], f.customer_id == ^customer_id)
    |> order_by([f], desc: f.created_at)
    |> Repo.all()
  end

  @doc """
  Gets fix attempt statistics for a customer.

  ## Examples

      iex> get_customer_stats(customer_id)
      %{total_attempts: 10, successful: 8, failed: 2}

  """
  def get_customer_stats(customer_id) do
    stats =
      FixAttempt
      |> where([f], f.customer_id == ^customer_id)
      |> group_by([f], f.status)
      |> select([f], {f.status, count(f.id)})
      |> Repo.all()
      |> Enum.into(%{})

    %{
      total_attempts: Map.values(stats) |> Enum.sum(),
      successful: Map.get(stats, "merged", 0),
      failed: Map.get(stats, "failed", 0) + Map.get(stats, "error", 0),
      pending: Map.get(stats, "pending", 0) + Map.get(stats, "in_progress", 0)
    }
  end

  @doc """
  Records usage data for tracking purposes.
  This is a placeholder implementation during Phase 3 integration.

  ## Examples

      iex> record_usage(%{customer_id: 1, provider: "anthropic", tokens_used: 100})
      {:ok, %{}}

  """
  def record_usage(usage_attrs) do
    # For now, this is a simple logging implementation
    # In the future this could create usage_records or update metrics
    require Logger
    Logger.info("Usage recorded: #{inspect(usage_attrs)}")
    {:ok, usage_attrs}
  end

  @doc """
  Creates a Stripe customer for a newly provisioned customer.

  Delegates to `Billing.CustomerSetup.create_stripe_customer/1`.

  ## Examples

      iex> create_stripe_customer(customer)
      {:ok, "cus_test123"}

  """
  defdelegate create_stripe_customer(customer), to: CustomerSetup

  @doc """
  Adds a payment method to a customer and grants billing addition bonus.

  Delegates to `Billing.CustomerSetup.add_payment_method/3`.

  ## Examples

      iex> add_payment_method(customer, "pm_abc", true)
      {:ok, %Customer{credit_balance: 15, ...}}

  """
  defdelegate add_payment_method(customer, payment_method_id, billing_consent), to: CustomerSetup

  @doc """
  Subscribes a customer to the Pro plan.

  Delegates to `Billing.SubscriptionManagement.subscribe_to_pro/1`.

  ## Examples

      iex> subscribe_to_pro(customer)
      {:ok, %Customer{subscription_type: "pro", ...}}

      iex> subscribe_to_pro(customer_without_payment_method)
      {:error, :no_payment_method}

  """
  defdelegate subscribe_to_pro(customer), to: SubscriptionManagement

  @doc """
  Cancels a customer's subscription.

  Delegates to `Billing.SubscriptionManagement.cancel_subscription/2`.

  ## Parameters
  - customer: The customer whose subscription to cancel
  - at_period_end: If true, schedule cancellation at period end. If false, cancel immediately.

  ## Examples

      iex> cancel_subscription(customer, true)
      {:ok, %Customer{subscription_cancel_at_period_end: true, ...}}

      iex> cancel_subscription(customer, false)
      {:ok, %Customer{subscription_type: "pay_as_you_go", ...}}

  """
  defdelegate cancel_subscription(customer, at_period_end), to: SubscriptionManagement

  # INTEGRATION POINT: RFC-060 Amendment 001
  # This function is called after validation/mitigation phases complete.
  @doc """
  Track fix deployment and consume credit or charge customer.

  Delegates to `Billing.UsageTracking.track_fix_deployed/2`.

  Flow:
  1. Has credits? → Consume 1 credit
  2. No credits, no billing → Error (block)
  3. No credits, has billing → Charge → Credit 1 → Consume 1

  ## Examples

      # Has credits - consume directly
      iex> customer = %Customer{id: 1, credit_balance: 10}
      iex> fix = %{id: 42}
      iex> {:ok, %{customer: customer, transaction: txn}} = Billing.track_fix_deployed(customer, fix)
      iex> txn.balance_after
      9

      # No credits, no billing - block
      iex> customer = %Customer{id: 1, credit_balance: 0, stripe_customer_id: nil}
      iex> fix = %{id: 42}
      iex> Billing.track_fix_deployed(customer, fix)
      {:error, :no_billing_info}

      # No credits, has billing - charge then consume
      iex> customer = %Customer{id: 1, credit_balance: 0, stripe_customer_id: "cus_123", subscription_type: "pay_as_you_go"}
      iex> fix = %{id: 42}
      iex> {:ok, :charged_and_consumed} = Billing.track_fix_deployed(customer, fix)
  """
  defdelegate track_fix_deployed(customer, fix), to: UsageTracking

  @doc """
  Returns true if customer has available credits.

  Delegates to `Billing.UsageTracking.has_credits?/1`.

  ## Examples

      iex> has_credits?(%Customer{credit_balance: 5})
      true

      iex> has_credits?(%Customer{credit_balance: 0})
      false

  """
  defdelegate has_credits?(customer), to: UsageTracking

  @doc """
  Returns true if customer has billing information configured.

  Delegates to `Billing.UsageTracking.has_billing_info?/1`.

  ## Examples

      iex> has_billing_info?(%Customer{stripe_customer_id: "cus_123"})
      true

      iex> has_billing_info?(%Customer{stripe_customer_id: nil})
      false

  """
  defdelegate has_billing_info?(customer), to: UsageTracking

  @doc """
  Lists credit transactions for a customer.

  ## Examples

      iex> list_credit_transactions(customer_id)
      [%CreditTransaction{}, ...]
  """
  def list_credit_transactions(customer_id) do
    customer = Customers.get_customer!(customer_id)
    CreditLedger.list_transactions(customer)
  end

  @doc """
  Gets usage summary for customer portal (RFC-071).

  Returns current credit balance, plan details, recent transactions,
  and warning messages when credits are running low.

  ## Examples

      iex> get_usage_summary(customer_id)
      {:ok, %{
        credit_balance: 5,
        subscription_type: "pro",
        subscription_state: "active",
        recent_transactions: [...],
        warnings: ["Low credit balance: 5 credits remaining"]
      }}
  """
  def get_usage_summary(customer_id) do
    customer = Customers.get_customer!(customer_id)
    recent_transactions = customer |> CreditLedger.list_transactions() |> Enum.take(10)

    summary = %{
      credit_balance: customer.credit_balance,
      subscription_type: customer.subscription_type,
      subscription_state: customer.subscription_state,
      has_payment_method: customer.has_payment_method,
      recent_transactions: format_transactions_for_display(recent_transactions),
      warnings: calculate_warnings(customer),
      pricing: Pricing.summary()
    }

    {:ok, summary}
  end

  # Private helper to format transactions for display
  defp format_transactions_for_display(transactions) do
    Enum.map(transactions, fn txn ->
      %{
        id: txn.id,
        amount: txn.amount,
        balance_after: txn.balance_after,
        source: txn.source,
        metadata: txn.metadata,
        inserted_at: txn.inserted_at
      }
    end)
  end

  # Private helper to calculate warning messages
  defp calculate_warnings(customer) do
    warnings = []

    warnings =
      cond do
        customer.credit_balance == 0 && !customer.has_payment_method ->
          [
            "No credits remaining and no payment method on file. Add a payment method to continue using RSOLV."
            | warnings
          ]

        customer.credit_balance == 0 ->
          ["No credits remaining. Your next fix will be charged." | warnings]

        customer.credit_balance <= 5 ->
          ["Low credit balance: #{customer.credit_balance} credits remaining" | warnings]

        true ->
          warnings
      end

    if customer.subscription_state == "past_due" do
      ["Payment failed. Please update your payment method." | warnings]
    else
      warnings
    end
  end
end
