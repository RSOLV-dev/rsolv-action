defmodule Rsolv.Billing do
  @moduledoc """
  The Billing context for managing fix attempts, credits, subscriptions, and payments.
  """

  import Ecto.Query, warn: false

  alias Rsolv.Repo
  alias Rsolv.Billing.{FixAttempt, StripeService, CreditLedger, Subscription, Config, Pricing}
  alias Rsolv.Customers.Customer
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
  Adds a payment method to a customer and grants billing addition bonus.

  This function:
  1. Validates billing consent was given
  2. Attaches payment method to Stripe customer
  3. Updates customer record with payment method details
  4. Credits +5 credits as billing addition bonus (trial_billing_added)

  ## Examples

      iex> add_payment_method(customer, "pm_abc", true)
      {:ok, %Customer{credit_balance: 15, ...}}

      iex> add_payment_method(customer, "pm_abc", false)
      {:error, :billing_consent_required}

  """
  def add_payment_method(%Customer{} = customer, payment_method_id, true = _billing_consent) do
    with {:ok, _} <-
           StripeService.attach_payment_method(customer.stripe_customer_id, payment_method_id) do
      update_customer_with_payment_method_and_credit(customer, payment_method_id)
    end
  end

  def add_payment_method(%Customer{}, _payment_method_id, false = _billing_consent) do
    {:error, :billing_consent_required}
  end

  # Private helper to update customer and add credits atomically
  defp update_customer_with_payment_method_and_credit(customer, payment_method_id) do
    now = DateTime.utc_now()
    bonus_credits = Config.trial_billing_addition_bonus()

    Ecto.Multi.new()
    |> Ecto.Multi.update(
      :customer,
      Customer.changeset(customer, %{
        stripe_payment_method_id: payment_method_id,
        has_payment_method: true,
        billing_consent_given: true,
        billing_consent_at: now,
        payment_method_added_at: now
      })
    )
    |> Ecto.Multi.run(:credit, fn _repo, %{customer: updated_customer} ->
      CreditLedger.credit(
        updated_customer,
        bonus_credits,
        "trial_billing_added",
        %{payment_method_id: payment_method_id}
      )
    end)
    |> Repo.transaction()
    |> case do
      {:ok, %{credit: %{customer: customer_with_credits}}} ->
        {:ok, customer_with_credits}

      {:error, _failed_operation, changeset, _changes} ->
        {:error, changeset}
    end
  end

  @doc """
  Subscribes a customer to the Pro plan.

  This function:
  1. Creates a Stripe subscription with the Pro price
  2. Updates customer record with subscription details
  3. Records the subscription in the subscriptions table

  The initial credit is added via webhook when invoice.paid is received.

  ## Examples

      iex> subscribe_to_pro(customer)
      {:ok, %Customer{subscription_type: "pro", ...}}

      iex> subscribe_to_pro(customer_without_payment_method)
      {:error, :no_payment_method}

  """
  def subscribe_to_pro(%Customer{has_payment_method: false}), do: {:error, :no_payment_method}

  def subscribe_to_pro(%Customer{} = customer) do
    pro_price_id = Config.pro_price_id()

    with {:ok, stripe_subscription} <-
           StripeService.create_subscription(customer.stripe_customer_id, pro_price_id) do
      create_subscription_records(customer, stripe_subscription)
    end
  end

  # Private helper to create customer and subscription records atomically
  defp create_subscription_records(customer, stripe_subscription) do
    Ecto.Multi.new()
    |> Ecto.Multi.update(
      :customer,
      Customer.changeset(customer, %{
        stripe_subscription_id: stripe_subscription.id,
        subscription_type: "pro",
        subscription_state: stripe_subscription.status,
        subscription_cancel_at_period_end: false
      })
    )
    |> Ecto.Multi.insert(:subscription, fn %{customer: updated_customer} ->
      Subscription.changeset(%Subscription{}, %{
        customer_id: updated_customer.id,
        stripe_subscription_id: stripe_subscription.id,
        plan: "pro",
        status: stripe_subscription.status,
        current_period_start: DateTime.from_unix!(stripe_subscription.current_period_start),
        current_period_end: DateTime.from_unix!(stripe_subscription.current_period_end),
        cancel_at_period_end: false
      })
    end)
    |> Repo.transaction()
    |> case do
      {:ok, %{customer: updated_customer}} -> {:ok, updated_customer}
      {:error, _op, changeset, _changes} -> {:error, changeset}
    end
  end

  @doc """
  Cancels a customer's subscription.

  ## Parameters
  - customer: The customer whose subscription to cancel
  - at_period_end: If true, schedule cancellation at period end. If false, cancel immediately.

  ## Examples

      iex> cancel_subscription(customer, true)
      {:ok, %Customer{subscription_cancel_at_period_end: true, ...}}

      iex> cancel_subscription(customer, false)
      {:ok, %Customer{subscription_type: "pay_as_you_go", ...}}

  """
  def cancel_subscription(%Customer{stripe_subscription_id: nil}, _at_period_end) do
    {:error, :no_active_subscription}
  end

  def cancel_subscription(%Customer{} = customer, at_period_end) when is_boolean(at_period_end) do
    stripe_result =
      if at_period_end do
        StripeService.update_subscription(customer.stripe_subscription_id, %{
          cancel_at_period_end: true
        })
      else
        StripeService.cancel_subscription(customer.stripe_subscription_id)
      end

    with {:ok, _stripe_subscription} <- stripe_result do
      update_customer_after_cancellation(customer, at_period_end)
    end
  end

  # Private helper to update customer record after cancellation
  defp update_customer_after_cancellation(customer, at_period_end) do
    updates =
      if at_period_end do
        %{subscription_cancel_at_period_end: true}
      else
        %{
          subscription_type: "pay_as_you_go",
          subscription_state: nil,
          stripe_subscription_id: nil,
          subscription_cancel_at_period_end: false
        }
      end

    customer
    |> Customer.changeset(updates)
    |> Repo.update()
  end

  # INTEGRATION POINT: RFC-060 Amendment 001
  # This function is called after validation/mitigation phases complete.
  @doc """
  Track fix deployment and consume credit or charge customer.

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
  def track_fix_deployed(customer, fix) do
    # Reload for current balance
    customer = Customers.get_customer!(customer.id)

    cond do
      has_credits?(customer) ->
        consume_fix_credit(customer, fix)

      !has_billing_info?(customer) ->
        {:error, :no_billing_info}

      true ->
        charge_and_consume(customer, fix)
    end
  end

  # Pattern: Credits available
  defp consume_fix_credit(customer, fix) do
    case CreditLedger.consume(customer, 1, "fix_deployed", %{"fix_id" => fix.id}) do
      {:ok, %{customer: customer, transaction: transaction}} ->
        {:ok, %{customer: customer, transaction: transaction}}

      error ->
        error
    end
  end

  # Pattern: No credits, must charge
  defp charge_and_consume(customer, fix) do
    amount_cents = Pricing.calculate_charge_amount(customer)

    Ecto.Multi.new()
    |> Ecto.Multi.run(:charge, fn _repo, _ ->
      StripeService.create_charge(customer, amount_cents, %{
        description: "Fix deployment",
        metadata: %{fix_id: fix.id}
      })
    end)
    |> Ecto.Multi.run(:credit, fn _repo, %{charge: charge} ->
      CreditLedger.credit(customer, 1, "purchased", %{
        "stripe_charge_id" => charge.id,
        "amount_cents" => amount_cents
      })
    end)
    |> Ecto.Multi.run(:consume, fn _repo, %{credit: %{customer: customer_with_credit}} ->
      CreditLedger.consume(customer_with_credit, 1, "fix_deployed", %{
        "fix_id" => fix.id
      })
    end)
    |> Repo.transaction()
    |> case do
      {:ok, _} -> {:ok, :charged_and_consumed}
      {:error, _operation, reason, _changes} -> {:error, reason}
    end
  rescue
    e in Stripe.Error ->
      # Return Stripe error for handling by caller (e.g., Oban retry)
      {:error, {:stripe_error, e.message}}
  end

  @doc """
  Returns true if customer has available credits.

  ## Examples

      iex> has_credits?(%Customer{credit_balance: 5})
      true

      iex> has_credits?(%Customer{credit_balance: 0})
      false

  """
  def has_credits?(%{credit_balance: balance}) when balance > 0, do: true
  def has_credits?(_), do: false

  @doc """
  Returns true if customer has billing information configured.

  ## Examples

      iex> has_billing_info?(%Customer{stripe_customer_id: "cus_123"})
      true

      iex> has_billing_info?(%Customer{stripe_customer_id: nil})
      false

  """
  def has_billing_info?(%{stripe_customer_id: id}) when not is_nil(id), do: true
  def has_billing_info?(_), do: false

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
