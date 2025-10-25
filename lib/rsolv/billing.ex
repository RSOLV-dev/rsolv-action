defmodule Rsolv.Billing do
  @moduledoc """
  The Billing context for managing fix attempts, credits, subscriptions, and payments.
  """

  import Ecto.Query, warn: false

  alias Rsolv.Repo
  alias Rsolv.Billing.{FixAttempt, StripeService, CreditLedger, Subscription, Config}
  alias Rsolv.Customers.Customer

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
      {:ok, %{credit: {customer_with_credits, _transaction}}} ->
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
end
