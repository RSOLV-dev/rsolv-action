defmodule Rsolv.Billing.CustomerSetup do
  @moduledoc """
  Handles customer onboarding and initial billing setup.

  This module manages:
  - Creating Stripe customers during signup
  - Adding payment methods with billing consent
  - Granting initial signup and billing bonuses
  """

  alias Rsolv.Repo
  alias Rsolv.Billing.{StripeService, CreditLedger, Config}
  alias Rsolv.Customers.Customer

  import Ecto.Query, warn: false

  @doc """
  Creates a Stripe customer for a newly provisioned customer.

  This function:
  1. Creates a Stripe customer via StripeService
  2. Returns the stripe_customer_id for storage

  Returns `{:ok, stripe_customer_id}` on success or `{:error, reason}` on failure.

  Tested via integration tests in `test/rsolv/billing/` and
  `test/integration/billing_onboarding_integration_test.exs`.
  """
  def create_stripe_customer(%Customer{} = customer) do
    case StripeService.create_customer(customer) do
      {:ok, stripe_customer} ->
        {:ok, stripe_customer.id}

      {:error, reason} ->
        {:error, reason}
    end
  end

  @doc """
  Adds a payment method to a customer and grants billing addition bonus.

  This function:
  1. Validates billing consent was given (returns `{:error, :billing_consent_required}` if false)
  2. Locks the customer row with SELECT FOR UPDATE to prevent race conditions
  3. Checks if customer already has payment method (prevents double bonus)
  4. Creates Stripe customer if needed (trial customers don't have one yet)
  5. Attaches payment method to Stripe customer
  6. Updates customer record with payment method details
  7. Credits +5 credits as billing addition bonus (trial_billing_added) ONLY for first payment method

  **Race Condition Prevention:**
  Uses PostgreSQL row-level locking (SELECT FOR UPDATE) to prevent concurrent requests
  from double-crediting the billing addition bonus. The lock is acquired at the start
  of the transaction and held until commit, ensuring only one request can proceed with
  the bonus credit.

  Returns `{:ok, customer}` on success or `{:error, reason}` on failure.

  Tested via integration tests in `test/rsolv/billing/payment_methods_test.exs` and
  `test/integration/billing_onboarding_integration_test.exs`.
  """
  def add_payment_method(%Customer{}, _payment_method_id, false = _billing_consent) do
    {:error, :billing_consent_required}
  end

  def add_payment_method(%Customer{id: customer_id}, payment_method_id, true = _billing_consent) do
    # Wrap entire operation in transaction with row lock to prevent race conditions
    Repo.transaction(fn ->
      # Lock the customer row for this transaction (SELECT FOR UPDATE)
      # This prevents concurrent payment method additions from racing
      locked_customer =
        from(c in Customer,
          where: c.id == ^customer_id,
          lock: "FOR UPDATE"
        )
        |> Repo.one!()

      # Check if customer already has payment method
      # If yes, attach the new payment method but don't credit bonus
      if locked_customer.has_payment_method do
        # Already has payment method - attach new one without bonus
        case attach_payment_method_only(locked_customer, payment_method_id) do
          {:ok, customer} -> customer
          {:error, reason} -> Repo.rollback(reason)
        end
      else
        # First payment method - attach and credit bonus
        case add_first_payment_method(locked_customer, payment_method_id) do
          {:ok, customer} -> customer
          {:error, reason} -> Repo.rollback(reason)
        end
      end
    end)
  end

  # Private helper to add first payment method with bonus credit
  # This is called within a transaction with the customer row already locked
  defp add_first_payment_method(locked_customer, payment_method_id) do
    now = DateTime.utc_now()
    bonus_credits = Config.trial_billing_addition_bonus()

    # Create Stripe customer if needed (trial customers don't have one yet)
    with {:ok, stripe_customer_id} <-
           ensure_stripe_customer(locked_customer),
         {:ok, _} <- StripeService.attach_payment_method(stripe_customer_id, payment_method_id) do
      # Update customer and credit bonus atomically
      Ecto.Multi.new()
      |> Ecto.Multi.update(
        :customer,
        Customer.changeset(locked_customer, %{
          stripe_customer_id: stripe_customer_id,
          stripe_payment_method_id: payment_method_id,
          has_payment_method: true,
          billing_consent_given: true,
          billing_consent_at: now,
          payment_method_added_at: now,
          # Upgrade to PAYG when payment method added
          subscription_type: "pay_as_you_go"
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
  end

  # Private helper to attach payment method without bonus (subsequent payment methods)
  # This is called within a transaction with the customer row already locked
  defp attach_payment_method_only(locked_customer, payment_method_id) do
    now = DateTime.utc_now()

    # Attach payment method to existing Stripe customer
    with {:ok, _} <-
           StripeService.attach_payment_method(
             locked_customer.stripe_customer_id,
             payment_method_id
           ) do
      # Update customer record with new payment method (no bonus credit)
      locked_customer
      |> Customer.changeset(%{
        stripe_payment_method_id: payment_method_id,
        payment_method_added_at: now
      })
      |> Repo.update()
    end
  end

  # Private helper to ensure customer has a Stripe customer ID
  # Creates one if missing, returns existing ID if present
  defp ensure_stripe_customer(%Customer{stripe_customer_id: nil} = customer) do
    case StripeService.create_customer(customer) do
      {:ok, stripe_customer} -> {:ok, stripe_customer.id}
      {:error, reason} -> {:error, reason}
    end
  end

  defp ensure_stripe_customer(%Customer{stripe_customer_id: stripe_customer_id}) do
    {:ok, stripe_customer_id}
  end
end
