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
  2. Creates Stripe customer if needed (trial customers don't have one yet)
  3. Attaches payment method to Stripe customer
  4. Updates customer record with payment method details
  5. Credits +5 credits as billing addition bonus (trial_billing_added)

  Returns `{:ok, customer}` on success or `{:error, reason}` on failure.

  Tested via integration tests in `test/rsolv/billing/payment_methods_test.exs` and
  `test/integration/billing_onboarding_integration_test.exs`.
  """
  def add_payment_method(%Customer{stripe_customer_id: nil} = customer, payment_method_id, true) do
    # Trial customers don't have Stripe customer yet - create one first
    with {:ok, stripe_customer} <- StripeService.create_customer(customer),
         {:ok, customer} <- update_stripe_customer_id(customer, stripe_customer.id),
         {:ok, _} <- StripeService.attach_payment_method(stripe_customer.id, payment_method_id) do
      update_customer_with_payment_method_and_credit(customer, payment_method_id)
    end
  end

  def add_payment_method(%Customer{} = customer, payment_method_id, true = _billing_consent) do
    # Customer already has Stripe customer ID - just attach payment method
    with {:ok, _} <-
           StripeService.attach_payment_method(customer.stripe_customer_id, payment_method_id) do
      update_customer_with_payment_method_and_credit(customer, payment_method_id)
    end
  end

  def add_payment_method(%Customer{}, _payment_method_id, false = _billing_consent) do
    {:error, :billing_consent_required}
  end

  # Private helper to update customer's stripe_customer_id
  defp update_stripe_customer_id(customer, stripe_customer_id) do
    customer
    |> Customer.changeset(%{stripe_customer_id: stripe_customer_id})
    |> Repo.update()
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
