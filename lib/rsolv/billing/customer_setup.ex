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

  ## Examples

      iex> alias Rsolv.Customers.Customer
      iex> customer = %Customer{id: 1, email: "test@example.com", name: "Test Customer"}
      iex> # Mock successful Stripe customer creation
      iex> expect(Rsolv.Billing.StripeMock, :create, fn _params ->
      ...>   {:ok, %{id: "cus_test123", email: "test@example.com", name: "Test Customer"}}
      ...> end)
      iex> {:ok, customer_id} = Rsolv.Billing.CustomerSetup.create_stripe_customer(customer)
      iex> customer_id
      "cus_test123"

  ## Error handling

      iex> alias Rsolv.Customers.Customer
      iex> customer = %Customer{id: 2, email: "error@example.com", name: "Error Customer"}
      iex> # Mock Stripe API error
      iex> expect(Rsolv.Billing.StripeMock, :create, fn _params ->
      ...>   {:error, %Stripe.Error{message: "Invalid email", source: :stripe, code: :invalid_request_error}}
      ...> end)
      iex> {:error, %Stripe.Error{message: msg}} = Rsolv.Billing.CustomerSetup.create_stripe_customer(customer)
      iex> msg
      "Invalid email"

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
end
