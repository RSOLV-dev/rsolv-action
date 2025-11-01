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

  Uses SELECT FOR UPDATE to prevent race conditions where concurrent requests
  could double-credit the billing bonus. The lock ensures only the first payment
  method addition receives the bonus.

  Returns `{:ok, customer}` on success or `{:error, reason}` on failure.
  """
  def add_payment_method(%Customer{}, _payment_method_id, false = _billing_consent) do
    {:error, :billing_consent_required}
  end

  def add_payment_method(%Customer{id: customer_id}, payment_method_id, true) do
    Repo.transaction(fn ->
      # Lock row to prevent concurrent bonus credits
      locked_customer = Repo.one!(from c in Customer, where: c.id == ^customer_id, lock: "FOR UPDATE")

      # Credit bonus only if this is the first payment method
      should_credit_bonus = not locked_customer.has_payment_method

      with {:ok, stripe_customer_id} <- ensure_stripe_customer(locked_customer),
           {:ok, _} <- StripeService.attach_payment_method(stripe_customer_id, payment_method_id),
           {:ok, customer} <- update_customer_with_payment_method(locked_customer, stripe_customer_id, payment_method_id, should_credit_bonus) do
        customer
      else
        {:error, reason} -> Repo.rollback(reason)
      end
    end)
  end

  # Update customer and optionally credit bonus in a single Multi transaction
  defp update_customer_with_payment_method(customer, stripe_customer_id, payment_method_id, credit_bonus?) do
    now = DateTime.utc_now()

    multi =
      Ecto.Multi.new()
      |> Ecto.Multi.update(:customer, Customer.changeset(customer, %{
        stripe_customer_id: stripe_customer_id,
        stripe_payment_method_id: payment_method_id,
        has_payment_method: true,
        billing_consent_given: true,
        billing_consent_at: now,
        payment_method_added_at: now,
        subscription_type: "pay_as_you_go"
      }))

    multi = if credit_bonus? do
      Ecto.Multi.run(multi, :credit, fn _repo, %{customer: updated_customer} ->
        CreditLedger.credit(
          updated_customer,
          Config.trial_billing_addition_bonus(),
          "trial_billing_added",
          %{payment_method_id: payment_method_id}
        )
      end)
    else
      multi
    end

    case Repo.transaction(multi) do
      {:ok, %{customer: customer}} -> {:ok, customer}
      {:ok, %{credit: %{customer: customer}}} -> {:ok, customer}
      {:error, _op, changeset, _changes} -> {:error, changeset}
    end
  end

  # Ensure customer has Stripe customer ID, creating if needed
  defp ensure_stripe_customer(%Customer{stripe_customer_id: nil} = customer) do
    with {:ok, stripe_customer} <- StripeService.create_customer(customer) do
      {:ok, stripe_customer.id}
    end
  end

  defp ensure_stripe_customer(%Customer{stripe_customer_id: id}), do: {:ok, id}
end
