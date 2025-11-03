defmodule Rsolv.Billing.CustomerSetup do
  @moduledoc """
  Handles customer onboarding and initial billing setup.

  This module manages:
  - Creating Stripe customers during signup
  - Adding payment methods with billing consent
  - Granting initial signup and billing bonuses
  """

  alias Rsolv.Repo
  alias Rsolv.Billing.{StripeService, CreditTransaction, Config}
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
    with {:ok, stripe_customer} <- StripeService.create_customer(customer) do
      {:ok, stripe_customer.id}
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
      locked_customer =
        Repo.one!(from c in Customer, where: c.id == ^customer_id, lock: "FOR UPDATE")

      # Credit bonus only if this is the first payment method
      should_credit_bonus = not locked_customer.has_payment_method
      bonus_amount = Config.trial_billing_addition_bonus()

      with {:ok, stripe_customer_id} <- ensure_stripe_customer(locked_customer),
           {:ok, _} <- StripeService.attach_payment_method(stripe_customer_id, payment_method_id) do
        # Build and execute Multi for all database updates
        multi =
          build_payment_method_multi(
            locked_customer,
            stripe_customer_id,
            payment_method_id,
            should_credit_bonus,
            bonus_amount
          )

        case Repo.transaction(multi) do
          {:ok, result} ->
            # Extract customer from whichever operation set it
            result[:credit_update] || result[:customer_update]

          {:error, _operation, reason, _changes} ->
            Repo.rollback(reason)
        end
      else
        {:error, reason} -> Repo.rollback(reason)
      end
    end)
  end

  # Builds a Multi for payment method addition with optional credit bonus
  # Note: This runs INSIDE the outer transaction started in add_payment_method/3
  defp build_payment_method_multi(
         customer,
         stripe_customer_id,
         payment_method_id,
         credit_bonus?,
         bonus_amount
       ) do
    now = DateTime.utc_now()

    Ecto.Multi.new()
    |> Ecto.Multi.update(
      :customer_update,
      Customer.changeset(customer, %{
        stripe_customer_id: stripe_customer_id,
        stripe_payment_method_id: payment_method_id,
        has_payment_method: true,
        billing_consent_given: true,
        billing_consent_at: now,
        payment_method_added_at: now,
        subscription_type: "pay_as_you_go"
      })
    )
    |> maybe_add_credit_bonus(credit_bonus?, bonus_amount, payment_method_id)
  end

  # Pattern match on false: no credit bonus, return multi unchanged
  defp maybe_add_credit_bonus(multi, false, _bonus_amount, _payment_method_id), do: multi

  # Pattern match on true: add credit bonus operations to multi
  defp maybe_add_credit_bonus(multi, true, bonus_amount, payment_method_id) do
    multi
    |> Ecto.Multi.run(:credit_update, fn _repo, %{customer_update: updated_customer} ->
      new_balance = updated_customer.credit_balance + bonus_amount

      Customer.changeset(updated_customer, %{credit_balance: new_balance})
      |> Repo.update()
    end)
    |> Ecto.Multi.insert(:credit_transaction, fn %{credit_update: credited_customer} ->
      CreditTransaction.changeset(%CreditTransaction{}, %{
        customer_id: credited_customer.id,
        amount: bonus_amount,
        balance_after: credited_customer.credit_balance,
        source: "trial_billing_added",
        metadata: %{payment_method_id: payment_method_id}
      })
    end)
  end

  # Ensure customer has Stripe customer ID, creating if needed
  defp ensure_stripe_customer(%Customer{stripe_customer_id: nil} = customer) do
    with {:ok, stripe_customer} <- StripeService.create_customer(customer) do
      {:ok, stripe_customer.id}
    end
  end

  defp ensure_stripe_customer(%Customer{stripe_customer_id: id}), do: {:ok, id}
end
