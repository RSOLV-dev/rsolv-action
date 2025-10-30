defmodule Rsolv.Billing.UsageTracking do
  @moduledoc """
  Tracks usage and handles credit consumption or charging for fix deployments.

  This module implements the RFC-060 Amendment 001 billing flow:
  1. Has credits? → Consume 1 credit
  2. No credits, no billing → Error (block)
  3. No credits, has billing → Charge → Credit 1 → Consume 1
  """

  alias Rsolv.Repo
  alias Rsolv.Billing.{StripeService, CreditLedger, Pricing}
  alias Rsolv.Customers

  import Ecto.Query, warn: false

  @doc """
  Track fix deployment and consume credit or charge customer.

  Flow:
  1. Has credits? → Consume 1 credit
  2. No credits, no billing → Error (block)
  3. No credits, has billing → Charge → Credit 1 → Consume 1

  Returns:
  - `{:ok, %{customer: customer, transaction: transaction}}` - when consuming existing credits
  - `{:ok, :charged_and_consumed}` - when charging and consuming
  - `{:error, :no_billing_info}` - when customer has no credits and no billing setup
  - `{:error, reason}` - on other failures

  Tested via integration tests in `test/rsolv/billing/fix_deployment_test.exs`.
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

  @doc """
  Returns true if customer has available credits.

  ## Examples

      iex> Rsolv.Billing.UsageTracking.has_credits?(%{credit_balance: 5})
      true

      iex> Rsolv.Billing.UsageTracking.has_credits?(%{credit_balance: 0})
      false

  """
  def has_credits?(%{credit_balance: balance}) when balance > 0, do: true
  def has_credits?(_), do: false

  @doc """
  Returns true if customer has billing information configured.

  ## Examples

      iex> Rsolv.Billing.UsageTracking.has_billing_info?(%{stripe_customer_id: "cus_123"})
      true

      iex> Rsolv.Billing.UsageTracking.has_billing_info?(%{stripe_customer_id: nil})
      false

  """
  def has_billing_info?(%{stripe_customer_id: id}) when not is_nil(id), do: true
  def has_billing_info?(_), do: false

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
end
