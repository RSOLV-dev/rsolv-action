defmodule Rsolv.Billing.Config do
  @moduledoc """
  Centralized billing configuration.

  Provides compile-time and runtime access to billing settings.
  """

  @doc """
  Returns the Stripe Pro plan price ID.

  ## Examples

      iex> pro_price_id()
      "price_test_pro_monthly_50000"
  """
  def pro_price_id do
    get_in(billing_config(), [:stripe_pro_price_id])
  end

  @doc """
  Returns the pricing configuration.

  ## Examples

      iex> pricing()
      %{trial: %{initial_credits: 10, ...}, ...}
  """
  def pricing do
    get_in(billing_config(), [:pricing])
  end

  @doc """
  Returns trial credits configuration.
  """
  def trial_initial_credits do
    get_in(pricing(), [:trial, :initial_credits])
  end

  def trial_billing_addition_bonus do
    get_in(pricing(), [:trial, :billing_addition_bonus])
  end

  @doc """
  Returns Pro plan configuration.
  """
  def pro_monthly_credits do
    get_in(pricing(), [:pro, :included_credits])
  end

  def pro_overage_price_cents do
    get_in(pricing(), [:pro, :overage_price_cents])
  end

  @doc """
  Returns PAYG configuration.
  """
  def payg_credit_price_cents do
    get_in(pricing(), [:pay_as_you_go, :credit_price_cents])
  end

  defp billing_config do
    Application.get_env(:rsolv, :billing, %{})
  end
end
