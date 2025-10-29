defmodule Rsolv.Billing.Pricing do
  @moduledoc """
  Pricing calculation module for fix deployments.

  Implements the pricing logic from RFC-066:
  - PAYG: $29/credit
  - Pro (additional): $15/credit
  - Trial: Initial 10 credits + 5 on billing addition

  ## Examples

      iex> calculate_charge_amount(%Customer{subscription_type: "pay_as_you_go"})
      2900

      iex> calculate_charge_amount(%Customer{subscription_type: "pro"})
      1500
  """

  alias Rsolv.Customers.Customer
  alias Rsolv.Billing.Config

  @doc """
  Calculates the charge amount in cents for a single credit based on customer subscription type.

  ## Parameters
    * `customer` - The customer to calculate pricing for

  ## Returns
    * Integer - The charge amount in cents

  ## Examples

      iex> customer = %Customer{subscription_type: "pay_as_you_go"}
      iex> Pricing.calculate_charge_amount(customer)
      2900

      iex> customer = %Customer{subscription_type: "pro"}
      iex> Pricing.calculate_charge_amount(customer)
      1500
  """
  def calculate_charge_amount(%Customer{subscription_type: "pro"}), do: pro_price_cents()

  def calculate_charge_amount(%Customer{subscription_type: "pay_as_you_go"}),
    do: payg_price_cents()

  # Default to PAYG pricing for unknown subscription types
  def calculate_charge_amount(_customer), do: payg_price_cents()

  @doc """
  Returns the PAYG price per credit in cents ($29.00).
  """
  def payg_price_cents do
    Config.payg_credit_price_cents()
  end

  @doc """
  Returns the Pro overage price per credit in cents ($15.00).
  """
  def pro_price_cents do
    Config.pro_overage_price_cents()
  end

  @doc """
  Returns pricing summary for display purposes.

  ## Examples

      iex> Pricing.summary()
      %{
        payg: %{price_cents: 2900, price_display: "$29.00"},
        pro: %{overage_price_cents: 1500, overage_display: "$15.00", monthly_credits: 100}
      }
  """
  def summary do
    %{
      payg: %{
        price_cents: payg_price_cents(),
        price_display: format_money(payg_price_cents())
      },
      pro: %{
        overage_price_cents: pro_price_cents(),
        overage_display: format_money(pro_price_cents()),
        monthly_credits: Config.pro_monthly_credits()
      }
    }
  end

  # Private helper to format cents as dollar string
  defp format_money(cents) do
    dollars = cents / 100
    "$#{:erlang.float_to_binary(dollars, decimals: 2)}"
  end
end
