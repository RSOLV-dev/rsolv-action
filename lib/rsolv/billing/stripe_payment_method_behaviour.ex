defmodule Rsolv.Billing.StripePaymentMethodBehaviour do
  @moduledoc """
  Behaviour for Stripe.PaymentMethod operations.
  """

  @callback attach(map()) :: {:ok, map()} | {:error, term()}
end
