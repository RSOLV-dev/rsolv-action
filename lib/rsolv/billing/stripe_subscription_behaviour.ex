defmodule Rsolv.Billing.StripeSubscriptionBehaviour do
  @moduledoc """
  Behaviour for Stripe.Subscription operations.
  """

  @callback create(map()) :: {:ok, map()} | {:error, term()}
  @callback update(String.t(), map()) :: {:ok, map()} | {:error, term()}
  @callback cancel(String.t()) :: {:ok, map()} | {:error, term()}
end
