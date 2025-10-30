defmodule Rsolv.Billing.StripeClientBehaviour do
  @moduledoc """
  Behaviour defining the Stripe client interface for mocking in tests.
  Matches the Stripe library's API method names across Customer, PaymentMethod, Subscription, and Charge.
  """

  # Stripe.Customer methods
  @callback create(map()) :: {:ok, map()} | {:error, term()}
  @callback retrieve(String.t()) :: {:ok, map()} | {:error, term()}
  @callback update(String.t(), map()) :: {:ok, map()} | {:error, term()}

  # Stripe.PaymentMethod methods
  @callback attach(map()) :: {:ok, map()} | {:error, term()}

  # Stripe.Subscription methods
  @callback cancel(String.t()) :: {:ok, map()} | {:error, term()}
end

defmodule Rsolv.Billing.StripeChargeBehaviour do
  @moduledoc """
  Behaviour for Stripe.Charge operations.
  Separate from StripeClientBehaviour to match Stripe module structure.
  """

  # Stripe.Charge methods
  @callback create(map()) :: {:ok, map()} | {:error, Stripe.Error.t()}
end
