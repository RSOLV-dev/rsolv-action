defmodule Rsolv.Billing.StripeClientBehaviour do
  @moduledoc """
  Behaviour defining the Stripe client interface for mocking in tests.
  """

  @callback create_customer(map()) :: {:ok, map()} | {:error, term()}
  @callback get_customer(String.t()) :: {:ok, map()} | {:error, term()}
  @callback attach_payment_method(String.t(), map()) :: {:ok, map()} | {:error, term()}
  @callback update_customer(String.t(), map()) :: {:ok, map()} | {:error, term()}
  @callback create_subscription(map()) :: {:ok, map()} | {:error, term()}
  @callback update_subscription(String.t(), map()) :: {:ok, map()} | {:error, term()}
  @callback cancel_subscription(String.t()) :: {:ok, map()} | {:error, term()}
  @callback retrieve_subscription(String.t()) :: {:ok, map()} | {:error, term()}
end
