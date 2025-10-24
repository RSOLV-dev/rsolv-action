defmodule Rsolv.Billing.StripeService do
  @moduledoc """
  Service for interacting with Stripe API.

  Handles customer creation, payment methods, subscriptions, and error handling.
  All operations emit telemetry events for observability.

  ## Configuration

  Stripe API key and webhook secret are configured in runtime.exs:

      config :stripity_stripe,
        api_key: System.get_env("STRIPE_API_KEY"),
        signing_secret: System.get_env("STRIPE_WEBHOOK_SECRET")

  ## Telemetry

  Emits the following events:
  - `[:rsolv, :billing, :stripe, :create_customer, :start]`
  - `[:rsolv, :billing, :stripe, :create_customer, :stop]`
  - `[:rsolv, :billing, :stripe, :create_customer, :exception]`

  """

  require Logger

  @stripe_client Application.compile_env(:rsolv, :stripe_client, Stripe.Customer)

  @doc """
  Creates a Stripe customer from an RSOLV customer.

  ## Examples

      iex> create_customer(customer)
      {:ok, %Stripe.Customer{id: "cus_123", ...}}

      iex> create_customer(customer)
      {:error, %Stripe.Error{message: "..."}}

  """
  def create_customer(customer) do
    metadata =
      customer.metadata
      |> Map.put("rsolv_customer_id", customer.id)

    params = %{
      email: customer.email,
      name: customer.name,
      metadata: metadata
    }

    start_time = System.monotonic_time()

    :telemetry.execute(
      [:rsolv, :billing, :stripe, :create_customer, :start],
      %{system_time: System.system_time()},
      %{customer_id: customer.id}
    )

    result =
      case @stripe_client.create(params) do
        {:ok, stripe_customer} ->
          Logger.info("Created Stripe customer",
            customer_id: customer.id,
            stripe_customer_id: stripe_customer.id
          )

          {:ok, stripe_customer}

        {:error, %Stripe.Error{} = error} ->
          Logger.error("Stripe API error creating customer",
            customer_id: customer.id,
            error_type: error.type,
            error_message: error.message
          )

          {:error, error}

        {:error, %HTTPoison.Error{reason: reason}} ->
          Logger.error("Network error creating Stripe customer",
            customer_id: customer.id,
            reason: reason
          )

          {:error, :network_error}

        {:error, other} ->
          Logger.error("Unknown error creating Stripe customer",
            customer_id: customer.id,
            error: inspect(other)
          )

          {:error, :unknown_error}
      end

    duration = System.monotonic_time() - start_time

    case result do
      {:ok, _} ->
        :telemetry.execute(
          [:rsolv, :billing, :stripe, :create_customer, :stop],
          %{duration: duration},
          %{customer_id: customer.id}
        )

      {:error, _} ->
        :telemetry.execute(
          [:rsolv, :billing, :stripe, :create_customer, :exception],
          %{duration: duration},
          %{customer_id: customer.id}
        )
    end

    result
  end

  @doc """
  Retrieves a Stripe customer by ID.

  ## Examples

      iex> get_customer("cus_123")
      {:ok, %Stripe.Customer{...}}

      iex> get_customer("cus_invalid")
      {:error, :not_found}

  """
  def get_customer(stripe_customer_id) do
    case @stripe_client.retrieve(stripe_customer_id) do
      {:ok, customer} ->
        {:ok, customer}

      {:error, %Stripe.Error{type: "invalid_request_error"}} ->
        {:error, :not_found}

      {:error, error} ->
        Logger.error("Error retrieving Stripe customer",
          stripe_customer_id: stripe_customer_id,
          error: inspect(error)
        )

        {:error, error}
    end
  end
end
