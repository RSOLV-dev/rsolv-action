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

  All Stripe operations emit telemetry events:
  - `[:rsolv, :billing, :stripe, <operation>, :start]`
  - `[:rsolv, :billing, :stripe, <operation>, :stop]`
  - `[:rsolv, :billing, :stripe, <operation>, :exception]`

  """

  require Logger

  @stripe_client Application.compile_env(:rsolv, :stripe_client, Stripe.Customer)
  @stripe_payment_method Application.compile_env(
                           :rsolv,
                           :stripe_payment_method,
                           Stripe.PaymentMethod
                         )
  @stripe_subscription Application.compile_env(:rsolv, :stripe_subscription, Stripe.Subscription)

  # Private helper for consistent error handling
  defp handle_stripe_error(error, operation, context) do
    case error do
      %Stripe.Error{} = stripe_error ->
        Logger.error(
          "Stripe API error during #{operation}",
          Keyword.merge(context,
            error_code: stripe_error.code,
            error_message: stripe_error.message
          )
        )

        {:error, stripe_error}

      %HTTPoison.Error{reason: reason} ->
        Logger.error(
          "Network error during #{operation}",
          Keyword.merge(context, reason: reason)
        )

        {:error, :network_error}

      other ->
        Logger.error(
          "Unknown error during #{operation}",
          Keyword.merge(context, error: inspect(other))
        )

        {:error, :unknown_error}
    end
  end

  # Private helper for telemetry-wrapped Stripe operations
  defp with_telemetry(operation, metadata, fun) do
    start_time = System.monotonic_time()

    :telemetry.execute(
      [:rsolv, :billing, :stripe, operation, :start],
      %{system_time: System.system_time()},
      metadata
    )

    result = fun.()
    duration = System.monotonic_time() - start_time

    event_type = if match?({:ok, _}, result), do: :stop, else: :exception

    :telemetry.execute(
      [:rsolv, :billing, :stripe, operation, event_type],
      %{duration: duration},
      metadata
    )

    result
  end

  @doc """
  Creates a Stripe customer from an RSOLV customer.

  ## Examples

      iex> create_customer(customer)
      {:ok, %Stripe.Customer{id: "cus_123", ...}}

      iex> create_customer(customer)
      {:error, %Stripe.Error{message: "..."}}

  """
  def create_customer(customer) do
    params = %{
      email: customer.email,
      name: customer.name,
      metadata: Map.put(customer.metadata, "rsolv_customer_id", customer.id)
    }

    with_telemetry(:create_customer, %{customer_id: customer.id}, fn ->
      case @stripe_client.create(params) do
        {:ok, stripe_customer} ->
          Logger.info("Created Stripe customer",
            customer_id: customer.id,
            stripe_customer_id: stripe_customer.id
          )

          {:ok, stripe_customer}

        {:error, error} ->
          handle_stripe_error(error, "create_customer", customer_id: customer.id)
      end
    end)
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
    with_telemetry(:get_customer, %{stripe_customer_id: stripe_customer_id}, fn ->
      case @stripe_client.retrieve(stripe_customer_id) do
        {:ok, customer} ->
          {:ok, customer}

        {:error, %Stripe.Error{code: :invalid_request_error}} ->
          {:error, :not_found}

        {:error, error} ->
          handle_stripe_error(error, "get_customer", stripe_customer_id: stripe_customer_id)
      end
    end)
  end

  @doc """
  Attaches a payment method to a Stripe customer and sets it as default.

  ## Examples

      iex> attach_payment_method("cus_123", "pm_abc")
      {:ok, "pm_abc"}

      iex> attach_payment_method("cus_invalid", "pm_abc")
      {:error, %Stripe.Error{...}}

  """
  def attach_payment_method(stripe_customer_id, payment_method_id) do
    context = [stripe_customer_id: stripe_customer_id, payment_method_id: payment_method_id]

    with_telemetry(:attach_payment_method, Map.new(context), fn ->
      with {:ok, _pm} <-
             @stripe_payment_method.attach(%{
               payment_method: payment_method_id,
               customer: stripe_customer_id
             }),
           {:ok, _customer} <-
             @stripe_client.update(stripe_customer_id, %{
               invoice_settings: %{default_payment_method: payment_method_id}
             }) do
        Logger.info("Attached payment method", context)
        {:ok, payment_method_id}
      else
        {:error, error} ->
          handle_stripe_error(error, "attach_payment_method", context)
      end
    end)
  end

  @doc """
  Creates a Stripe subscription for a customer.

  ## Examples

      iex> create_subscription("cus_123", "price_pro")
      {:ok, %Stripe.Subscription{...}}

  """
  def create_subscription(stripe_customer_id, price_id) do
    params = %{
      customer: stripe_customer_id,
      items: [%{price: price_id}],
      # No trial - charge immediately
      trial_period_days: 0,
      expand: ["latest_invoice.payment_intent"]
    }

    with_telemetry(:create_subscription, %{stripe_customer_id: stripe_customer_id}, fn ->
      case @stripe_subscription.create(params) do
        {:ok, subscription} ->
          Logger.info("Created Stripe subscription",
            stripe_customer_id: stripe_customer_id,
            subscription_id: subscription.id
          )

          {:ok, subscription}

        {:error, error} ->
          handle_stripe_error(error, "create_subscription",
            stripe_customer_id: stripe_customer_id
          )
      end
    end)
  end

  @doc """
  Updates a Stripe subscription.

  ## Examples

      iex> update_subscription("sub_123", %{cancel_at_period_end: true})
      {:ok, %Stripe.Subscription{...}}

  """
  def update_subscription(subscription_id, params) do
    with_telemetry(:update_subscription, %{subscription_id: subscription_id}, fn ->
      case @stripe_subscription.update(subscription_id, params) do
        {:ok, subscription} ->
          Logger.info("Updated Stripe subscription",
            subscription_id: subscription_id,
            params: inspect(params)
          )

          {:ok, subscription}

        {:error, error} ->
          handle_stripe_error(error, "update_subscription", subscription_id: subscription_id)
      end
    end)
  end

  @doc """
  Cancels a Stripe subscription immediately.

  ## Examples

      iex> cancel_subscription("sub_123")
      {:ok, %Stripe.Subscription{status: "canceled"}}

  """
  def cancel_subscription(subscription_id) do
    with_telemetry(:cancel_subscription, %{subscription_id: subscription_id}, fn ->
      case @stripe_subscription.delete(subscription_id) do
        {:ok, subscription} ->
          Logger.info("Canceled Stripe subscription", subscription_id: subscription_id)
          {:ok, subscription}

        {:error, error} ->
          handle_stripe_error(error, "cancel_subscription", subscription_id: subscription_id)
      end
    end)
  end
end
