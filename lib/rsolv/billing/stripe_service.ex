defmodule Rsolv.Billing.StripeService do
  @moduledoc """
  Service for interacting with Stripe API.

  Handles customer creation, payment methods, subscriptions, and error handling.
  All operations emit telemetry events for observability and include automatic
  retry logic with exponential backoff for transient failures.

  ## Configuration

  Stripe API key and webhook secret are configured in runtime.exs:

      config :stripity_stripe,
        api_key: System.get_env("STRIPE_API_KEY"),
        signing_secret: System.get_env("STRIPE_WEBHOOK_SECRET")

  ## Retry Behavior

  All Stripe API operations automatically retry on transient failures:

  - **Retryable errors**: Rate limits, network timeouts, API connection errors
  - **Max attempts**: 3 (configurable via @max_attempts)
  - **Backoff strategy**: Exponential with jitter (1s, 2s, 4s)
  - **Max backoff**: 8 seconds
  - **Retry-After**: Respects Stripe's rate limit header when present

  Non-retryable errors (authentication, invalid requests) fail immediately.

  ## Telemetry

  All Stripe operations emit telemetry events:
  - `[:rsolv, :billing, :stripe, <operation>, :start]`
  - `[:rsolv, :billing, :stripe, <operation>, :retry]` - Emitted on each retry attempt
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
  @stripe_charge Application.compile_env(:rsolv, :stripe_charge, Stripe.Charge)

  # Retry configuration
  @max_attempts 3
  @base_backoff_ms 1000
  @max_backoff_ms 8000
  @retryable_stripe_errors [:rate_limit_error, :api_connection_error, :api_error]
  @retryable_network_errors [:timeout, :econnrefused, :closed]

  # Private helper for consistent error handling
  defp handle_stripe_error(error, operation, context) do
    case error do
      %{__struct__: Stripe.Error} = stripe_error ->
        Logger.error(
          "Stripe API error during #{operation}",
          Keyword.merge(context,
            error_code: stripe_error.code,
            error_message: stripe_error.message
          )
        )

        {:error, stripe_error}

      %{__struct__: HTTPoison.Error, reason: reason} ->
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

  # Determines if an error should trigger a retry
  defp should_retry?(%{__struct__: Stripe.Error, code: code}),
    do: code in @retryable_stripe_errors

  defp should_retry?(%{__struct__: HTTPoison.Error, reason: reason}),
    do: reason in @retryable_network_errors

  defp should_retry?(_), do: false

  # Calculates backoff with Retry-After header support and exponential backoff with jitter
  defp calculate_backoff(error, attempt) do
    case get_retry_after_seconds(error) do
      seconds when is_integer(seconds) ->
        min(seconds * 1000, @max_backoff_ms)

      nil ->
        backoff = min(@base_backoff_ms * :math.pow(2, attempt - 1), @max_backoff_ms)
        jitter = :rand.uniform(trunc(backoff * 0.1))
        trunc(backoff + jitter)
    end
  end

  # Extracts Retry-After header value from Stripe rate limit errors
  defp get_retry_after_seconds(%{__struct__: Stripe.Error, code: :rate_limit_error, extra: extra})
       when is_map(extra) do
    extra
    |> Map.get(:http_headers, [])
    |> Enum.find_value(fn
      {"retry-after", value} ->
        case Integer.parse(value) do
          {seconds, _} -> seconds
          :error -> nil
        end

      _ ->
        nil
    end)
  end

  defp get_retry_after_seconds(_), do: nil

  # Retries an operation with exponential backoff
  defp with_retry(operation, metadata, fun, attempt \\ 1) do
    case fun.() do
      {:ok, result} ->
        {:ok, result}

      {:error, error} when attempt < @max_attempts ->
        if should_retry?(error) do
          backoff = calculate_backoff(error, attempt)

          Logger.warning("Stripe API error, retrying in #{backoff}ms",
            operation: operation,
            attempt: attempt,
            max_attempts: @max_attempts,
            error_code: extract_error_code(error)
          )

          :telemetry.execute(
            [:rsolv, :billing, :stripe, operation, :retry],
            %{attempt: attempt, backoff_ms: backoff},
            metadata
          )

          Process.sleep(backoff)
          with_retry(operation, metadata, fun, attempt + 1)
        else
          {:error, error}
        end

      {:error, error} ->
        {:error, error}
    end
  end

  # Extracts error code for logging
  defp extract_error_code(%{__struct__: Stripe.Error, code: code}), do: code
  defp extract_error_code(%{__struct__: HTTPoison.Error, reason: reason}), do: reason
  defp extract_error_code(_), do: :unknown

  # Private helper for telemetry-wrapped Stripe operations
  defp with_telemetry(operation, metadata, fun) do
    start_time = System.monotonic_time()

    :telemetry.execute(
      [:rsolv, :billing, :stripe, operation, :start],
      %{system_time: System.system_time()},
      metadata
    )

    result = with_retry(operation, metadata, fun)
    duration = System.monotonic_time() - start_time

    # Normalize error after all retries exhausted
    normalized_result =
      case result do
        {:error, error} -> handle_stripe_error(error, operation, Map.to_list(metadata))
        other -> other
      end

    event_type = if match?({:ok, _}, normalized_result), do: :stop, else: :exception

    :telemetry.execute(
      [:rsolv, :billing, :stripe, operation, event_type],
      %{duration: duration},
      metadata
    )

    normalized_result
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
          {:error, error}
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

        {:error, %{__struct__: Stripe.Error, code: :invalid_request_error}} ->
          {:error, :not_found}

        {:error, error} ->
          {:error, error}
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
          {:error, error}
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
          {:error, error}
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
          {:error, error}
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
      case @stripe_subscription.cancel(subscription_id) do
        {:ok, subscription} ->
          Logger.info("Canceled Stripe subscription", subscription_id: subscription_id)
          {:ok, subscription}

        {:error, error} ->
          {:error, error}
      end
    end)
  end

  @doc """
  Creates a one-time charge for a customer.

  ## Parameters
    * `customer` - The RSOLV customer struct (must have stripe_customer_id)
    * `amount_cents` - The charge amount in cents
    * `opts` - Optional parameters (description, metadata, etc.)

  ## Examples

      iex> create_charge(customer, 2900, %{description: "Fix deployment"})
      {:ok, %Stripe.Charge{id: "ch_123", amount: 2900, ...}}

      iex> create_charge(customer_without_payment, 2900, %{})
      {:error, %Stripe.Error{message: "No payment method attached"}}

  """
  def create_charge(customer, amount_cents, opts \\ %{}) do
    params = %{
      customer: customer.stripe_customer_id,
      amount: amount_cents,
      currency: "usd",
      description: Map.get(opts, :description, "RSOLV charge"),
      metadata: Map.get(opts, :metadata, %{})
    }

    context = [customer_id: customer.id, amount_cents: amount_cents]

    with_telemetry(:create_charge, Map.new(context), fn ->
      case @stripe_charge.create(params) do
        {:ok, charge} ->
          Logger.info("Created Stripe charge", context ++ [charge_id: charge.id])
          {:ok, charge}

        {:error, error} ->
          {:error, error}
      end
    end)
  end
end
