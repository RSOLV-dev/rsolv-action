defmodule Rsolv.StripeMock do
  @moduledoc """
  Mock Stripe API for unit testing billing features.

  This module provides simulated Stripe responses for testing without
  making actual API calls. It supports both success and failure scenarios.

  ## Usage

      # Mock successful customer creation
      {:ok, customer} = StripeMock.create_customer(%{email: "test@example.com"})

      # Mock failure scenarios
      {:error, reason} = StripeMock.create_customer(%{email: "fail@test.example.com"})

  ## Failure Triggers

  Certain email addresses or customer IDs trigger specific failure scenarios:
  - `fail@test.example.com` - Card declined
  - `cus_no_payment` - No payment method attached
  - `invalid@test.example.com` - Invalid customer error

  See RFC-068 for complete testing infrastructure details.
  """

  @doc """
  Mock Stripe customer creation.

  ## Examples

      iex> create_customer(%{email: "test@example.com"})
      {:ok, %{id: "cus_test_...", email: "test@example.com", ...}}

      iex> create_customer(%{email: "fail@test.example.com"})
      {:error, "Card declined"}
  """
  def create_customer(%{email: "fail@test.example.com"}) do
    {:error, stripe_error("card_declined", "Your card was declined.")}
  end

  def create_customer(%{email: "invalid@test.example.com"}) do
    {:error, stripe_error("invalid_request_error", "Invalid email address.")}
  end

  def create_customer(params) do
    customer = %{
      id: "cus_test_#{System.unique_integer([:positive])}",
      object: "customer",
      email: params[:email] || params["email"],
      name: params[:name] || params["name"],
      created: DateTime.to_unix(DateTime.utc_now()),
      livemode: false,
      metadata: params[:metadata] || params["metadata"] || %{}
    }

    {:ok, customer}
  end

  @doc """
  Mock Stripe subscription creation.

  ## Examples

      iex> create_subscription(%{customer: "cus_test_123"})
      {:ok, %{id: "sub_test_...", status: "active", ...}}

      iex> create_subscription(%{customer: "cus_no_payment"})
      {:error, "No payment method attached"}
  """
  def create_subscription(%{customer: "cus_no_payment"}) do
    {:error,
     stripe_error(
       "invalid_request_error",
       "This customer has no attached payment source or default payment method."
     )}
  end

  def create_subscription(%{customer: customer_id}) when is_binary(customer_id) do
    {:ok, build_subscription_fixture(%{customer: customer_id})}
  end

  def create_subscription(_params) do
    {:error, stripe_error("invalid_request_error", "Missing required param: customer.")}
  end

  @doc """
  Mock Stripe subscription update.

  ## Examples

      iex> update_subscription("sub_test_123", %{cancel_at_period_end: true})
      {:ok, %{id: "sub_test_123", cancel_at_period_end: true, ...}}
  """
  def update_subscription(subscription_id, params) when is_binary(subscription_id) do
    subscription = build_subscription_fixture(%{id: subscription_id})
    updated = Map.merge(subscription, params)
    {:ok, updated}
  end

  def update_subscription(_id, _params) do
    {:error, stripe_error("invalid_request_error", "Invalid subscription ID.")}
  end

  @doc """
  Mock Stripe subscription cancellation.

  ## Examples

      iex> cancel_subscription("sub_test_123")
      {:ok, %{id: "sub_test_123", status: "canceled", ...}}
  """
  def cancel_subscription(subscription_id) when is_binary(subscription_id) do
    {:ok, build_subscription_fixture(%{id: subscription_id, status: "canceled"})}
  end

  def cancel_subscription(_id) do
    {:error, stripe_error("invalid_request_error", "Invalid subscription ID.")}
  end

  @doc """
  Mock Stripe webhook event construction.

  Generates a properly formatted Stripe webhook event for testing.

  ## Examples

      iex> construct_event("payload", "sig_header", "webhook_secret")
      {:ok, %{type: "customer.subscription.created", data: %{...}}}
  """
  def construct_event(_payload, _signature, _secret) do
    # In real implementation, this would verify webhook signature
    # For mocking, we just return a sample event
    {:ok, build_billing_event("customer.subscription.created")}
  end

  @doc """
  Mock Stripe payment intent creation.

  ## Examples

      iex> create_payment_intent(%{amount: 500, currency: "usd"})
      {:ok, %{id: "pi_test_...", status: "requires_payment_method", ...}}
  """
  def create_payment_intent(%{amount: amount, currency: currency}) when amount > 0 do
    intent = %{
      id: "pi_test_#{System.unique_integer([:positive])}",
      object: "payment_intent",
      amount: amount,
      currency: currency,
      status: "requires_payment_method",
      created: DateTime.to_unix(DateTime.utc_now()),
      livemode: false
    }

    {:ok, intent}
  end

  def create_payment_intent(_params) do
    {:error, stripe_error("invalid_request_error", "Invalid amount or currency.")}
  end

  @doc """
  Mock retrieving a Stripe customer.

  ## Examples

      iex> retrieve_customer("cus_test_123")
      {:ok, %{id: "cus_test_123", ...}}

      iex> retrieve_customer("cus_invalid")
      {:error, "No such customer"}
  """
  def retrieve_customer("cus_invalid") do
    {:error, stripe_error("resource_missing", "No such customer: cus_invalid")}
  end

  def retrieve_customer(customer_id) when is_binary(customer_id) do
    customer = %{
      id: customer_id,
      object: "customer",
      email: "test@example.com",
      created: DateTime.to_unix(DateTime.utc_now()),
      livemode: false
    }

    {:ok, customer}
  end

  @doc """
  Mock retrieving a Stripe subscription.

  ## Examples

      iex> retrieve_subscription("sub_test_123")
      {:ok, %{id: "sub_test_123", status: "active", ...}}
  """
  def retrieve_subscription(subscription_id) when is_binary(subscription_id) do
    {:ok, build_subscription_fixture(%{id: subscription_id})}
  end

  def retrieve_subscription(_id) do
    {:error, stripe_error("resource_missing", "No such subscription")}
  end

  @doc """
  Mock attaching a payment method to a customer.

  ## Examples

      iex> attach_payment_method("pm_test_123", %{customer: "cus_test_123"})
      {:ok, %{id: "pm_test_123", customer: "cus_test_123"}}
  """
  def attach_payment_method(payment_method_id, %{customer: customer_id})
      when is_binary(payment_method_id) and is_binary(customer_id) do
    {:ok, %{id: payment_method_id, customer: customer_id, object: "payment_method"}}
  end

  def attach_payment_method(_id, _params) do
    {:error, stripe_error("invalid_request_error", "Invalid payment method or customer.")}
  end

  @doc """
  Mock updating a Stripe customer.

  ## Examples

      iex> update_customer("cus_test_123", %{invoice_settings: %{default_payment_method: "pm_123"}})
      {:ok, %{id: "cus_test_123", ...}}
  """
  def update_customer(customer_id, params) when is_binary(customer_id) do
    customer = %{
      id: customer_id,
      object: "customer",
      invoice_settings: params[:invoice_settings] || %{},
      metadata: params[:metadata] || %{}
    }

    {:ok, customer}
  end

  def update_customer(_id, _params) do
    {:error, stripe_error("invalid_request_error", "Invalid customer ID.")}
  end

  # Private helpers

  defp stripe_error(type, message) do
    %{
      error: %{
        type: type,
        message: message,
        code: type,
        param: nil
      }
    }
  end

  defp build_subscription_fixture(attrs) when is_map(attrs) do
    Enum.into(attrs, %{
      id: "sub_test_#{System.unique_integer([:positive])}",
      object: "subscription",
      customer: "cus_test_#{System.unique_integer([:positive])}",
      status: "active",
      current_period_start: DateTime.to_unix(DateTime.utc_now()),
      current_period_end: DateTime.to_unix(DateTime.add(DateTime.utc_now(), 30, :day)),
      cancel_at_period_end: false,
      items: %{
        object: "list",
        data: [
          %{
            id: "si_test_#{System.unique_integer([:positive])}",
            price: %{
              id: "price_test_pro",
              unit_amount: 2900,
              currency: "usd"
            },
            quantity: 1
          }
        ]
      }
    })
  end

  defp build_billing_event(type, attrs \\ %{}) do
    base_event = %{
      id: "evt_test_#{System.unique_integer([:positive])}",
      object: "event",
      type: type,
      created: DateTime.to_unix(DateTime.utc_now()),
      livemode: false,
      api_version: "2023-10-16"
    }

    data =
      case type do
        "customer.subscription.created" ->
          %{object: build_subscription_fixture(attrs)}

        "customer.subscription.updated" ->
          %{object: build_subscription_fixture(attrs)}

        "customer.subscription.deleted" ->
          %{object: build_subscription_fixture(Map.put(attrs, :status, "canceled"))}

        "invoice.payment_succeeded" ->
          %{object: build_invoice_fixture(attrs)}

        "invoice.payment_failed" ->
          %{object: build_invoice_fixture(Map.put(attrs, :status, "open"))}

        _ ->
          %{object: attrs}
      end

    Map.put(base_event, :data, data)
  end

  defp build_invoice_fixture(attrs) do
    Enum.into(attrs, %{
      id: "in_test_#{System.unique_integer([:positive])}",
      object: "invoice",
      customer: "cus_test_#{System.unique_integer([:positive])}",
      status: "paid",
      amount_paid: 2900,
      currency: "usd",
      created: DateTime.to_unix(DateTime.utc_now())
    })
  end
end
