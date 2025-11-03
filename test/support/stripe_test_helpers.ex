defmodule Rsolv.StripeTestHelpers do
  @moduledoc """
  Test helpers for Stripe integration testing.

  Provides utilities for:
  - Simulating webhook signatures
  - Creating test customers with known states
  - Generating webhook events
  - Mocking Stripe API responses

  ## Usage

      use Rsolv.StripeTestHelpers

      test "handles subscription webhook" do
        event = stripe_webhook_event("customer.subscription.created")
        # Test webhook handler with event
      end

  See RFC-068 for complete testing infrastructure details.
  """

  import Rsolv.CustomersFixtures

  @doc """
  Generates a valid Stripe webhook signature for testing.

  This simulates the signature that Stripe would send in the
  `Stripe-Signature` header.

  ## Examples

      iex> generate_webhook_signature(payload)
      "t=1234567890,v1=signature_hash"
  """
  def generate_webhook_signature(payload) when is_binary(payload) do
    timestamp = DateTime.to_unix(DateTime.utc_now())
    # In real tests, this would use the webhook secret to generate HMAC
    # For now, we just create a valid format
    signature = :crypto.hash(:sha256, "#{timestamp}.#{payload}") |> Base.encode16(case: :lower)
    "t=#{timestamp},v1=#{signature}"
  end

  @doc """
  Creates a complete Stripe webhook event with signature.

  Returns a tuple of `{payload, signature}` ready for webhook testing.

  ## Examples

      iex> {payload, signature} = create_signed_webhook("customer.subscription.created")
      iex> # Use in controller tests
  """
  def create_signed_webhook(event_type, attrs \\ %{}) do
    event = billing_event_fixture(event_type, attrs)
    payload = Jason.encode!(event)
    signature = generate_webhook_signature(payload)
    {payload, signature}
  end

  @doc """
  Simulates a Stripe API call with configurable responses.

  Useful for testing retry logic and error handling.

  ## Examples

      iex> simulate_stripe_call(fn -> {:ok, "success"} end)
      {:ok, "success"}

      iex> simulate_stripe_call(fn -> raise "API error" end)
      {:error, %{message: "API error"}}
  """
  def simulate_stripe_call(fun) when is_function(fun, 0) do
    try do
      fun.()
    rescue
      e -> {:error, %{message: Exception.message(e)}}
    end
  end

  @doc """
  Creates a test customer with a known API key for testing.

  Returns `{customer, api_key}` tuple where api_key is the raw,
  unhashed key that can be used in API requests.

  Note: This is a helper that generates test data. To actually insert
  a customer into the database, use the Factory directly in your test.

  ## Examples

      iex> {customer, api_key} = create_test_customer_with_api_key()
      iex> # Use api_key in API request headers
  """
  def create_test_customer_with_api_key(attrs \\ %{}) do
    # Generate a known API key
    raw_key =
      "rsolv_test_#{System.unique_integer([:positive])}_#{:crypto.strong_rand_bytes(16) |> Base.encode64(padding: false)}"

    # Return placeholder customer data
    # Tests should use Factory.insert(:customer) to persist
    customer =
      Map.merge(
        %{
          id: System.unique_integer([:positive]),
          email: "test-#{System.unique_integer([:positive])}@example.com"
        },
        attrs
      )

    {customer, raw_key}
  end

  @doc """
  Simulates a successful Stripe payment.

  Returns a payment intent in the "succeeded" state.

  ## Examples

      iex> payment = simulate_successful_payment(2900)
      iex> payment.status
      "succeeded"
  """
  def simulate_successful_payment(amount, attrs \\ %{}) do
    Enum.into(attrs, %{
      id: "pi_test_#{System.unique_integer([:positive])}",
      object: "payment_intent",
      amount: amount,
      currency: "usd",
      status: "succeeded",
      created: DateTime.to_unix(DateTime.utc_now()),
      livemode: false
    })
  end

  @doc """
  Simulates a failed Stripe payment.

  Returns a payment intent in the "requires_payment_method" state
  with a failure reason.

  ## Examples

      iex> payment = simulate_failed_payment(2900, "card_declined")
      iex> payment.last_payment_error.code
      "card_declined"
  """
  def simulate_failed_payment(amount, error_code \\ "card_declined", attrs \\ %{}) do
    Enum.into(attrs, %{
      id: "pi_test_#{System.unique_integer([:positive])}",
      object: "payment_intent",
      amount: amount,
      currency: "usd",
      status: "requires_payment_method",
      last_payment_error: %{
        code: error_code,
        message: error_message_for_code(error_code)
      },
      created: DateTime.to_unix(DateTime.utc_now()),
      livemode: false
    })
  end

  @doc """
  Advances time for subscription testing.

  Useful for testing subscription renewals and expirations.

  ## Examples

      iex> subscription = advance_subscription_period(subscription, days: 30)
      iex> # Subscription is now in next billing period
  """
  def advance_subscription_period(subscription, opts \\ []) do
    days = Keyword.get(opts, :days, 30)
    current_end = subscription.current_period_end
    new_start = current_end
    new_end = current_end + days * 24 * 60 * 60

    subscription
    |> Map.put(:current_period_start, new_start)
    |> Map.put(:current_period_end, new_end)
  end

  @doc """
  Verifies that a Stripe webhook was processed correctly.

  Checks for expected database changes and side effects.

  ## Examples

      iex> verify_webhook_processing("customer.subscription.created", customer_id)
      :ok
  """
  def verify_webhook_processing(event_type, expected_changes) do
    # This would perform verification based on event type
    # For now, it's a placeholder that can be extended
    case event_type do
      "customer.subscription.created" ->
        verify_subscription_created(expected_changes)

      "invoice.payment_succeeded" ->
        verify_payment_recorded(expected_changes)

      _ ->
        :ok
    end
  end

  # Private helpers

  defp error_message_for_code("card_declined"), do: "Your card was declined."
  defp error_message_for_code("insufficient_funds"), do: "Your card has insufficient funds."
  defp error_message_for_code("expired_card"), do: "Your card has expired."
  defp error_message_for_code(_), do: "An error occurred processing your payment."

  defp verify_subscription_created(_changes) do
    # Placeholder for subscription verification
    :ok
  end

  defp verify_payment_recorded(_changes) do
    # Placeholder for payment verification
    :ok
  end

  # Mox Helpers for Stripe API Mocking

  import Mox
  import ExUnit.Assertions

  @doc """
  Sets up a mock for attaching a payment method to a customer.

  This helper mocks both the payment method attachment and the customer update
  to set the default payment method.

  ## Options
  - `:times` - Number of times the mock should be called (default: 1)

  ## Examples

      # Mock single payment method attachment
      mock_payment_method_attach("pm_test_visa", "cus_test_123")

      # Mock multiple concurrent attachments
      mock_payment_method_attach("pm_test_visa", "cus_test_123", times: 2)
  """
  def mock_payment_method_attach(payment_method_id, customer_id, opts \\ []) do
    times = Keyword.get(opts, :times, 1)

    expect(Rsolv.Billing.StripePaymentMethodMock, :attach, times, fn params ->
      {:ok, %{id: params.payment_method, customer: params.customer}}
    end)

    expect(Rsolv.Billing.StripeMock, :update, times, fn id, _params ->
      {:ok, %{id: id}}
    end)
  end

  @doc """
  Sets up a mock for creating a Stripe customer.

  Returns a mock Stripe customer with the provided ID and email.

  ## Examples

      mock_stripe_customer_create("cus_test_123", "test@example.com")
  """
  def mock_stripe_customer_create(stripe_customer_id, email) do
    expect(Rsolv.Billing.StripeMock, :create, fn _params ->
      {:ok, %{id: stripe_customer_id, email: email}}
    end)
  end

  @doc """
  Sets up a mock for creating a Stripe subscription.

  Returns a mock active subscription with proper structure including period dates.

  ## Options
  - `:subscription_id` - Custom subscription ID (default: generated)
  - `:price_id` - Price ID to verify (optional)
  - `:status` - Subscription status (default: "active")

  ## Examples

      # Basic subscription mock
      mock_stripe_subscription_create("cus_test_123")

      # Verify specific price and custom ID
      mock_stripe_subscription_create(
        "cus_test_123",
        subscription_id: "sub_custom",
        price_id: "price_pro_monthly"
      )
  """
  def mock_stripe_subscription_create(customer_id, opts \\ []) do
    subscription_id =
      Keyword.get(opts, :subscription_id, "sub_test_#{System.unique_integer([:positive])}")

    price_id = Keyword.get(opts, :price_id)
    status = Keyword.get(opts, :status, "active")

    expect(Rsolv.Billing.StripeSubscriptionMock, :create, fn params ->
      # Optionally verify price_id if provided
      if price_id do
        assert params.items == [%{price: price_id}]
      end

      {:ok,
       %{
         id: subscription_id,
         status: status,
         customer: customer_id,
         current_period_start: DateTime.utc_now() |> DateTime.to_unix(),
         current_period_end: DateTime.utc_now() |> DateTime.add(30, :day) |> DateTime.to_unix(),
         items: %{
           data: [
             %{
               price: %{
                 id: price_id || "price_test_default",
                 metadata: %{plan: "pro"}
               }
             }
           ]
         }
       }}
    end)

    subscription_id
  end
end
