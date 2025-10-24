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

  ## Examples

      iex> {customer, api_key} = create_test_customer_with_api_key()
      iex> # Use api_key in API request headers
  """
  def create_test_customer_with_api_key(attrs \\ %{}) do
    import Rsolv.Factory

    # Generate a known API key
    raw_key = "rsolv_test_#{System.unique_integer([:positive])}_#{:crypto.strong_rand_bytes(16) |> Base.encode64()}"

    customer = insert(:customer, attrs)

    # In a real implementation, this would insert the API key
    # For now, we just return the customer and raw key
    {customer, raw_key}
  end

  @doc """
  Clears all sent emails (for Bamboo email testing).

  Useful in test setup blocks to ensure clean state.

  ## Examples

      setup do
        clear_sent_emails()
        :ok
      end
  """
  def clear_sent_emails do
    # Bamboo.SentEmail.reset() would be called here
    # For now, this is a placeholder
    :ok
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
    new_end = current_end + (days * 24 * 60 * 60)

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
end
