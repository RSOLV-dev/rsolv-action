defmodule Rsolv.Billing.StripeServiceRetryTest do
  use Rsolv.DataCase, async: false

  import Mox

  alias Rsolv.Billing.StripeService

  # Setup mocks - use global mode for retry tests since they cross process boundaries
  setup :verify_on_exit!
  setup :set_mox_global

  describe "retry behavior" do
    test "retries on network timeout and succeeds on second attempt" do
      customer = insert(:customer)

      # First attempt fails with timeout
      expect(Rsolv.Billing.StripeMock, :create, fn _params ->
        {:error, %HTTPoison.Error{reason: :timeout}}
      end)

      # Second attempt succeeds
      expect(Rsolv.Billing.StripeMock, :create, fn _params ->
        {:ok, %Stripe.Customer{id: "cus_retry_success"}}
      end)

      assert {:ok, stripe_customer} = StripeService.create_customer(customer)
      assert stripe_customer.id == "cus_retry_success"
    end

    test "retries on rate limit with exponential backoff" do
      customer = insert(:customer)

      # First two attempts fail with rate limit, third succeeds
      expect(Rsolv.Billing.StripeMock, :create, 2, fn _params ->
        {:error,
         %Stripe.Error{
           source: :stripe,
           code: :rate_limit_error,
           message: "Too many requests"
         }}
      end)

      expect(Rsolv.Billing.StripeMock, :create, fn _params ->
        {:ok, %Stripe.Customer{id: "cus_rate_limit_ok"}}
      end)

      start_time = System.monotonic_time(:millisecond)
      assert {:ok, stripe_customer} = StripeService.create_customer(customer)
      duration = System.monotonic_time(:millisecond) - start_time

      assert stripe_customer.id == "cus_rate_limit_ok"
      # Should have at least 1s + 2s = 3s of backoff (with some tolerance)
      assert duration >= 2500
    end

    test "respects Retry-After header for rate limits" do
      customer = insert(:customer)

      # Fail with rate limit including Retry-After header
      expect(Rsolv.Billing.StripeMock, :create, fn _params ->
        {:error,
         %Stripe.Error{
           source: :stripe,
           code: :rate_limit_error,
           message: "Too many requests",
           extra: %{
             http_headers: [
               {"content-type", "application/json"},
               {"retry-after", "2"}
             ]
           }
         }}
      end)

      expect(Rsolv.Billing.StripeMock, :create, fn _params ->
        {:ok, %Stripe.Customer{id: "cus_retry_after"}}
      end)

      start_time = System.monotonic_time(:millisecond)
      assert {:ok, stripe_customer} = StripeService.create_customer(customer)
      duration = System.monotonic_time(:millisecond) - start_time

      assert stripe_customer.id == "cus_retry_after"
      # Should respect the 2-second Retry-After header
      assert duration >= 1900
    end

    test "does not retry on authentication errors" do
      customer = insert(:customer)

      # Authentication errors should not be retried
      expect(Rsolv.Billing.StripeMock, :create, fn _params ->
        {:error,
         %Stripe.Error{
           source: :stripe,
           code: :authentication_error,
           message: "Invalid API key"
         }}
      end)

      assert {:error, %Stripe.Error{code: :authentication_error}} =
               StripeService.create_customer(customer)
    end

    test "does not retry on invalid request errors" do
      customer = insert(:customer)

      # Invalid request errors should not be retried
      expect(Rsolv.Billing.StripeMock, :create, fn _params ->
        {:error,
         %Stripe.Error{
           source: :stripe,
           code: :invalid_request_error,
           message: "Missing required parameter"
         }}
      end)

      assert {:error, %Stripe.Error{code: :invalid_request_error}} =
               StripeService.create_customer(customer)
    end

    test "fails after max attempts exhausted" do
      customer = insert(:customer)

      # All three attempts fail with network timeout
      expect(Rsolv.Billing.StripeMock, :create, 3, fn _params ->
        {:error, %HTTPoison.Error{reason: :timeout}}
      end)

      start_time = System.monotonic_time()
      assert {:error, :network_error} = StripeService.create_customer(customer)
      duration = System.convert_time_unit(System.monotonic_time() - start_time, :native, :millisecond)

      # Should have tried 3 times with backoff: 1s + 2s = 3s total
      assert duration >= 2500
    end

    test "retries on econnrefused network error" do
      customer = insert(:customer)

      # First attempt fails with econnrefused
      expect(Rsolv.Billing.StripeMock, :create, fn _params ->
        {:error, %HTTPoison.Error{reason: :econnrefused}}
      end)

      # Second attempt succeeds
      expect(Rsolv.Billing.StripeMock, :create, fn _params ->
        {:ok, %Stripe.Customer{id: "cus_econnrefused_ok"}}
      end)

      assert {:ok, stripe_customer} = StripeService.create_customer(customer)
      assert stripe_customer.id == "cus_econnrefused_ok"
    end

    test "retries on api_connection_error" do
      customer = insert(:customer)

      expect(Rsolv.Billing.StripeMock, :create, fn _params ->
        {:error,
         %Stripe.Error{
           source: :stripe,
           code: :api_connection_error,
           message: "Could not connect to Stripe"
         }}
      end)

      expect(Rsolv.Billing.StripeMock, :create, fn _params ->
        {:ok, %Stripe.Customer{id: "cus_connection_ok"}}
      end)

      assert {:ok, stripe_customer} = StripeService.create_customer(customer)
      assert stripe_customer.id == "cus_connection_ok"
    end

    test "retries on api_error (general Stripe error)" do
      customer = insert(:customer)

      expect(Rsolv.Billing.StripeMock, :create, fn _params ->
        {:error,
         %Stripe.Error{
           source: :stripe,
           code: :api_error,
           message: "Internal server error"
         }}
      end)

      expect(Rsolv.Billing.StripeMock, :create, fn _params ->
        {:ok, %Stripe.Customer{id: "cus_api_error_ok"}}
      end)

      assert {:ok, stripe_customer} = StripeService.create_customer(customer)
      assert stripe_customer.id == "cus_api_error_ok"
    end
  end

  describe "retry behavior for other operations" do
    test "retries attach_payment_method on timeout" do
      # First attempt fails with timeout
      expect(Rsolv.Billing.StripePaymentMethodMock, :attach, fn _params ->
        {:error, %HTTPoison.Error{reason: :timeout}}
      end)

      # Second attempt succeeds
      expect(Rsolv.Billing.StripePaymentMethodMock, :attach, fn _params ->
        {:ok, %Stripe.PaymentMethod{id: "pm_test123"}}
      end)

      stub(Rsolv.Billing.StripeMock, :update, fn _id, _params ->
        {:ok, %Stripe.Customer{id: "cus_test123"}}
      end)

      assert {:ok, "pm_test123"} =
               StripeService.attach_payment_method("cus_test123", "pm_test123")
    end

    test "retries create_subscription on rate limit" do
      expect(Rsolv.Billing.StripeSubscriptionMock, :create, fn _params ->
        {:error,
         %Stripe.Error{
           source: :stripe,
           code: :rate_limit_error,
           message: "Too many requests"
         }}
      end)

      expect(Rsolv.Billing.StripeSubscriptionMock, :create, fn _params ->
        {:ok, %Stripe.Subscription{id: "sub_test123", status: "active"}}
      end)

      assert {:ok, subscription} = StripeService.create_subscription("cus_test123", "price_pro")
      assert subscription.id == "sub_test123"
    end

    test "retries update_subscription on api_connection_error" do
      expect(Rsolv.Billing.StripeSubscriptionMock, :update, fn _id, _params ->
        {:error,
         %Stripe.Error{
           source: :stripe,
           code: :api_connection_error,
           message: "Connection failed"
         }}
      end)

      expect(Rsolv.Billing.StripeSubscriptionMock, :update, fn _id, _params ->
        {:ok, %Stripe.Subscription{id: "sub_test123", cancel_at_period_end: true}}
      end)

      assert {:ok, subscription} =
               StripeService.update_subscription("sub_test123", %{cancel_at_period_end: true})

      assert subscription.cancel_at_period_end == true
    end

    test "retries create_charge on network timeout" do
      customer = insert(:customer, stripe_customer_id: "cus_test123")

      # First attempt fails with timeout
      expect(Rsolv.Billing.StripeChargeMock, :create, fn _params ->
        {:error, %HTTPoison.Error{reason: :timeout}}
      end)

      # Second attempt succeeds
      expect(Rsolv.Billing.StripeChargeMock, :create, fn _params ->
        {:ok, %Stripe.Charge{id: "ch_test123", amount: 2900, status: "succeeded"}}
      end)

      assert {:ok, charge} = StripeService.create_charge(customer, 2900, %{})
      assert charge.id == "ch_test123"
      assert charge.amount == 2900
    end
  end

  describe "telemetry events" do
    test "emits retry telemetry event on each retry attempt" do
      customer = insert(:customer)

      test_pid = self()

      :telemetry.attach_many(
        "test-retry-handler",
        [
          [:rsolv, :billing, :stripe, :create_customer, :retry],
          [:rsolv, :billing, :stripe, :create_customer, :stop]
        ],
        fn event, measurements, metadata, _config ->
          send(test_pid, {:telemetry_event, event, measurements, metadata})
        end,
        nil
      )

      # First attempt fails with timeout
      expect(Rsolv.Billing.StripeMock, :create, fn _params ->
        {:error, %HTTPoison.Error{reason: :timeout}}
      end)

      # Second attempt succeeds
      expect(Rsolv.Billing.StripeMock, :create, fn _params ->
        {:ok, %Stripe.Customer{id: "cus_telemetry"}}
      end)

      assert {:ok, _} = StripeService.create_customer(customer)

      assert_receive {:telemetry_event, [:rsolv, :billing, :stripe, :create_customer, :retry],
                      %{attempt: 1, backoff_ms: backoff}, _metadata}

      assert backoff >= 1000

      assert_receive {:telemetry_event, [:rsolv, :billing, :stripe, :create_customer, :stop],
                      %{duration: _}, _metadata}

      :telemetry.detach("test-retry-handler")
    end
  end
end
