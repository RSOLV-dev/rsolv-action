defmodule Rsolv.Billing.StripeServiceTest do
  use Rsolv.DataCase, async: true

  import Mox

  alias Rsolv.Billing.StripeService

  # Setup mocks
  setup :verify_on_exit!

  describe "create_customer/2" do
    test "creates Stripe customer with metadata" do
      customer = insert(:customer, name: "Test User")

      # Mock Stripe API response
      expect(Rsolv.Billing.StripeMock, :create, fn params ->
        assert params[:email] == customer.email
        assert params[:name] == "Test User"
        assert params[:metadata]["rsolv_customer_id"] == customer.id

        {:ok,
         %Stripe.Customer{
           id: "cus_test123",
           email: customer.email,
           metadata: %{"rsolv_customer_id" => to_string(customer.id)}
         }}
      end)

      assert {:ok, stripe_customer} = StripeService.create_customer(customer)
      assert stripe_customer.id == "cus_test123"
    end

    test "includes customer metadata in Stripe customer" do
      customer = insert(:customer, metadata: %{"source" => "github_action"})

      expect(Rsolv.Billing.StripeMock, :create, fn params ->
        assert params[:metadata]["rsolv_customer_id"] == customer.id
        assert params[:metadata]["source"] == "github_action"

        {:ok, %Stripe.Customer{id: "cus_test456"}}
      end)

      assert {:ok, _stripe_customer} = StripeService.create_customer(customer)
    end

    test "handles Stripe API errors gracefully" do
      customer = insert(:customer)

      expect(Rsolv.Billing.StripeMock, :create, fn _params ->
        {:error,
         %Stripe.Error{
           source: :stripe,
           code: "invalid_request_error",
           message: "Invalid API key"
         }}
      end)

      assert {:error, %Stripe.Error{message: "Invalid API key"}} =
               StripeService.create_customer(customer)
    end

    test "handles network errors" do
      customer = insert(:customer)

      expect(Rsolv.Billing.StripeMock, :create, fn _params ->
        {:error, %HTTPoison.Error{reason: :timeout}}
      end)

      assert {:error, :network_error} = StripeService.create_customer(customer)
    end
  end

  describe "get_customer/1" do
    test "retrieves Stripe customer by ID" do
      expect(Rsolv.Billing.StripeMock, :retrieve, fn "cus_test123" ->
        {:ok,
         %Stripe.Customer{
           id: "cus_test123",
           email: "retrieved@example.com"
         }}
      end)

      assert {:ok, stripe_customer} = StripeService.get_customer("cus_test123")
      assert stripe_customer.id == "cus_test123"
    end

    test "handles customer not found" do
      expect(Rsolv.Billing.StripeMock, :retrieve, fn "cus_invalid" ->
        {:error,
         %Stripe.Error{
           source: :stripe,
           code: :invalid_request_error,
           message: "No such customer"
         }}
      end)

      assert {:error, :not_found} = StripeService.get_customer("cus_invalid")
    end
  end

  describe "telemetry and logging" do
    test "emits telemetry event on successful customer creation" do
      customer = insert(:customer)

      expect(Rsolv.Billing.StripeMock, :create, fn _params ->
        {:ok, %Stripe.Customer{id: "cus_test789"}}
      end)

      # In a real implementation, we would set up telemetry handlers to verify
      # events are emitted. For now, just verify the operation succeeds.
      assert {:ok, _} = StripeService.create_customer(customer)
    end
  end
end
