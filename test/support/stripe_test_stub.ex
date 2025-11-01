defmodule Rsolv.Billing.StripeTestStub do
  @moduledoc """
  Default stub implementation for Stripe Mock in tests.

  This provides sensible defaults for all Stripe API operations,
  allowing tests to override specific behaviors with `expect/3` or `stub/3`.

  ## Usage

  In your test setup:

      setup do
        Mox.stub_with(Rsolv.Billing.StripeMock, Rsolv.Billing.StripeTestStub)
        :ok
      end

  Then override specific calls with `expect/3`:

      test "subscribes to Pro" do
        expect(Rsolv.Billing.StripeMock, :create_subscription, fn params ->
          {:ok, %{id: "sub_123", status: "active"}}
        end)

        # test code here
      end
  """

  @behaviour Rsolv.Billing.StripeClientBehaviour
  # Note: StripeClientBehaviour already includes all charge operations via create_charge/1
  # No need for separate StripeChargeBehaviour to avoid callback conflicts

  # Implement actual Stripe.Customer API interface
  # This handles both Stripe.Customer.create and Stripe.Subscription.create
  @impl true
  def create(params) when is_map(params) do
    cond do
      # Subscription creation (has :customer and :items keys)
      Map.has_key?(params, :customer) and Map.has_key?(params, :items) ->
        {:ok,
         %{
           id: "sub_test_#{random_id()}",
           customer: params[:customer],
           status: "active",
           items: %{
             data: [
               %{
                 price: %{
                   id: params[:items] |> hd() |> Map.get(:price),
                   recurring: %{interval: "month"}
                 }
               }
             ]
           },
           current_period_start: DateTime.to_unix(DateTime.utc_now()),
           current_period_end: DateTime.to_unix(DateTime.add(DateTime.utc_now(), 30, :day))
         }}

      # Customer creation (has :email key)
      Map.has_key?(params, :email) ->
        {:ok,
         %{
           id: "cus_test_#{random_id()}",
           email: params[:email],
           name: params[:name]
         }}

      # Default to customer creation
      true ->
        {:ok,
         %{
           id: "cus_test_#{random_id()}",
           email: "unknown@test.example.com",
           name: "Test Customer"
         }}
    end
  end

  def create(params) when is_list(params) do
    # Convert keyword list to map and recursively call
    create(Enum.into(params, %{}))
  end

  @impl true
  def retrieve(customer_id) do
    {:ok,
     %{
       id: customer_id,
       email: "test@example.com",
       name: "Test Customer"
     }}
  end

  @impl true
  def update(customer_id_or_subscription_id, params) do
    {:ok,
     %{
       id: customer_id_or_subscription_id,
       email: "test@example.com",
       name: "Test Customer",
       invoice_settings: params[:invoice_settings] || %{},
       # For subscription updates
       status: "active",
       cancel_at_period_end: params[:cancel_at_period_end] || false,
       current_period_end: DateTime.to_unix(DateTime.add(DateTime.utc_now(), 15, :day))
     }}
  end

  # Implement actual Stripe.PaymentMethod API interface
  @impl true
  def attach(params) do
    {:ok,
     %{
       id: params[:payment_method],
       customer: params[:customer],
       type: "card",
       card: %{
         brand: "visa",
         last4: "4242"
       }
     }}
  end

  # Implement actual Stripe.Subscription API interface
  @impl true
  def cancel(subscription_id) do
    {:ok,
     %{
       id: subscription_id,
       status: "canceled",
       canceled_at: DateTime.to_unix(DateTime.utc_now())
     }}
  end

  # Implement behaviour methods (for when they're used via behaviour interface)
  @impl true
  def create_customer(params), do: create(params)

  @impl true
  def retrieve_customer(customer_id), do: retrieve(customer_id)

  @impl true
  def update_customer(customer_id, params), do: update(customer_id, params)

  @impl true
  def attach_payment_method(customer_id, payment_method_id) do
    attach(%{customer: customer_id, payment_method: payment_method_id})
  end

  @impl true
  def create_subscription(params) do
    {:ok,
     %{
       id: "sub_test_#{random_id()}",
       customer: params[:customer],
       status: "active",
       items: %{
         data: [
           %{
             price: %{
               id: params[:items] |> hd() |> Map.get(:price),
               recurring: %{interval: "month"}
             }
           }
         ]
       },
       current_period_start: DateTime.to_unix(DateTime.utc_now()),
       current_period_end: DateTime.to_unix(DateTime.add(DateTime.utc_now(), 30, :day))
     }}
  end

  @impl true
  def update_subscription(subscription_id, params) do
    {:ok,
     %{
       id: subscription_id,
       status: "active",
       cancel_at_period_end: params[:cancel_at_period_end] || false,
       current_period_end: DateTime.to_unix(DateTime.add(DateTime.utc_now(), 15, :day))
     }}
  end

  @impl true
  def cancel_subscription(subscription_id), do: cancel(subscription_id)

  @impl true
  def retrieve_invoice(invoice_id) do
    {:ok,
     %{
       id: invoice_id,
       amount_paid: 59900,
       status: "paid",
       subscription: "sub_test_#{random_id()}"
     }}
  end

  @impl true
  def create_charge(params) do
    {:ok,
     %{
       id: "ch_test_#{random_id()}",
       amount: params[:amount],
       currency: params[:currency] || "usd",
       status: "succeeded",
       customer: params[:customer]
     }}
  end

  # Private helpers

  defp random_id do
    :crypto.strong_rand_bytes(8) |> Base.encode64(padding: false) |> binary_part(0, 11)
  end
end
