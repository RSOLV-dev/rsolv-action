defmodule Rsolv.Billing.SubscriptionManagementTest do
  use ExUnit.Case, async: true

  alias Rsolv.Billing.SubscriptionManagement
  alias Rsolv.Customers.Customer

  describe "subscribe_to_pro/1" do
    test "returns error when customer has no payment method" do
      customer = %Customer{
        id: 1,
        email: "test@example.com",
        has_payment_method: false
      }

      assert {:error, :no_payment_method} =
        SubscriptionManagement.subscribe_to_pro(customer)
    end
  end

  describe "cancel_subscription/2" do
    test "returns error when customer has no active subscription" do
      customer = %Customer{
        id: 1,
        email: "test@example.com",
        stripe_subscription_id: nil
      }

      assert {:error, :no_active_subscription} =
        SubscriptionManagement.cancel_subscription(customer, true)

      assert {:error, :no_active_subscription} =
        SubscriptionManagement.cancel_subscription(customer, false)
    end
  end
end
