defmodule Rsolv.Billing.ProvisioningRaceConditionTest do
  @moduledoc """
  Tests SELECT FOR UPDATE prevents double-crediting billing bonus (RFC-069).
  """
  use Rsolv.DataCase, async: false
  import Mox
  import Rsolv.StripeTestHelpers

  alias Rsolv.{Billing, Repo}
  alias Rsolv.Billing.CreditLedger
  alias Rsolv.Customers.Customer

  setup :verify_on_exit!

  defp bonus_count(customer) do
    customer
    |> CreditLedger.list_transactions()
    |> Enum.count(&(&1.source == "trial_billing_added"))
  end

  describe "concurrent payment method additions" do
    setup do
      customer =
        insert(:customer,
          stripe_customer_id: "cus_test123",
          credit_balance: 10,
          has_payment_method: false,
          subscription_type: "trial"
        )

      %{customer: customer}
    end

    test "concurrent requests only credit bonus once", %{customer: customer} do
      mock_payment_method_attach("pm_test_card", customer.stripe_customer_id, times: 2)
      initial_balance = customer.credit_balance

      results =
        Task.async_stream(
          [1, 2],
          fn _ -> Billing.add_payment_method(customer, "pm_test_card", true) end,
          timeout: 10_000
        )
        |> Enum.to_list()

      assert Enum.all?(results, &match?({:ok, {:ok, _}}, &1))

      final = Repo.get!(Customer, customer.id)
      assert final.credit_balance == initial_balance + 5
      assert bonus_count(final) == 1
    end

    test "second request sees has_payment_method and skips bonus", %{customer: customer} do
      mock_payment_method_attach("pm_1", customer.stripe_customer_id)
      mock_payment_method_attach("pm_2", customer.stripe_customer_id)
      initial = customer.credit_balance

      # First request gets bonus
      assert {:ok, after_first} = Billing.add_payment_method(customer, "pm_1", true)
      assert after_first.has_payment_method
      assert after_first.credit_balance == initial + 5

      # Second request skips bonus (simulates serialized concurrent requests)
      assert {:ok, after_second} = Billing.add_payment_method(after_first, "pm_2", true)
      assert after_second.credit_balance == initial + 5
      assert bonus_count(after_second) == 1
    end

    test "triple concurrent requests (double-click simulation)", %{customer: customer} do
      mock_payment_method_attach("pm_test", customer.stripe_customer_id, times: 3)
      initial = customer.credit_balance

      results =
        Task.async_stream(
          [1, 2, 3],
          fn _ -> Billing.add_payment_method(customer, "pm_test", true) end,
          timeout: 10_000
        )
        |> Enum.to_list()

      assert Enum.all?(results, &match?({:ok, {:ok, _}}, &1))

      final = Repo.get!(Customer, customer.id)
      assert final.credit_balance == initial + 5
      assert bonus_count(final) == 1
    end
  end

  describe "trial customer without Stripe customer" do
    test "concurrent requests with Stripe creation only credit once" do
      customer = insert(:customer, stripe_customer_id: nil, credit_balance: 5)

      # Only one Stripe customer will be created due to SELECT FOR UPDATE lock
      mock_stripe_customer_create("cus_newly_created", customer.email)
      mock_payment_method_attach("pm_test", "cus_newly_created", times: 2)

      results =
        Task.async_stream(
          [1, 2],
          fn _ -> Billing.add_payment_method(customer, "pm_test", true) end,
          timeout: 10_000
        )
        |> Enum.to_list()

      assert Enum.all?(results, &match?({:ok, {:ok, _}}, &1))

      final = Repo.get!(Customer, customer.id)
      assert final.stripe_customer_id == "cus_newly_created"
      assert final.credit_balance == 10
      assert bonus_count(final) == 1
    end
  end

  describe "error handling" do
    test "lock released on Stripe error" do
      customer = insert(:customer, credit_balance: 10)

      # First attempt: customer creation succeeds, payment method attachment fails
      # Transaction rolls back, so we need to create customer again on retry
      mock_stripe_customer_create("cus_error_test_1", customer.email)

      import Mox

      expect(Rsolv.Billing.StripePaymentMethodMock, :attach, fn _ ->
        {:error, %{message: "card_declined"}}
      end)

      assert {:error, _} = Billing.add_payment_method(customer, "pm_bad", true)

      # Second attempt: customer created again (first rolled back), now succeeds
      mock_stripe_customer_create("cus_error_test_2", customer.email)
      mock_payment_method_attach("pm_good", "cus_error_test_2")

      assert {:ok, updated} = Billing.add_payment_method(customer, "pm_good", true)
      assert updated.has_payment_method
      assert updated.credit_balance == 15
    end
  end
end
