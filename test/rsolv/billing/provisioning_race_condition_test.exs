defmodule Rsolv.Billing.ProvisioningRaceConditionTest do
  @moduledoc """
  Tests SELECT FOR UPDATE prevents double-crediting billing bonus (RFC-069).
  """
  use Rsolv.DataCase, async: false
  import Mox

  alias Rsolv.{Billing, Repo}
  alias Rsolv.Billing.CreditLedger
  alias Rsolv.Customers.Customer

  setup :verify_on_exit!

  defp bonus_count(customer) do
    customer
    |> CreditLedger.list_transactions()
    |> Enum.count(&(&1.source == "trial_billing_added"))
  end

  defp mock_stripe_attach(times \\ 1) do
    expect(Rsolv.Billing.StripePaymentMethodMock, :attach, times, fn params ->
      {:ok, %{id: params.payment_method, customer: params.customer}}
    end)

    expect(Rsolv.Billing.StripeMock, :update, times, fn id, _ ->
      {:ok, %{id: id}}
    end)
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
      mock_stripe_attach(2)
      initial_balance = customer.credit_balance

      # Run two concurrent requests
      [result1, result2] =
        Task.async_stream(
          [1, 2],
          fn _ -> Billing.add_payment_method(customer, "pm_test_card", true) end,
          timeout: 10_000
        )
        |> Enum.to_list()

      assert {:ok, {:ok, _}} = result1
      assert {:ok, {:ok, _}} = result2

      # Verify: only +5 credits and one bonus transaction
      final = Repo.get!(Customer, customer.id)
      assert final.credit_balance == initial_balance + 5
      assert bonus_count(final) == 1
    end

    test "second request sees has_payment_method and skips bonus", %{customer: customer} do
      mock_stripe_attach(2)
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
      mock_stripe_attach(3)
      initial = customer.credit_balance

      # Simulate 3 rapid clicks
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
      customer =
        insert(:customer, stripe_customer_id: nil, credit_balance: 5, has_payment_method: false)

      new_id = "cus_newly_created"
      initial = customer.credit_balance

      # Only one Stripe customer will be created due to SELECT FOR UPDATE lock
      expect(Rsolv.Billing.StripeMock, :create, fn _ ->
        {:ok, %{id: new_id, email: customer.email}}
      end)

      mock_stripe_attach(2)

      results =
        Task.async_stream(
          [1, 2],
          fn _ -> Billing.add_payment_method(customer, "pm_test", true) end,
          timeout: 10_000
        )
        |> Enum.to_list()

      assert Enum.all?(results, &match?({:ok, {:ok, _}}, &1))

      final = Repo.get!(Customer, customer.id)
      assert final.stripe_customer_id == new_id
      assert final.credit_balance == initial + 5
      assert bonus_count(final) == 1
    end
  end

  describe "error handling" do
    test "lock released on Stripe error" do
      customer = insert(:customer, credit_balance: 10, has_payment_method: false)

      # First attempt creates Stripe customer but fails to attach payment method
      # The transaction is rolled back, so stripe_customer_id is not saved
      expect(Rsolv.Billing.StripeMock, :create, fn _ ->
        {:ok, %{id: "cus_error_test_1", email: customer.email}}
      end)

      expect(Rsolv.Billing.StripePaymentMethodMock, :attach, fn _ ->
        {:error, %{message: "card_declined"}}
      end)

      assert {:error, _} = Billing.add_payment_method(customer, "pm_bad", true)

      # Second attempt needs to create Stripe customer again (first was rolled back)
      expect(Rsolv.Billing.StripeMock, :create, fn _ ->
        {:ok, %{id: "cus_error_test_2", email: customer.email}}
      end)

      # Second attempt succeeds (proves lock was released)
      mock_stripe_attach()
      assert {:ok, updated} = Billing.add_payment_method(customer, "pm_good", true)
      assert updated.has_payment_method
      assert updated.credit_balance == 15
    end
  end
end
