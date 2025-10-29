defmodule Rsolv.Billing.PaymentMethodsTest do
  use Rsolv.DataCase, async: false
  import Mox

  alias Rsolv.Billing

  setup :verify_on_exit!

  describe "add_payment_method/3" do
    setup do
      customer = insert(:customer, stripe_customer_id: "cus_test123", credit_balance: 10)
      %{customer: customer}
    end

    test "adds payment method to customer", %{customer: customer} do
      payment_method_id = "pm_test_card"
      billing_consent = true

      expect(Rsolv.Billing.StripeMock, :attach, fn params ->
        assert params.payment_method == payment_method_id
        assert params.customer == customer.stripe_customer_id
        {:ok, %{id: payment_method_id, customer: customer.stripe_customer_id}}
      end)

      expect(Rsolv.Billing.StripeMock, :update, fn stripe_customer_id, params ->
        assert stripe_customer_id == customer.stripe_customer_id
        assert params.invoice_settings.default_payment_method == payment_method_id
        {:ok, %{id: stripe_customer_id}}
      end)

      assert {:ok, updated_customer} =
               Billing.add_payment_method(customer, payment_method_id, billing_consent)

      assert updated_customer.stripe_payment_method_id == payment_method_id
      assert updated_customer.has_payment_method == true
      assert updated_customer.billing_consent_given == true
      assert updated_customer.payment_method_added_at != nil
      assert updated_customer.billing_consent_at != nil
    end

    test "requires billing consent checkbox", %{customer: customer} do
      payment_method_id = "pm_test_card"
      billing_consent = false

      assert {:error, :billing_consent_required} =
               Billing.add_payment_method(customer, payment_method_id, billing_consent)
    end

    test "credits +5 when billing added", %{customer: customer} do
      payment_method_id = "pm_test_card"
      billing_consent = true
      initial_balance = customer.credit_balance

      expect(Rsolv.Billing.StripeMock, :attach, fn _ ->
        {:ok, %{id: payment_method_id, customer: customer.stripe_customer_id}}
      end)

      expect(Rsolv.Billing.StripeMock, :update, fn _, _ ->
        {:ok, %{id: customer.stripe_customer_id}}
      end)

      assert {:ok, updated_customer} =
               Billing.add_payment_method(customer, payment_method_id, billing_consent)

      # Should get +5 credits
      assert updated_customer.credit_balance == initial_balance + 5

      # Verify transaction was recorded
      transactions = Rsolv.Billing.CreditLedger.list_transactions(updated_customer)
      assert length(transactions) == 1

      [transaction] = transactions
      assert transaction.amount == 5
      assert transaction.source == "trial_billing_added"
      assert transaction.balance_after == initial_balance + 5
    end
  end
end
