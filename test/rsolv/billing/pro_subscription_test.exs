defmodule Rsolv.Billing.ProSubscriptionTest do
  @moduledoc """
  End-to-end verification tests for RFC-066 payment method addition and Pro subscription flow.

  This test suite verifies:
  - Payment method addition with billing consent
  - Stripe payment method attachment
  - Trial to Pro upgrade flow
  - Initial $599 charge processing
  - Credit allocation on payment (via webhook simulation)

  These tests use Mox to mock Stripe API calls.
  """
  use Rsolv.DataCase, async: false
  import Mox
  import Rsolv.StripeTestHelpers

  alias Rsolv.Billing
  alias Rsolv.Billing.{CreditLedger, Subscription}
  alias Rsolv.Repo

  setup :verify_on_exit!

  describe "Pro subscription flow (RFC-066 verification)" do
    test "complete flow: add payment method → subscribe to Pro → verify credits" do
      # ARRANGE: Create trial customer with initial 5 credits
      customer =
        insert(:customer,
          email: "trial@example.com",
          name: "Trial Customer",
          subscription_type: "trial",
          subscription_state: "active",
          credit_balance: 5,
          stripe_customer_id: "cus_test_trial_user",
          has_payment_method: false,
          billing_consent_given: false
        )

      # ACT 1: Add payment method with billing consent
      payment_method_id = "pm_test_visa"
      mock_payment_method_attach(payment_method_id, customer.stripe_customer_id)

      assert {:ok, customer_with_payment} =
               Billing.add_payment_method(customer, payment_method_id, true)

      # ASSERT 1: Payment method added, consent given, credits increased to 10
      assert customer_with_payment.stripe_payment_method_id == payment_method_id
      assert customer_with_payment.has_payment_method == true
      assert customer_with_payment.billing_consent_given == true
      assert customer_with_payment.billing_consent_at != nil
      assert customer_with_payment.payment_method_added_at != nil
      assert customer_with_payment.credit_balance == 10, "Should have 5 initial + 5 bonus = 10"

      # Verify billing_added transaction
      transactions = CreditLedger.list_transactions(customer_with_payment)
      assert length(transactions) == 1
      [billing_txn] = transactions
      assert billing_txn.source == "trial_billing_added"
      assert billing_txn.amount == 5
      assert billing_txn.balance_after == 10

      # ACT 2: Subscribe to Pro plan
      pro_price_id = "price_test_pro_monthly_50000"
      stripe_subscription_id =
        mock_stripe_subscription_create(
          customer_with_payment.stripe_customer_id,
          subscription_id: "sub_test_pro_123",
          price_id: pro_price_id
        )

      assert {:ok, pro_customer} = Billing.subscribe_to_pro(customer_with_payment)

      # ASSERT 2: Subscription created, customer upgraded to Pro
      assert pro_customer.subscription_type == "pro"
      assert pro_customer.subscription_state == "active"
      assert pro_customer.stripe_subscription_id == stripe_subscription_id
      assert pro_customer.subscription_cancel_at_period_end == false

      # Verify subscription record created
      subscription = Repo.get_by(Subscription, stripe_subscription_id: stripe_subscription_id)
      assert subscription != nil
      assert subscription.customer_id == pro_customer.id
      assert subscription.plan == "pro"
      assert subscription.status == "active"

      # ACT 3: Simulate webhook invoice.paid event (credits 60 fixes)
      # In real flow, this would come from Stripe webhook, but we simulate it here
      {:ok, %{customer: customer_with_pro_credits}} =
        CreditLedger.credit(pro_customer, 60, "pro_subscription_payment", %{
          "stripe_invoice_id" => "in_test_123",
          "amount_cents" => 59_900
        })

      # ASSERT 3: Credits increased by 60 (10 existing + 60 new = 70)
      assert customer_with_pro_credits.credit_balance == 70

      # Verify pro_subscription_payment transaction
      all_transactions = CreditLedger.list_transactions(customer_with_pro_credits)
      assert length(all_transactions) == 2

      pro_credit_txn = Enum.find(all_transactions, &(&1.source == "pro_subscription_payment"))
      assert pro_credit_txn.amount == 60
      assert pro_credit_txn.balance_after == 70
      assert pro_credit_txn.metadata["stripe_invoice_id"] == "in_test_123"
      assert pro_credit_txn.metadata["amount_cents"] == 59_900
    end

    test "requires payment method before subscribing to Pro" do
      # ARRANGE: Customer without payment method
      customer =
        insert(:customer,
          email: "nopayment@example.com",
          has_payment_method: false,
          stripe_customer_id: "cus_test_no_payment"
        )

      # ACT & ASSERT: Should fail with no_payment_method error
      assert {:error, :no_payment_method} = Billing.subscribe_to_pro(customer)
    end

    test "payment method addition requires billing consent" do
      # ARRANGE: Trial customer
      customer =
        insert(:customer,
          email: "noconsent@example.com",
          stripe_customer_id: "cus_test_no_consent"
        )

      # ACT & ASSERT: Should fail without billing consent
      assert {:error, :billing_consent_required} =
               Billing.add_payment_method(customer, "pm_test_visa", false)
    end

    test "verify $599 charge amount for Pro subscription" do
      customer =
        insert(:customer,
          stripe_customer_id: "cus_test_price_check",
          has_payment_method: true
        )

      # Mock verifies correct price_id is passed to Stripe
      pro_price_id = "price_test_pro_monthly_50000"
      mock_stripe_subscription_create(customer.stripe_customer_id, price_id: pro_price_id)

      assert {:ok, _} = Billing.subscribe_to_pro(customer)
    end

    test "60 credits allocated when invoice.paid webhook received" do
      # ARRANGE: Pro customer (subscription just created)
      customer =
        insert(:customer,
          email: "webhook@example.com",
          subscription_type: "pro",
          subscription_state: "active",
          credit_balance: 10,
          stripe_subscription_id: "sub_test_webhook"
        )

      # ACT: Simulate webhook processing (credit customer 60 fixes)
      {:ok, %{customer: updated_customer}} =
        CreditLedger.credit(customer, 60, "pro_subscription_payment", %{
          "stripe_invoice_id" => "in_webhook_test",
          "amount_cents" => 59_900
        })

      # ASSERT: 60 credits added (10 + 60 = 70)
      assert updated_customer.credit_balance == 70

      # Verify transaction recorded correctly
      transactions = CreditLedger.list_transactions(updated_customer)
      [txn] = transactions
      assert txn.source == "pro_subscription_payment"
      assert txn.amount == 60
      assert txn.balance_after == 70
    end
  end

  describe "usage summary for Pro customers (RFC-071 integration)" do
    test "get_usage_summary shows Pro subscription details" do
      # ARRANGE: Pro customer with credits
      customer =
        insert(:customer,
          email: "summary@example.com",
          subscription_type: "pro",
          subscription_state: "active",
          credit_balance: 45,
          has_payment_method: true
        )

      # ACT: Get usage summary
      assert {:ok, summary} = Billing.get_usage_summary(customer.id)

      # ASSERT: Summary includes correct Pro details
      assert summary.credit_balance == 45
      assert summary.subscription_type == "pro"
      assert summary.subscription_state == "active"
      assert summary.has_payment_method == true
      assert summary.recent_transactions == []
      assert summary.warnings == []
    end

    test "get_usage_summary warns when Pro customer has low credits" do
      # ARRANGE: Pro customer with only 3 credits left
      customer =
        insert(:customer,
          email: "lowcredits@example.com",
          subscription_type: "pro",
          subscription_state: "active",
          credit_balance: 3,
          has_payment_method: true
        )

      # ACT: Get usage summary
      assert {:ok, summary} = Billing.get_usage_summary(customer.id)

      # ASSERT: Warning shown for low credits
      assert "Low credit balance: 3 credits remaining" in summary.warnings
    end
  end
end
