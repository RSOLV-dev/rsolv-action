defmodule Rsolv.BillingInfrastructureTest do
  @moduledoc """
  Smoke tests for RFC-068 Week 1 billing test infrastructure.

  Verifies that all infrastructure components work together:
  - Test factories (ExMachina)
  - Test fixtures
  - StripeMock service
  - Test helpers
  - Bamboo email testing
  """
  use Rsolv.DataCase, async: true

  # Use CustomerFactory for building customer structs (not the old Factory version)
  import Rsolv.CustomerFactory
  import Rsolv.CustomersFixtures
  import Rsolv.TestHelpers
  import Rsolv.StripeTestHelpers

  alias Rsolv.StripeMock
  alias Rsolv.Customers.Customer

  describe "CustomerFactory" do
    test "builds basic customer" do
      customer = Rsolv.CustomerFactory.build(:customer)

      assert %Customer{} = customer
      assert customer.email =~ "@test.example.com"
      assert customer.subscription_plan == "trial"
    end

    test "with_trial_credits trait sets 5 credits" do
      customer = Rsolv.CustomerFactory.build(:customer) |> with_trial_credits()

      assert customer.trial_fixes_limit == 5
      assert customer.trial_fixes_used == 0
    end

    test "with_billing_added trait sets 10 credits and Stripe ID" do
      customer = Rsolv.CustomerFactory.build(:customer) |> with_billing_added()

      assert customer.trial_fixes_limit == 10
      assert customer.has_payment_method == true
      assert customer.stripe_customer_id =~ "cus_test_"
      assert customer.payment_method_added_at != nil
    end

    test "with_pro_plan trait sets 60 credits and Pro status" do
      customer = Rsolv.CustomerFactory.build(:customer) |> with_pro_plan()

      assert customer.subscription_plan == "pro"
      assert customer.subscription_status == "active"
      assert customer.fixes_quota_this_month == 60
      assert customer.fixes_used_this_month == 0
    end

    test "with_pro_plan_partial_usage trait sets used credits" do
      customer = Rsolv.CustomerFactory.build(:customer) |> with_pro_plan_partial_usage()

      assert customer.fixes_used_this_month == 15
      assert customer.fixes_quota_this_month == 60
    end

    test "with_past_due trait sets past_due status" do
      customer = Rsolv.CustomerFactory.build(:customer) |> with_pro_plan() |> with_past_due()

      assert customer.subscription_status == "past_due"
    end

    test "with_expired_trial trait sets expired state" do
      customer = Rsolv.CustomerFactory.build(:customer) |> with_expired_trial()

      assert customer.trial_fixes_used == 5
      assert customer.trial_fixes_limit == 5
      assert customer.trial_expired_at != nil
      assert DateTime.compare(customer.trial_expired_at, DateTime.utc_now()) == :lt
    end

    test "with_payg trait sets PAYG plan" do
      customer = Rsolv.CustomerFactory.build(:customer) |> with_payg()

      assert customer.subscription_plan == "payg"
      assert customer.has_payment_method == true
    end
  end

  describe "Subscription Fixtures" do
    test "subscription_fixture creates valid Stripe subscription" do
      subscription = subscription_fixture()

      assert subscription.id =~ "sub_test_"
      assert subscription.object == "subscription"
      assert subscription.status == "active"
      assert is_integer(subscription.current_period_start)
      assert is_integer(subscription.current_period_end)
    end

    test "subscription_fixture accepts custom attributes" do
      subscription = subscription_fixture(%{status: "past_due", customer: "cus_custom"})

      assert subscription.status == "past_due"
      assert subscription.customer == "cus_custom"
    end
  end

  describe "Billing Event Fixtures" do
    test "billing_event_fixture creates subscription.created event" do
      event = billing_event_fixture("customer.subscription.created")

      assert event.type == "customer.subscription.created"
      assert event.object == "event"
      assert event.data.object.status == "active"
    end

    test "billing_event_fixture creates invoice.payment_succeeded event" do
      event = billing_event_fixture("invoice.payment_succeeded")

      assert event.type == "invoice.payment_succeeded"
      assert event.data.object.status == "paid"
    end

    test "billing_event_fixture creates invoice.payment_failed event" do
      event = billing_event_fixture("invoice.payment_failed")

      assert event.type == "invoice.payment_failed"
      assert event.data.object.status == "open"
    end
  end

  describe "Credit Transaction Fixtures" do
    test "credit_transaction_fixture creates valid transaction" do
      transaction = credit_transaction_fixture()

      assert transaction.amount == 5
      assert transaction.transaction_type == "signup_bonus"
      assert transaction.description =~ "Signup"
    end

    test "credit_transaction_fixture accepts custom attributes" do
      transaction =
        credit_transaction_fixture(%{
          amount: 60,
          transaction_type: "subscription_payment"
        })

      assert transaction.amount == 60
      assert transaction.transaction_type == "subscription_payment"
    end
  end

  describe "StripeMock" do
    test "create_customer succeeds with valid email" do
      {:ok, customer} = StripeMock.create_customer(%{email: "test@example.com"})

      assert customer.id =~ "cus_test_"
      assert customer.email == "test@example.com"
      assert customer.object == "customer"
    end

    test "create_customer fails with fail@test.example.com" do
      {:error, error} = StripeMock.create_customer(%{email: "fail@test.example.com"})

      assert error.error.type == "card_declined"
      assert error.error.message =~ "declined"
    end

    test "create_subscription succeeds with valid customer" do
      {:ok, subscription} = StripeMock.create_subscription(%{customer: "cus_test_123"})

      assert subscription.customer == "cus_test_123"
      assert subscription.status == "active"
    end

    test "create_subscription fails with cus_no_payment" do
      {:error, error} = StripeMock.create_subscription(%{customer: "cus_no_payment"})

      assert error.error.message =~ "no attached payment"
    end

    test "update_subscription merges parameters" do
      {:ok, subscription} =
        StripeMock.update_subscription("sub_123", %{cancel_at_period_end: true})

      assert subscription.id == "sub_123"
      assert subscription.cancel_at_period_end == true
    end

    test "cancel_subscription sets canceled status" do
      {:ok, subscription} = StripeMock.cancel_subscription("sub_123")

      assert subscription.id == "sub_123"
      assert subscription.status == "canceled"
    end

    test "construct_event returns valid webhook event" do
      {:ok, event} = StripeMock.construct_event("payload", "signature", "secret")

      assert event.type == "customer.subscription.created"
      assert event.object == "event"
    end

    test "create_payment_intent succeeds with valid amount" do
      {:ok, intent} = StripeMock.create_payment_intent(%{amount: 2900, currency: "usd"})

      assert intent.amount == 2900
      assert intent.currency == "usd"
      assert intent.status == "requires_payment_method"
    end
  end

  describe "Stripe Test Helpers" do
    test "generate_webhook_signature returns valid format" do
      signature = generate_webhook_signature("test payload")

      assert signature =~ ~r/^t=\d+,v1=[a-f0-9]+$/
    end

    test "create_signed_webhook returns payload and signature" do
      {payload, signature} = create_signed_webhook("customer.subscription.created")

      assert is_binary(payload)
      {:ok, decoded} = Jason.decode(payload)
      assert decoded["type"] == "customer.subscription.created"

      assert signature =~ ~r/^t=\d+,v1=/
    end

    test "simulate_successful_payment returns succeeded intent" do
      payment = simulate_successful_payment(2900)

      assert payment.status == "succeeded"
      assert payment.amount == 2900
    end

    test "simulate_failed_payment returns failed intent with error" do
      payment = simulate_failed_payment(2900, "card_declined")

      assert payment.status == "requires_payment_method"
      assert payment.last_payment_error.code == "card_declined"
    end

    test "advance_subscription_period moves dates forward" do
      subscription = subscription_fixture()
      original_end = subscription.current_period_end

      advanced = advance_subscription_period(subscription, days: 30)

      assert advanced.current_period_start == original_end
      assert advanced.current_period_end > original_end
    end
  end

  describe "Test Helpers" do
    test "clear_sent_emails resets Bamboo" do
      # Should not raise
      assert :ok = clear_sent_emails()
    end

    test "create_test_api_key generates unique key" do
      customer = Rsolv.CustomerFactory.build(:customer)
      {_customer, raw_key} = create_test_api_key(%{id: customer.id, email: customer.email})

      assert raw_key =~ "rsolv_test_"
      assert String.length(raw_key) > 20
    end
  end

  describe "Integration: Complete Billing Flow" do
    test "simulates customer signup through Pro subscription" do
      # 1. New customer signs up (5 trial credits)
      customer = Rsolv.CustomerFactory.build(:customer) |> with_trial_credits()
      assert customer.trial_fixes_limit == 5

      # 2. Customer adds billing (gets +5 bonus = 10 total)
      customer = customer |> with_billing_added()
      assert customer.trial_fixes_limit == 10
      assert is_binary(customer.stripe_customer_id)

      # 3. Create Stripe customer
      {:ok, stripe_customer} =
        StripeMock.create_customer(%{
          email: customer.email,
          name: customer.name
        })

      assert stripe_customer.email == customer.email

      # 4. Customer subscribes to Pro (60 credits)
      {:ok, subscription} =
        StripeMock.create_subscription(%{
          customer: stripe_customer.id
        })

      assert subscription.status == "active"

      # 5. Webhook event for subscription created
      event =
        billing_event_fixture("customer.subscription.created", %{
          customer: stripe_customer.id
        })

      assert event.data.object.status == "active"

      # 6. Customer uses 15 credits
      customer = customer |> with_pro_plan_partial_usage()
      assert customer.fixes_used_this_month == 15
      assert customer.fixes_quota_this_month == 60

      # 7. Simulate successful payment
      payment = simulate_successful_payment(2900)
      assert payment.status == "succeeded"

      # Everything works together!
      assert true
    end
  end
end
