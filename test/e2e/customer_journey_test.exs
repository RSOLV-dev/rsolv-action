defmodule Rsolv.E2E.CustomerJourneyTest do
  @moduledoc """
  End-to-end tests for complete customer journeys through the RSOLV billing system.

  These tests follow the TDD RED → GREEN → REFACTOR methodology and verify
  the complete customer lifecycle from signup through subscription management.

  ## Test Coverage (RFC-069 Tuesday)

  1. **Trial Signup to First Fix** (2 tests)
     - Complete trial journey: signup → provision → first fix deployment
     - Trial customer blocked when no credits and no billing

  2. **Trial to Paid Conversion** (1 test)
     - Trial customer adds payment method and upgrades to PAYG

  3. **Marketplace Installation Flow** (1 test)
     - Customer installs from GitHub Marketplace and completes onboarding

  4. **Payment Method Addition** (2 tests)
     - Customer adds payment method with explicit billing consent
     - Payment addition without consent is rejected

  5. **Pro Subscription Creation and Renewal** (3 tests)
     - Customer subscribes to Pro plan and receives credits on payment
     - Pro subscription renewal grants another 60 credits
     - Pro customer charges $15 for additional fixes beyond credits

  6. **Subscription Cancellation** (2 tests)
     - Immediate cancellation downgrades to PAYG (rate changes $15 → $29)
     - End-of-period cancellation maintains Pro pricing until period ends

  ## TDD Phase: RED

  All tests written first to document expected behavior. Tests will initially
  fail until implementation is complete (GREEN phase).

  ## References
  - RFC-065: Automated Customer Provisioning
  - RFC-066: Credit-Based Usage Tracking
  - RFC-067: GitHub Marketplace Integration
  - RFC-069: Integration Week Plan (Tuesday: Happy Path Testing)
  """

  use Rsolv.DataCase, async: false
  import Rsolv.CustomerFactory
  import Mox

  alias Rsolv.CustomerOnboarding
  alias Rsolv.Billing
  alias Rsolv.Billing.{CreditLedger, SubscriptionManagement}
  alias Rsolv.Customers

  # Setup Mox for Stripe API mocking
  setup :verify_on_exit!

  setup do
    # Setup Stripe mocks for all Stripe API operations
    Mox.stub_with(Rsolv.Billing.StripeMock, Rsolv.Billing.StripeTestStub)

    # Manual stub for StripeChargeMock (delegate to StripeTestStub.create_charge/1)
    # Can't use stub_with because both behaviours define create/1, causing compiler warning
    Mox.stub(Rsolv.Billing.StripeChargeMock, :create, fn params ->
      Rsolv.Billing.StripeTestStub.create_charge(params)
    end)

    # Set up ConvertKit config for tests
    Application.put_env(:rsolv, :convertkit,
      api_key: "test_api_key",
      form_id: "test_form_id",
      early_access_tag_id: "7700607",
      tag_onboarding: "7700607",
      api_base_url: "https://api.convertkit.com/v3"
    )

    # Stub ConvertKit HTTP calls to prevent UnexpectedCallError
    # This allows any ConvertKit API calls to succeed without specific expectations
    Mox.stub(Rsolv.HTTPClientMock, :post, fn _url, _body, _headers, _options ->
      {:ok,
       %HTTPoison.Response{
         status_code: 200,
         body: Jason.encode!(%{"subscription" => %{"id" => 123_456}})
       }}
    end)

    :ok
  end

  # Helper to persist factory trait changes to database
  # Factory traits like with_trial_credits() return modified maps but don't persist
  # Usage: customer = insert_with_trait(:customer, &with_trial_credits/1)
  defp insert_with_trait(factory_name, trait_fun) do
    customer = insert(factory_name)
    trait_customer = trait_fun.(customer)

    changes =
      Map.take(trait_customer, [
        :credit_balance,
        :trial_fixes_limit,
        :trial_fixes_used,
        :subscription_type,
        :subscription_state,
        :has_payment_method,
        :stripe_customer_id,
        :stripe_payment_method_id,
        :stripe_subscription_id,
        :fixes_quota_this_month,
        :fixes_used_this_month,
        :rollover_fixes,
        :payment_method_added_at,
        :billing_consent_given,
        :billing_consent_at
      ])
      # Truncate DateTime fields to :second precision for database compatibility
      |> Map.update(:payment_method_added_at, nil, fn
        nil -> nil
        dt -> DateTime.truncate(dt, :second)
      end)
      |> Map.update(:billing_consent_at, nil, fn
        nil -> nil
        dt -> DateTime.truncate(dt, :second)
      end)

    Repo.update!(Ecto.Changeset.change(customer, changes))
  end

  describe "Trial Signup to First Fix" do
    test "complete trial journey: signup → provision → first fix deployment" do
      # ARRANGE: Customer signup data
      signup_params = %{
        email: "new-customer-#{System.unique_integer([:positive])}@test.rsolv.dev",
        name: "New Customer",
        source: "direct"
      }

      # ACT: Provision customer (signup flow)
      assert {:ok, %{customer: customer, api_key: api_key}} =
               CustomerOnboarding.provision_customer(signup_params)

      # ASSERT: Customer created with correct attributes
      assert customer.email == signup_params.email
      assert customer.name == signup_params.name
      assert customer.subscription_type == "trial"
      assert customer.credit_balance == 5, "Should have 5 trial credits"
      assert String.starts_with?(customer.stripe_customer_id, "cus_test_")
      assert String.starts_with?(api_key, "rsolv_")

      # ASSERT: Credit transaction recorded
      transactions = CreditLedger.list_transactions(customer)
      assert length(transactions) == 1

      first_txn = hd(transactions)
      assert first_txn.amount == 5
      assert first_txn.source == "trial_signup"
      assert first_txn.balance_after == 5

      # ACT: Deploy first fix (consume 1 credit)
      fix = %{id: 1, vulnerability_id: "VULN-001", status: "merged"}

      assert {:ok, %{customer: customer_after_fix, transaction: consume_txn}} =
               Billing.track_fix_deployed(customer, fix)

      # ASSERT: Credit consumed, balance decreased
      assert customer_after_fix.credit_balance == 4, "Should have 4 credits remaining"
      assert consume_txn.amount == -1
      assert consume_txn.source == "fix_deployed"
      assert consume_txn.balance_after == 4

      # ASSERT: Can view usage summary
      assert {:ok, summary} = Billing.get_usage_summary(customer_after_fix.id)
      assert summary.credit_balance == 4
      assert summary.subscription_type == "trial"
      assert length(summary.recent_transactions) == 2
      assert Enum.any?(summary.warnings, &String.contains?(&1, "Low credit balance"))
    end

    test "trial customer blocked when no credits and no billing" do
      # ARRANGE: Trial customer with 0 credits and no payment method
      customer =
        insert(:customer,
          subscription_type: "trial",
          credit_balance: 0,
          has_payment_method: false
        )

      # ACT: Attempt to deploy fix with no credits and no billing
      fix = %{id: 2, vulnerability_id: "VULN-002", status: "merged"}
      result = Billing.track_fix_deployed(customer, fix)

      # ASSERT: Deployment blocked with clear error message
      assert {:error, :no_billing_info} = result

      # ASSERT: No credit transaction created
      transactions = CreditLedger.list_transactions(customer)
      assert Enum.empty?(transactions), "Should not create transaction when blocked"

      # ASSERT: Usage summary shows critical warning
      assert {:ok, summary} = Billing.get_usage_summary(customer.id)
      assert summary.credit_balance == 0

      assert Enum.any?(
               summary.warnings,
               &String.contains?(&1, "No credits remaining and no payment method")
             )
    end
  end

  describe "Trial to Paid Conversion" do
    test "trial customer adds payment method and gets charged when credits exhausted" do
      # ARRANGE: Trial customer with 2 credits (no Stripe customer - will be created on payment add)
      customer = insert_with_trait(:customer, &with_trial_credits/1)
      customer = Repo.update!(Ecto.Changeset.change(customer, %{credit_balance: 2}))

      # ACT: Add payment method with billing consent
      assert {:ok, customer_with_billing} =
               Billing.add_payment_method(customer, "pm_test_123", true)

      # ASSERT: Payment method added, Stripe customer created, bonus credits granted (2 + 5 = 7)
      assert customer_with_billing.has_payment_method == true
      assert customer_with_billing.credit_balance == 7, "Should have 2 + 5 bonus credits"
      assert customer_with_billing.subscription_type == "pay_as_you_go"

      assert String.starts_with?(customer_with_billing.stripe_customer_id, "cus_test_"),
             "Should have created Stripe customer"

      # ASSERT: Billing addition credit transaction recorded
      transactions = CreditLedger.list_transactions(customer_with_billing)
      billing_txn = Enum.find(transactions, &(&1.source == "trial_billing_added"))
      assert billing_txn.amount == 5
      assert billing_txn.balance_after == 7

      # ACT: Consume all credits (7 fixes)
      customer_no_credits =
        Enum.reduce(1..7, customer_with_billing, fn i, acc_customer ->
          fix = %{id: i, vulnerability_id: "VULN-#{i}", status: "merged"}
          {:ok, %{customer: updated_customer}} = Billing.track_fix_deployed(acc_customer, fix)
          updated_customer
        end)

      # ASSERT: All credits consumed
      customer_no_credits = Repo.reload!(customer_no_credits)
      assert customer_no_credits.credit_balance == 0

      # ACT: Deploy fix when out of credits (should charge $29)
      fix_after_credits = %{id: 8, vulnerability_id: "VULN-008", status: "merged"}

      assert {:ok, :charged_and_consumed} =
               Billing.track_fix_deployed(customer_no_credits, fix_after_credits)

      # ASSERT: Customer charged, credit added and immediately consumed (balance stays 0)
      customer_after_charge = Repo.reload!(customer_no_credits)
      assert customer_after_charge.credit_balance == 0

      # ASSERT: Charge and consume transactions recorded
      all_transactions = CreditLedger.list_transactions(customer_after_charge)
      charge_txn = Enum.find(all_transactions, &(&1.source == "purchased"))
      assert charge_txn.amount == 1, "Should credit 1 fix"
      assert charge_txn.metadata["amount_cents"] == 2900, "Should charge $29 at PAYG rate"

      consume_txn =
        Enum.find(all_transactions, &(&1.source == "fix_deployed" and &1.amount == -1))

      assert consume_txn != nil, "Should consume the credited fix"
    end
  end

  describe "Marketplace Installation Flow" do
    test "customer installs from GitHub Marketplace and completes onboarding" do
      # ARRANGE: Customer signup from GitHub Marketplace
      marketplace_params = %{
        email: "marketplace-#{System.unique_integer([:positive])}@test.rsolv.dev",
        name: "Marketplace Customer",
        source: "gh_marketplace"
      }

      # ACT: Provision customer (marketplace signup flow)
      assert {:ok, %{customer: customer, api_key: api_key}} =
               CustomerOnboarding.provision_customer(marketplace_params)

      # ASSERT: Customer created with marketplace source tracked
      assert customer.email == marketplace_params.email
      assert customer.subscription_type == "trial"
      assert customer.credit_balance == 5

      # ASSERT: Metadata tracks marketplace source
      transactions = CreditLedger.list_transactions(customer)
      first_txn = hd(transactions)
      assert first_txn.metadata["source"] == "gh_marketplace"

      # ASSERT: API key delivered for GitHub Actions integration
      assert String.starts_with?(api_key, "rsolv_")
    end
  end

  describe "Payment Method Addition" do
    test "customer adds payment method with explicit billing consent" do
      # ARRANGE: Trial customer
      customer = insert_with_trait(:customer, &with_trial_credits/1)

      # ACT: Add payment method with consent = true
      assert {:ok, customer_with_billing} =
               Billing.add_payment_method(customer, "pm_test_consent", true)

      # ASSERT: Payment method added successfully
      assert customer_with_billing.has_payment_method == true
      assert customer_with_billing.billing_consent_given == true
      assert customer_with_billing.credit_balance == 10, "Should have 5 + 5 bonus credits"
    end

    test "payment addition without consent is rejected" do
      # ARRANGE: Trial customer
      customer = insert_with_trait(:customer, &with_trial_credits/1)

      # ACT: Attempt to add payment method without consent
      result = Billing.add_payment_method(customer, "pm_test_no_consent", false)

      # ASSERT: Payment addition rejected
      assert {:error, :billing_consent_required} = result

      # ASSERT: Customer state unchanged
      customer_unchanged = Repo.reload!(customer)
      assert customer_unchanged.has_payment_method == false
      assert customer_unchanged.credit_balance == 5, "Credits should remain unchanged"
    end
  end

  describe "Pro Subscription Creation and Renewal" do
    test "customer subscribes to Pro plan and receives credits on payment" do
      # ARRANGE: Customer with billing added (10 credits)
      customer = insert_with_trait(:customer, &with_billing_added/1)

      # ACT: Subscribe to Pro plan
      assert {:ok, pro_customer} = Billing.subscribe_to_pro(customer)

      # ASSERT: Subscription created, customer upgraded
      assert pro_customer.subscription_type == "pro"
      assert pro_customer.subscription_state == "active"
      assert String.starts_with?(pro_customer.stripe_subscription_id, "sub_test_")

      # Simulate webhook: invoice.payment_succeeded (grants 60 credits)
      # This would normally come from Stripe webhook processor
      assert {:ok, %{customer: customer_with_credits}} =
               CreditLedger.credit(pro_customer, 60, "pro_subscription_payment", %{
                 "subscription_id" => pro_customer.stripe_subscription_id
               })

      # ASSERT: Pro credits added (10 existing + 60 Pro = 70 total)
      assert customer_with_credits.credit_balance == 70

      # ASSERT: Usage summary shows Pro plan details
      assert {:ok, summary} = Billing.get_usage_summary(customer_with_credits.id)
      assert summary.subscription_type == "pro"
      assert summary.subscription_state == "active"
      assert summary.credit_balance == 70
    end

    test "Pro subscription renewal grants another 60 credits" do
      # ARRANGE: Pro customer with 10 credits remaining from previous month
      customer = insert_with_trait(:customer, &with_pro_plan/1)
      customer = Repo.update!(Ecto.Changeset.change(customer, %{credit_balance: 10}))

      # Simulate webhook: invoice.payment_succeeded (renewal)
      assert {:ok, %{customer: renewed_customer}} =
               CreditLedger.credit(customer, 60, "pro_subscription_payment", %{
                 "subscription_id" => customer.stripe_subscription_id,
                 "renewal" => true
               })

      # ASSERT: Credits refreshed (10 existing + 60 renewal = 70 total)
      assert renewed_customer.credit_balance == 70

      # ASSERT: Transaction recorded
      transactions = CreditLedger.list_transactions(renewed_customer)
      renewal_txn = Enum.find(transactions, &(&1.source == "pro_subscription_payment"))
      assert renewal_txn.amount == 60
      assert renewal_txn.metadata["renewal"] == true
    end

    test "Pro customer charges $15 for additional fixes beyond credits" do
      # ARRANGE: Pro customer with 0 credits
      customer = insert_with_trait(:customer, &with_pro_plan/1)
      customer = Repo.update!(Ecto.Changeset.change(customer, %{credit_balance: 0}))

      # ACT: Deploy fix when out of credits (should charge $15)
      fix = %{id: 1, vulnerability_id: "VULN-PRO-001", status: "merged"}

      assert {:ok, :charged_and_consumed} = Billing.track_fix_deployed(customer, fix)

      # ASSERT: Customer charged at Pro rate ($15), credit added and consumed
      customer_after_charge = Repo.reload!(customer)
      assert customer_after_charge.credit_balance == 0

      # ASSERT: Charge transaction recorded at Pro rate
      transactions = CreditLedger.list_transactions(customer_after_charge)
      charge_txn = Enum.find(transactions, &(&1.source == "purchased"))
      assert charge_txn.amount == 1
      assert charge_txn.metadata["amount_cents"] == 1500
    end
  end

  describe "Subscription Cancellation" do
    test "immediate cancellation downgrades to PAYG and changes rate to $29" do
      # ARRANGE: Pro customer with 45 credits remaining
      customer = insert_with_trait(:customer, &with_pro_plan/1)
      customer = Repo.update!(Ecto.Changeset.change(customer, %{credit_balance: 45}))

      # ACT: Cancel subscription immediately (at_period_end = false)
      assert {:ok, downgraded_customer} = Billing.cancel_subscription(customer, false)

      # ASSERT: Customer downgraded to PAYG, credits preserved
      assert downgraded_customer.subscription_type == "pay_as_you_go"
      assert downgraded_customer.subscription_state == "canceled"
      assert downgraded_customer.credit_balance == 45, "Credits should be preserved"

      # ARRANGE: Consume all remaining credits
      customer_no_credits =
        Enum.reduce(1..45, downgraded_customer, fn i, acc_customer ->
          fix = %{id: i, vulnerability_id: "VULN-CANCEL-#{i}", status: "merged"}
          {:ok, %{customer: updated_customer}} = Billing.track_fix_deployed(acc_customer, fix)
          updated_customer
        end)

      # ASSERT: All credits consumed
      customer_no_credits = Repo.reload!(customer_no_credits)
      assert customer_no_credits.credit_balance == 0

      # ACT: Deploy fix after cancellation (should charge at PAYG rate)
      fix_after_cancel = %{id: 46, vulnerability_id: "VULN-AFTER-CANCEL", status: "merged"}

      assert {:ok, :charged_and_consumed} =
               Billing.track_fix_deployed(customer_no_credits, fix_after_cancel)

      # ASSERT: Charged at PAYG rate ($29)
      customer_after_payg_charge = Repo.reload!(customer_no_credits)
      payg_transactions = CreditLedger.list_transactions(customer_after_payg_charge)
      payg_charge = Enum.find(payg_transactions, &(&1.source == "purchased"))
      assert payg_charge.metadata["amount_cents"] == 2900, "Should charge $29 at PAYG rate"
    end

    test "end-of-period cancellation maintains Pro pricing until period ends" do
      # ARRANGE: Pro customer with 45 credits remaining
      customer = insert_with_trait(:customer, &with_pro_plan/1)
      customer = Repo.update!(Ecto.Changeset.change(customer, %{credit_balance: 45}))

      # ACT: Schedule cancellation at period end
      assert {:ok, scheduled_cancel_customer} = Billing.cancel_subscription(customer, true)

      # ASSERT: Customer still Pro, cancellation scheduled
      assert scheduled_cancel_customer.subscription_type == "pro"
      assert scheduled_cancel_customer.subscription_state == "active"
      assert scheduled_cancel_customer.subscription_cancel_at_period_end == true

      # ARRANGE: Consume all remaining credits
      customer_no_credits =
        Enum.reduce(1..45, scheduled_cancel_customer, fn i, acc_customer ->
          fix = %{id: i, vulnerability_id: "VULN-SCHED-#{i}", status: "merged"}
          {:ok, %{customer: updated_customer}} = Billing.track_fix_deployed(acc_customer, fix)
          updated_customer
        end)

      # ASSERT: All credits consumed
      customer_no_credits = Repo.reload!(customer_no_credits)
      assert customer_no_credits.credit_balance == 0

      # ACT: Deploy fix after scheduled cancellation (should still charge at Pro rate)
      fix_during_grace = %{id: 46, vulnerability_id: "VULN-GRACE-PERIOD", status: "merged"}

      assert {:ok, :charged_and_consumed} =
               Billing.track_fix_deployed(customer_no_credits, fix_during_grace)

      # ASSERT: Charged at Pro rate ($15) even though cancellation scheduled
      customer_after_grace_charge = Repo.reload!(customer_no_credits)
      grace_transactions = CreditLedger.list_transactions(customer_after_grace_charge)
      grace_charge = Enum.find(grace_transactions, &(&1.source == "purchased"))

      assert grace_charge.metadata["amount_cents"] == 1500,
             "Should charge $15 (Pro rate) until period ends"
    end
  end
end
