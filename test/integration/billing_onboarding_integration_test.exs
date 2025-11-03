defmodule Rsolv.BillingOnboardingIntegrationTest do
  @moduledoc """
  Integration tests for RFC-069 Week 4 Monday validation.

  Tests complete data flows across provisioning, billing, and webhook processing
  to ensure all systems integrate correctly.

  These tests use mocked Stripe API calls (Mox) but exercise real code paths
  through CustomerOnboarding, Billing, CreditLedger, and WebhookProcessor.
  """
  use Rsolv.DataCase, async: false

  alias Rsolv.CustomerOnboarding
  alias Rsolv.Billing
  alias Rsolv.Billing.{CreditLedger, WebhookProcessor}
  alias Rsolv.Customers

  import Mox

  setup :verify_on_exit!

  setup do
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

  describe "RFC-069: Onboarding → Stripe → Initial Credits Flow" do
    test "signup creates customer and API key with Stripe customer and initial credits" do
      # Mock Stripe customer creation
      expect(Rsolv.Billing.StripeMock, :create, fn params ->
        assert params.email =~ "@testcompany.com"
        assert params.name == "Integration Test Customer"

        {:ok,
         %{
           id: "cus_test_#{System.unique_integer([:positive])}",
           email: params.email,
           name: params.name
         }}
      end)

      # Provision customer (simulates signup flow)
      attrs = %{
        "name" => "Integration Test Customer",
        "email" => "integration_test_#{System.unique_integer([:positive])}@testcompany.com",
        "source" => "direct"
      }

      assert {:ok, %{customer: customer, api_key: api_key}} =
               CustomerOnboarding.provision_customer(attrs)

      # Verify customer created
      assert customer.name == "Integration Test Customer"
      assert customer.email == attrs["email"]

      # Verify Stripe customer ID set
      assert customer.stripe_customer_id =~ "cus_test_"

      # Verify 5 initial credits allocated
      assert customer.credit_balance == 5

      # Verify credit transaction
      transactions = CreditLedger.list_transactions(customer)
      assert length(transactions) == 1
      signup_credit = hd(transactions)
      assert signup_credit.amount == 5
      assert signup_credit.source == "trial_signup"
      assert signup_credit.metadata["source"] == "direct"

      # Verify API key generated
      assert is_binary(api_key)
      assert String.starts_with?(api_key, "rsolv_")
    end

    test "marketplace signup creates customer with Stripe and initial credits" do
      # Mock Stripe customer creation
      expect(Rsolv.Billing.StripeMock, :create, fn params ->
        assert params.email =~ "@testcompany.com"
        assert params.name == "Marketplace Customer"

        {:ok,
         %{
           id: "cus_marketplace_#{System.unique_integer([:positive])}",
           email: params.email,
           name: params.name
         }}
      end)

      attrs = %{
        "name" => "Marketplace Customer",
        "email" => "marketplace_#{System.unique_integer([:positive])}@testcompany.com",
        "source" => "gh_marketplace"
      }

      assert {:ok, %{customer: customer}} = CustomerOnboarding.provision_customer(attrs)

      # Verify basic customer creation works
      assert customer.name == "Marketplace Customer"

      # Verify 5 initial credits allocated
      assert customer.credit_balance == 5

      # Verify source recorded in transaction metadata
      transactions = CreditLedger.list_transactions(customer)
      signup_credit = hd(transactions)
      assert signup_credit.metadata["source"] == "gh_marketplace"
    end
  end

  describe "RFC-069: Payment Method → Credit Top-up Flow" do
    test "adding payment method grants +5 credits when first payment method added" do
      # Create customer with initial credits
      customer = insert(:customer, credit_balance: 5, stripe_customer_id: "cus_test_123")

      # Mock Stripe payment method attachment
      expect(Rsolv.Billing.StripePaymentMethodMock, :attach, fn params ->
        assert params.payment_method == "pm_test_card"
        assert params.customer == "cus_test_123"

        {:ok,
         %{
           id: "pm_test_card",
           customer: "cus_test_123",
           type: "card"
         }}
      end)

      # Mock Stripe customer update
      expect(Rsolv.Billing.StripeMock, :update, fn customer_id, params ->
        assert customer_id == "cus_test_123"
        assert params[:invoice_settings][:default_payment_method] == "pm_test_card"

        {:ok,
         %{
           id: "cus_test_123",
           invoice_settings: %{default_payment_method: "pm_test_card"}
         }}
      end)

      # Add payment method (simulates billing consent flow with consent=true)
      assert {:ok, updated_customer} =
               Billing.add_payment_method(customer, "pm_test_card", true)

      # Verify +5 credits granted
      assert updated_customer.credit_balance == 10
      assert updated_customer.has_payment_method == true
      assert updated_customer.stripe_payment_method_id == "pm_test_card"

      # Verify credit transaction
      transactions = CreditLedger.list_transactions(updated_customer)
      assert length(transactions) == 1

      payment_credit = hd(transactions)
      assert payment_credit.amount == 5
      assert payment_credit.source == "trial_billing_added"
    end

    test "payment method without billing consent returns error" do
      customer = insert(:customer, credit_balance: 5, stripe_customer_id: "cus_test_456")

      # Add payment method without billing consent (should error)
      assert {:error, :billing_consent_required} =
               Billing.add_payment_method(customer, "pm_test_card", false)

      # Customer unchanged (reload to verify)
      reloaded = Customers.get_customer!(customer.id)
      assert reloaded.credit_balance == 5
      assert reloaded.has_payment_method == false

      # No new transactions
      assert CreditLedger.list_transactions(reloaded) == []
    end
  end

  describe "RFC-069: Fix Deployed → Credit Consumption Flow" do
    test "deploying fix consumes 1 credit when credits available" do
      # Create customer with credits
      customer = insert(:customer, credit_balance: 10)
      fix = %{id: "fix_integration_test_#{System.unique_integer([:positive])}"}

      # Track fix deployment
      assert {:ok, %{customer: updated_customer, transaction: transaction}} =
               Billing.track_fix_deployed(customer, fix)

      # Verify credit consumed
      assert updated_customer.credit_balance == 9
      assert transaction.amount == -1
      assert transaction.source == "fix_deployed"
      assert transaction.metadata["fix_id"] == fix.id
    end

    test "deploying fix charges PAYG rate when no credits but has payment method" do
      # Create PAYG customer with billing but no credits
      customer =
        insert(:customer,
          credit_balance: 0,
          subscription_type: "pay_as_you_go",
          stripe_customer_id: "cus_payg_test",
          stripe_payment_method_id: "pm_test_visa",
          has_payment_method: true
        )

      fix = %{id: "fix_payg_test"}

      # Mock Stripe charge
      expect(Rsolv.Billing.StripeChargeMock, :create, fn params ->
        assert params.customer == "cus_payg_test"
        # $29.00 PAYG rate
        assert params.amount == 2900
        assert params.currency == "usd"

        {:ok,
         %{
           id: "ch_payg_test",
           amount: 2900,
           currency: "usd",
           customer: "cus_payg_test",
           status: "succeeded"
         }}
      end)

      # Track fix deployment
      assert {:ok, :charged_and_consumed} = Billing.track_fix_deployed(customer, fix)

      # Verify charge-credit-consume flow
      reloaded = Customers.get_customer!(customer.id)
      # 1 added, 1 consumed
      assert reloaded.credit_balance == 0

      transactions = Billing.list_credit_transactions(customer.id)
      assert length(transactions) == 2

      # Verify purchase transaction
      purchase = Enum.find(transactions, &(&1.source == "purchased"))
      assert purchase.amount == 1
      assert purchase.metadata["amount_cents"] == 2900

      # Verify consumption transaction
      consume = Enum.find(transactions, &(&1.source == "fix_deployed"))
      assert consume.amount == -1
      assert consume.metadata["fix_id"] == fix.id
    end

    test "deploying fix charges Pro discounted rate for Pro customers" do
      # Create Pro customer with no credits
      customer =
        insert(:customer,
          credit_balance: 0,
          subscription_type: "pro",
          subscription_state: "active",
          stripe_customer_id: "cus_pro_test",
          stripe_payment_method_id: "pm_test_visa",
          stripe_subscription_id: "sub_pro_active",
          has_payment_method: true
        )

      fix = %{id: "fix_pro_test"}

      # Mock Stripe charge at Pro rate
      expect(Rsolv.Billing.StripeChargeMock, :create, fn params ->
        # $15.00 Pro additional rate
        assert params.amount == 1500
        {:ok, %{id: "ch_pro_test", amount: 1500, status: "succeeded", currency: "usd"}}
      end)

      assert {:ok, :charged_and_consumed} = Billing.track_fix_deployed(customer, fix)

      transactions = Billing.list_credit_transactions(customer.id)
      purchase = Enum.find(transactions, &(&1.source == "purchased"))
      assert purchase.metadata["amount_cents"] == 1500
    end

    test "deploying fix blocks when no credits and no billing info" do
      # Create customer with no credits and no billing
      customer =
        insert(:customer,
          credit_balance: 0,
          stripe_customer_id: nil,
          has_payment_method: false
        )

      fix = %{id: "fix_blocked_test"}

      # Should be blocked
      assert {:error, :no_billing_info} = Billing.track_fix_deployed(customer, fix)

      # No transactions created
      assert Billing.list_credit_transactions(customer.id) == []
    end
  end

  describe "RFC-069: Webhook → Credit Grant Flow" do
    test "invoice.payment_succeeded webhook grants 60 credits for Pro subscription" do
      # Create Pro customer
      customer =
        insert(:customer,
          credit_balance: 0,
          stripe_customer_id: "cus_webhook_pro",
          subscription_type: "pro",
          subscription_state: "active"
        )

      # Simulate Stripe webhook event
      event_data = %{
        "stripe_event_id" => "evt_#{System.unique_integer([:positive])}",
        "event_type" => "invoice.payment_succeeded",
        "event_data" => %{
          "object" => %{
            "id" => "in_test_123",
            "customer" => "cus_webhook_pro",
            # $599.00
            "amount_paid" => 59900,
            "lines" => %{
              "data" => [
                %{
                  "price" => %{
                    "metadata" => %{"plan" => "pro"},
                    "lookup_key" => "pro_monthly"
                  }
                }
              ]
            }
          }
        }
      }

      # Process webhook
      assert {:ok, :processed} = WebhookProcessor.process_event(event_data)

      # Verify 60 credits granted
      reloaded = Customers.get_customer!(customer.id)
      assert reloaded.credit_balance == 60

      # Verify transaction
      transactions = CreditLedger.list_transactions(reloaded)
      assert length(transactions) == 1

      credit = hd(transactions)
      assert credit.amount == 60
      assert credit.source == "pro_subscription_payment"
      assert credit.metadata["stripe_invoice_id"] == "in_test_123"
      assert credit.metadata["amount_cents"] == 59900
    end

    test "webhook idempotency prevents duplicate credit grants" do
      customer = insert(:customer, stripe_customer_id: "cus_idempotent", credit_balance: 0)

      event_data = %{
        "stripe_event_id" => "evt_duplicate_test",
        "event_type" => "invoice.payment_succeeded",
        "event_data" => %{
          "object" => %{
            "customer" => "cus_idempotent",
            "amount_paid" => 59900,
            "lines" => %{
              "data" => [%{"price" => %{"metadata" => %{"plan" => "pro"}}}]
            }
          }
        }
      }

      # Process webhook first time
      assert {:ok, :processed} = WebhookProcessor.process_event(event_data)
      reloaded = Customers.get_customer!(customer.id)
      assert reloaded.credit_balance == 60

      # Process same webhook again (duplicate)
      assert {:ok, :duplicate} = WebhookProcessor.process_event(event_data)

      # Credits unchanged
      reloaded_again = Customers.get_customer!(customer.id)
      assert reloaded_again.credit_balance == 60

      # Only one transaction
      transactions = CreditLedger.list_transactions(reloaded_again)
      assert length(transactions) == 1
    end

    test "invoice.payment_failed webhook updates subscription state to past_due" do
      customer =
        insert(:customer,
          stripe_customer_id: "cus_payment_failed",
          subscription_type: "pro",
          subscription_state: "active"
        )

      event_data = %{
        "stripe_event_id" => "evt_payment_failed_#{System.unique_integer([:positive])}",
        "event_type" => "invoice.payment_failed",
        "event_data" => %{
          "object" => %{
            "id" => "in_failed_123",
            "customer" => "cus_payment_failed",
            "amount_due" => 59900
          }
        }
      }

      assert {:ok, :processed} = WebhookProcessor.process_event(event_data)

      # Verify subscription state updated
      reloaded = Customers.get_customer!(customer.id)
      assert reloaded.subscription_state == "past_due"

      # No credits granted
      assert reloaded.credit_balance == 0
    end

    test "customer.subscription.created webhook records subscription info" do
      customer =
        insert(:customer, stripe_customer_id: "cus_new_sub", subscription_type: "pay_as_you_go")

      event_data = %{
        "stripe_event_id" => "evt_sub_created_#{System.unique_integer([:positive])}",
        "event_type" => "customer.subscription.created",
        "event_data" => %{
          "object" => %{
            "id" => "sub_new_123",
            "customer" => "cus_new_sub",
            "status" => "active"
          }
        }
      }

      assert {:ok, :processed} = WebhookProcessor.process_event(event_data)

      # Verify subscription info updated
      reloaded = Customers.get_customer!(customer.id)
      assert reloaded.stripe_subscription_id == "sub_new_123"
      assert reloaded.subscription_type == "pro"
      assert reloaded.subscription_state == "active"
    end

    test "customer.subscription.deleted webhook downgrades to PAYG" do
      customer =
        insert(:customer,
          stripe_customer_id: "cus_cancel_sub",
          subscription_type: "pro",
          subscription_state: "active",
          stripe_subscription_id: "sub_cancel_123",
          credit_balance: 25
        )

      event_data = %{
        "stripe_event_id" => "evt_sub_deleted_#{System.unique_integer([:positive])}",
        "event_type" => "customer.subscription.deleted",
        "event_data" => %{
          "object" => %{
            "id" => "sub_cancel_123",
            "customer" => "cus_cancel_sub"
          }
        }
      }

      assert {:ok, :processed} = WebhookProcessor.process_event(event_data)

      # Verify downgrade
      reloaded = Customers.get_customer!(customer.id)
      assert reloaded.subscription_type == "pay_as_you_go"
      assert reloaded.subscription_state == nil
      assert reloaded.stripe_subscription_id == nil
      assert reloaded.subscription_cancel_at_period_end == false

      # Credits preserved
      assert reloaded.credit_balance == 25
    end
  end

  describe "RFC-069: End-to-End Integration Flow" do
    test "complete customer journey: signup → add payment → deploy fix → webhook credit" do
      # Step 1: Customer signs up
      # Mock Stripe customer creation
      expect(Rsolv.Billing.StripeMock, :create, fn params ->
        {:ok,
         %{
           id: "cus_e2e_test",
           email: params.email,
           name: params.name
         }}
      end)

      attrs = %{
        "name" => "E2E Test Customer",
        "email" => "e2e_#{System.unique_integer([:positive])}@testcompany.com",
        "source" => "direct"
      }

      assert {:ok, %{customer: customer}} = CustomerOnboarding.provision_customer(attrs)

      # Verify initial credits allocated
      assert customer.credit_balance == 5
      assert customer.stripe_customer_id == "cus_e2e_test"

      # Step 2: Customer adds payment method
      expect(Rsolv.Billing.StripePaymentMethodMock, :attach, fn _params ->
        {:ok, %{id: "pm_e2e_card", customer: "cus_e2e_test"}}
      end)

      expect(Rsolv.Billing.StripeMock, :update, fn _customer_id, _params ->
        {:ok, %{id: "cus_e2e_test"}}
      end)

      assert {:ok, customer} =
               Billing.add_payment_method(customer, "pm_e2e_card", true)

      # 5 initial + 5 billing
      assert customer.credit_balance == 10

      # Step 3: Customer deploys a fix (consumes credit)
      fix = %{id: "fix_e2e_1"}
      assert {:ok, %{customer: customer}} = Billing.track_fix_deployed(customer, fix)
      # 10 - 1
      assert customer.credit_balance == 9

      # Step 4: Customer subscribes to Pro
      customer =
        customer
        |> Ecto.Changeset.change(%{
          subscription_type: "pro",
          subscription_state: "active",
          stripe_subscription_id: "sub_e2e_pro"
        })
        |> Repo.update!()

      # Step 5: Webhook processes Pro payment (grants 60 credits)
      event_data = %{
        "stripe_event_id" => "evt_e2e_#{System.unique_integer([:positive])}",
        "event_type" => "invoice.payment_succeeded",
        "event_data" => %{
          "object" => %{
            "customer" => "cus_e2e_test",
            "amount_paid" => 59900,
            "lines" => %{"data" => [%{"price" => %{"metadata" => %{"plan" => "pro"}}}]}
          }
        }
      }

      assert {:ok, :processed} = WebhookProcessor.process_event(event_data)

      # Final verification
      final_customer = Customers.get_customer!(customer.id)
      # 9 + 60
      assert final_customer.credit_balance == 69

      # Verify complete transaction history
      transactions = CreditLedger.list_transactions(final_customer)
      # trial_signup, billing, consume, pro payment
      assert length(transactions) == 4

      sources = Enum.map(transactions, & &1.source)
      assert "trial_signup" in sources
      assert "trial_billing_added" in sources
      assert "fix_deployed" in sources
      assert "pro_subscription_payment" in sources
    end
  end

  describe "RFC-069: Billing Status Checks" do
    test "has_credits? returns true when customer has credits" do
      customer = insert(:customer, credit_balance: 10)
      assert Billing.has_credits?(customer) == true
    end

    test "has_credits? returns false when no credits" do
      customer = insert(:customer, credit_balance: 0)
      assert Billing.has_credits?(customer) == false
    end

    test "has_billing_info? returns true when customer has stripe_customer_id" do
      customer =
        insert(:customer,
          credit_balance: 0,
          stripe_customer_id: "cus_test",
          has_payment_method: true
        )

      assert Billing.has_billing_info?(customer) == true
    end

    test "has_billing_info? returns false when no stripe_customer_id" do
      customer =
        insert(:customer,
          credit_balance: 0,
          stripe_customer_id: nil,
          has_payment_method: false
        )

      assert Billing.has_billing_info?(customer) == false
    end

    test "customer can use service with credits or billing info" do
      # Customer with credits can use service
      customer_with_credits = insert(:customer, credit_balance: 10)

      assert Billing.has_credits?(customer_with_credits) ||
               Billing.has_billing_info?(customer_with_credits)

      # Customer with billing info can use service
      customer_with_billing =
        insert(:customer,
          credit_balance: 0,
          stripe_customer_id: "cus_test",
          has_payment_method: true
        )

      assert Billing.has_credits?(customer_with_billing) ||
               Billing.has_billing_info?(customer_with_billing)

      # Customer with neither cannot use service
      customer_blocked =
        insert(:customer,
          credit_balance: 0,
          stripe_customer_id: nil,
          has_payment_method: false
        )

      refute Billing.has_credits?(customer_blocked) || Billing.has_billing_info?(customer_blocked)
    end

    test "get_usage_summary/1 returns complete usage information" do
      customer =
        insert(:customer,
          credit_balance: 15,
          subscription_type: "pro",
          subscription_state: "active"
        )

      # Create some transactions (reload customer to avoid stale struct)
      {:ok, %{customer: customer}} =
        CreditLedger.credit(customer, 60, "pro_subscription_payment", %{})

      {:ok, %{customer: customer}} =
        CreditLedger.consume(customer, 1, "fix_deployed", %{fix_id: "fix_123"})

      # get_usage_summary takes customer_id, not customer
      assert {:ok, summary} = Billing.get_usage_summary(customer.id)

      # Balance should be: 15 + 60 - 1 = 74
      assert summary.credit_balance == 74
      assert summary.subscription_type == "pro"
      assert summary.subscription_state == "active"
      assert summary.has_payment_method == false
      assert length(summary.recent_transactions) == 2
      # Pricing structure: %{payg: %{price_cents: ...}, pro: %{overage_price_cents: ...}}
      assert summary.pricing.payg.price_cents == 2900
      assert summary.pricing.pro.overage_price_cents == 1500
    end
  end
end
