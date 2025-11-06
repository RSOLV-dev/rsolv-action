defmodule Rsolv.Billing.WebhookCancellationTest do
  use Rsolv.DataCase, async: false

  alias Rsolv.Customers
  alias Rsolv.Customers.Customer
  alias Rsolv.Billing.{WebhookProcessor, CreditLedger, BillingEvent}
  alias Rsolv.Repo

  import Ecto.Query

  describe "customer.subscription.deleted webhook" do
    setup do
      # Create test customer with Pro subscription
      stripe_customer_id =
        "cus_test_cancel_#{System.system_time(:second)}_#{:rand.uniform(99999)}"

      stripe_subscription_id =
        "sub_test_cancel_#{System.system_time(:second)}_#{:rand.uniform(99999)}"

      {:ok, customer} =
        Customers.register_customer(%{
          name: "Webhook Cancel Test",
          email: "cancel-test-#{System.system_time(:second)}-#{:rand.uniform(99999)}@example.com",
          password: "TestP@ssw0rd2025!",
          subscription_type: "pro",
          subscription_state: "active",
          stripe_customer_id: stripe_customer_id,
          stripe_subscription_id: stripe_subscription_id,
          metadata: %{"type" => "test", "purpose" => "webhook_cancellation_test"}
        })

      # Add credits (using "adjustment" as a valid source)
      {:ok, _} = CreditLedger.credit(customer, 1000, "adjustment", %{note: "test credits"})
      customer = Repo.get!(Customer, customer.id)

      %{
        customer: customer,
        stripe_customer_id: stripe_customer_id,
        stripe_subscription_id: stripe_subscription_id,
        initial_credits: 1000
      }
    end

    test "downgrades customer to PAYG while preserving credits", %{
      customer: customer,
      stripe_customer_id: stripe_customer_id,
      stripe_subscription_id: stripe_subscription_id,
      initial_credits: initial_credits
    } do
      IO.puts("\n=== Testing webhook subscription cancellation ===\n")
      IO.puts("Customer ID: #{customer.id}")
      IO.puts("Email: #{customer.email}")
      IO.puts("Initial state:")
      IO.puts("  Subscription type: #{customer.subscription_type}")
      IO.puts("  Subscription state: #{customer.subscription_state}")
      IO.puts("  Credit balance: #{customer.credit_balance}")

      # Trigger cancellation webhook
      webhook_event = %{
        "stripe_event_id" => "evt_test_#{System.system_time(:second)}_#{:rand.uniform(99999)}",
        "event_type" => "customer.subscription.deleted",
        "event_data" => %{
          "object" => %{
            "id" => stripe_subscription_id,
            "customer" => stripe_customer_id,
            "status" => "canceled",
            "cancel_at_period_end" => false,
            "canceled_at" => System.system_time(:second)
          }
        }
      }

      IO.puts("\nProcessing webhook...")
      {:ok, status} = WebhookProcessor.process_event(webhook_event)
      assert status == :processed

      # Refresh customer
      customer = Repo.get!(Customer, customer.id)

      IO.puts("\nAfter webhook processing:")
      IO.puts("  Subscription type: #{customer.subscription_type}")
      IO.puts("  Subscription state: #{inspect(customer.subscription_state)}")
      IO.puts("  Stripe subscription ID: #{inspect(customer.stripe_subscription_id)}")
      IO.puts("  Credit balance: #{customer.credit_balance}")

      # Verify customer downgraded to PAYG
      assert customer.subscription_type == "pay_as_you_go",
             "Customer should be downgraded to pay_as_you_go"

      assert is_nil(customer.subscription_state), "Subscription state should be nil"
      assert is_nil(customer.stripe_subscription_id), "Stripe subscription ID should be nil"

      assert customer.subscription_cancel_at_period_end == false,
             "Cancel at period end should be false"

      # Verify credits preserved
      balance = CreditLedger.get_balance(customer)

      assert balance == initial_credits,
             "Credits should be preserved (expected #{initial_credits}, got #{balance})"

      IO.puts("\n✓ Credits preserved: #{balance}/#{initial_credits}")

      # Verify billing event recorded
      billing_event =
        BillingEvent
        |> where([e], e.stripe_event_id == ^webhook_event["stripe_event_id"])
        |> Repo.one()

      assert not is_nil(billing_event), "Billing event should be recorded"
      assert billing_event.event_type == "customer.subscription.deleted"
      assert billing_event.customer_id == customer.id

      IO.puts("✓ Billing event recorded (ID: #{billing_event.id})")

      # Verify transaction history
      transactions = CreditLedger.list_transactions(customer)
      assert length(transactions) == 1, "Should have exactly 1 credit transaction"
      assert hd(transactions).amount == initial_credits

      IO.puts("✓ Transaction history correct (#{length(transactions)} transactions)")

      IO.puts("\n=== ✅ ALL CHECKS PASSED ===")
      IO.puts("Customer downgraded to PAYG with #{balance} credits preserved")
    end

    test "is idempotent - processing same webhook twice doesn't double-process", %{
      customer: customer,
      stripe_customer_id: stripe_customer_id,
      stripe_subscription_id: stripe_subscription_id,
      initial_credits: initial_credits
    } do
      webhook_event = %{
        "stripe_event_id" =>
          "evt_idempotent_#{System.system_time(:second)}_#{:rand.uniform(99999)}",
        "event_type" => "customer.subscription.deleted",
        "event_data" => %{
          "object" => %{
            "id" => stripe_subscription_id,
            "customer" => stripe_customer_id,
            "status" => "canceled"
          }
        }
      }

      # Process once
      {:ok, status1} = WebhookProcessor.process_event(webhook_event)
      assert status1 == :processed

      # Process again with same event ID
      {:ok, status2} = WebhookProcessor.process_event(webhook_event)
      assert status2 == :duplicate

      # Verify credits still correct (not double-processed)
      customer = Repo.get!(Customer, customer.id)
      balance = CreditLedger.get_balance(customer)

      assert balance == initial_credits,
             "Credits should still be #{initial_credits} after duplicate webhook"
    end
  end
end
