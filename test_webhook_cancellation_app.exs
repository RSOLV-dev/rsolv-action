# Test script for webhook subscription cancellation scenario
# This version ensures the application is properly started

# Start application
Application.ensure_all_started(:rsolv)

alias Rsolv.Repo
alias Rsolv.Customers
alias Rsolv.Customers.Customer
alias Rsolv.Billing.{WebhookProcessor, CreditLedger, BillingEvent}
import Ecto.Query

IO.puts("\n=== Webhook Subscription Cancellation Test ===\n")

# Step 1: Create test customer with Pro subscription
IO.puts("Step 1: Creating test customer with Pro subscription...")

stripe_customer_id = "cus_test_webhook_cancel_#{:rand.uniform(99999)}"
stripe_subscription_id = "sub_test_webhook_cancel_#{:rand.uniform(99999)}"

{:ok, customer} =
  Customers.register_customer(%{
    name: "Webhook Cancel Test Customer",
    email: "webhook-cancel-test-#{:rand.uniform(99999)}@example.com",
    password: "TestP@ssw0rd2025!",
    subscription_type: "pro",
    subscription_state: "active",
    stripe_customer_id: stripe_customer_id,
    stripe_subscription_id: stripe_subscription_id,
    metadata: %{
      "type" => "test",
      "purpose" => "webhook_cancellation_test"
    }
  })

IO.puts("  ✓ Customer created: #{customer.email}")
IO.puts("    ID: #{customer.id}")
IO.puts("    Stripe Customer ID: #{customer.stripe_customer_id}")
IO.puts("    Stripe Subscription ID: #{customer.stripe_subscription_id}")
IO.puts("    Subscription Type: #{customer.subscription_type}")
IO.puts("    Subscription State: #{customer.subscription_state}")

# Step 2: Add credit balance
IO.puts("\nStep 2: Adding credit balance...")

initial_credits = 1000

{:ok, _ledger_entry} =
  CreditLedger.credit(customer, initial_credits, "manual_test_credit", %{
    note: "Initial credits for cancellation test"
  })

# Refresh customer to get updated balance
customer = Repo.get!(Customer, customer.id)
IO.puts("  ✓ Credits added: #{initial_credits}")
IO.puts("    Current balance: #{customer.credit_balance}")

# Step 3: Trigger subscription cancellation webhook
IO.puts("\nStep 3: Triggering subscription cancellation webhook...")

webhook_event = %{
  "stripe_event_id" => "evt_test_webhook_cancel_#{:rand.uniform(99999)}",
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

{:ok, status} = WebhookProcessor.process_event(webhook_event)
IO.puts("  ✓ Webhook processed: #{status}")

# Step 4: Verify customer downgraded to PAYG
IO.puts("\nStep 4: Verifying customer downgraded to PAYG...")

customer = Repo.get!(Customer, customer.id)

checks = [
  {"Subscription type", customer.subscription_type == "pay_as_you_go", customer.subscription_type},
  {"Subscription state", is_nil(customer.subscription_state), customer.subscription_state},
  {"Stripe subscription ID", is_nil(customer.stripe_subscription_id),
   customer.stripe_subscription_id},
  {"Cancel at period end", customer.subscription_cancel_at_period_end == false,
   customer.subscription_cancel_at_period_end}
]

all_passed = Enum.all?(checks, fn {_, passed, _} -> passed end)

Enum.each(checks, fn {name, passed, value} ->
  status = if passed, do: "✓", else: "✗"
  IO.puts("  #{status} #{name}: #{inspect(value)}")
end)

# Step 5: Verify credits preserved
IO.puts("\nStep 5: Verifying credits preserved...")

balance = CreditLedger.get_balance(customer)
credits_preserved = balance == initial_credits

IO.puts("  Initial credits: #{initial_credits}")
IO.puts("  Current balance: #{balance}")
IO.puts("  #{if credits_preserved, do: "✓", else: "✗"} Credits preserved: #{credits_preserved}")

# Step 6: Check billing event recorded
IO.puts("\nStep 6: Checking billing event recorded...")

billing_event =
  BillingEvent
  |> where([e], e.stripe_event_id == ^webhook_event["stripe_event_id"])
  |> Repo.one()

if billing_event do
  IO.puts("  ✓ Billing event recorded:")
  IO.puts("    Event type: #{billing_event.event_type}")
  IO.puts("    Customer ID: #{billing_event.customer_id}")
  IO.puts("    Inserted at: #{billing_event.inserted_at}")
else
  IO.puts("  ✗ Billing event NOT found")
end

# Step 7: Verify transaction history
IO.puts("\nStep 7: Checking transaction history...")

transactions = CreditLedger.list_transactions(customer)
IO.puts("  Total transactions: #{length(transactions)}")

Enum.each(transactions, fn txn ->
  IO.puts("    - #{txn.transaction_type}: #{txn.amount} credits (#{txn.inserted_at})")
end)

# Summary
IO.puts("\n=== Test Summary ===")
IO.puts("Customer ID: #{customer.id}")
IO.puts("Email: #{customer.email}")
IO.puts("Subscription Type: #{customer.subscription_type}")
IO.puts("Credit Balance: #{customer.credit_balance}")

test_passed = all_passed and credits_preserved and not is_nil(billing_event)
IO.puts("All checks passed: #{test_passed}")

if test_passed do
  IO.puts("\n✅ TEST PASSED - Subscription cancellation works correctly!")
  IO.puts("   - Customer downgraded to PAYG")
  IO.puts("   - Credits preserved (#{initial_credits} credits)")
  IO.puts("   - Billing event recorded")
else
  IO.puts("\n❌ TEST FAILED - Some checks did not pass")
  System.halt(1)
end

IO.puts("\n=== Cleanup Instructions ===")
IO.puts("To manually inspect the test customer:")
IO.puts("  iex> customer = Rsolv.Repo.get!(Rsolv.Customers.Customer, #{customer.id})")
IO.puts("  iex> Rsolv.Billing.CreditLedger.list_transactions(customer)")
IO.puts("\nTo delete the test customer:")
IO.puts("  iex> Rsolv.Repo.delete(Rsolv.Repo.get!(Rsolv.Customers.Customer, #{customer.id}))")

# Cleanup test customer automatically
IO.puts("\nCleaning up test customer...")
Repo.delete(customer)
IO.puts("  ✓ Test customer deleted")

# Exit successfully
System.halt(0)
