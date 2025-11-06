# Test webhook subscription cancellation in IEx
# Copy and paste this entire file into IEx

alias Rsolv.Repo
alias Rsolv.Customers
alias Rsolv.Customers.Customer
alias Rsolv.Billing.{WebhookProcessor, CreditLedger, BillingEvent}
import Ecto.Query

IO.puts("\n=== Webhook Subscription Cancellation Test ===\n")

# Step 1: Create test customer
IO.puts("Step 1: Creating test customer with Pro subscription...")
stripe_customer_id = "cus_test_cancel_#{System.system_time(:second)}"
stripe_subscription_id = "sub_test_cancel_#{System.system_time(:second)}"

{:ok, customer} = Customers.register_customer(%{
  name: "Webhook Cancel Test",
  email: "cancel-test-#{System.system_time(:second)}@example.com",
  password: "TestP@ssw0rd2025!",
  subscription_type: "pro",
  subscription_state: "active",
  stripe_customer_id: stripe_customer_id,
  stripe_subscription_id: stripe_subscription_id,
  metadata: %{"type" => "test"}
})

IO.puts("  ✓ Customer ID: #{customer.id}")
IO.puts("    Email: #{customer.email}")
IO.puts("    Subscription: #{customer.subscription_type} (#{customer.subscription_state})")

# Step 2: Add credits
IO.puts("\nStep 2: Adding credits...")
{:ok, _} = CreditLedger.credit(customer, 1000, "test_credit", %{})
customer = Repo.get!(Customer, customer.id)
IO.puts("  ✓ Credits added: #{customer.credit_balance}")

# Step 3: Trigger webhook
IO.puts("\nStep 3: Processing cancellation webhook...")
webhook = %{
  "stripe_event_id" => "evt_test_#{System.system_time(:second)}",
  "event_type" => "customer.subscription.deleted",
  "event_data" => %{
    "object" => %{
      "id" => stripe_subscription_id,
      "customer" => stripe_customer_id,
      "status" => "canceled"
    }
  }
}

{:ok, status} = WebhookProcessor.process_event(webhook)
IO.puts("  ✓ Webhook status: #{status}")

# Step 4: Verify results
IO.puts("\nStep 4: Verifying results...")
customer = Repo.get!(Customer, customer.id)

IO.puts("  Subscription type: #{customer.subscription_type}")
IO.puts("  Subscription state: #{inspect(customer.subscription_state)}")
IO.puts("  Stripe subscription ID: #{inspect(customer.stripe_subscription_id)}")
IO.puts("  Credit balance: #{customer.credit_balance}")

# Check billing event
event = BillingEvent |> where([e], e.stripe_event_id == ^webhook["stripe_event_id"]) |> Repo.one()
IO.puts("  Billing event recorded: #{not is_nil(event)}")

# Summary
passed = customer.subscription_type == "pay_as_you_go" and
         is_nil(customer.subscription_state) and
         is_nil(customer.stripe_subscription_id) and
         customer.credit_balance == 1000 and
         not is_nil(event)

IO.puts("\n=== Result: #{if passed, do: "✅ PASS", else: "❌ FAIL"} ===")
IO.puts("Customer ID: #{customer.id} (for cleanup)")

# Store customer_id for cleanup
customer_id = customer.id
