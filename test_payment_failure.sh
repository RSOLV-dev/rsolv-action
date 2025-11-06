#!/bin/bash
# Test script for payment failure webhook
# Run with: ./test_payment_failure.sh

echo "=== Payment Failure Webhook Test ==="
echo ""
echo "Starting IEx session to run test commands..."
echo ""

iex -S mix <<'EOF'

# Import required modules
alias Rsolv.Repo
alias Rsolv.Customers
alias Rsolv.Billing.WebhookProcessor
alias Rsolv.Billing.BillingEvent
import Ecto.Query

IO.puts "\n=== Step 1: Create test customer with Pro subscription ===\n"

{:ok, customer} =
  Customers.register_customer(%{
    name: "Payment Test Customer",
    email: "payment.test@example.com",
    password: "PaymentTest2025!",
    subscription_type: "pro",
    subscription_state: "active",
    stripe_customer_id: "cus_test_pay_fail_#{:rand.uniform(99999)}",
    stripe_subscription_id: "sub_test_pay_fail_#{:rand.uniform(99999)}",
    metadata: %{"type" => "test", "purpose" => "payment_failure_test"}
  })

IO.puts "✓ Customer created: #{customer.email}"
IO.puts "✓ Stripe Customer ID: #{customer.stripe_customer_id}"
IO.puts "✓ Initial state: #{customer.subscription_state}"

IO.puts "\n=== Step 2: Simulate payment failure webhook ===\n"

stripe_event_id = "evt_test_#{:rand.uniform(99999999)}"
stripe_invoice_id = "in_test_#{:rand.uniform(99999)}"

webhook_payload = %{
  "stripe_event_id" => stripe_event_id,
  "event_type" => "invoice.payment_failed",
  "event_data" => %{
    "object" => %{
      "id" => stripe_invoice_id,
      "customer" => customer.stripe_customer_id,
      "amount_due" => 2900,
      "amount_paid" => 0,
      "attempt_count" => 1,
      "next_payment_attempt" => DateTime.utc_now() |> DateTime.add(23 * 3600, :second) |> DateTime.to_unix(),
      "status" => "open",
      "billing_reason" => "subscription_cycle"
    }
  }
}

result = WebhookProcessor.process_event(webhook_payload)
IO.puts "✓ Webhook processed: #{inspect(result)}"

IO.puts "\n=== Step 3: Verify customer state ===\n"

updated = Repo.reload!(customer)
IO.puts "✓ New subscription_state: #{updated.subscription_state}"

if updated.subscription_state == "past_due" do
  IO.puts "✅ PASS: Customer state updated correctly"
else
  IO.puts "❌ FAIL: Expected 'past_due', got '#{updated.subscription_state}'"
end

IO.puts "\n=== Step 4: Check email job ===\n"

email_job = from(j in Oban.Job,
  where: j.worker == "Rsolv.Workers.EmailWorker",
  where: fragment("?->>'type' = ?", j.args, "payment_failed"),
  where: fragment("?->>'customer_id' = ?", j.args, ^to_string(customer.id)),
  order_by: [desc: j.inserted_at],
  limit: 1
) |> Repo.one()

if email_job do
  IO.puts "✅ PASS: Email job created"
  IO.puts "  Job ID: #{email_job.id}"
  IO.puts "  Queue: #{email_job.queue}"
  IO.puts "  State: #{email_job.state}"
  IO.puts "  Type: #{email_job.args["type"]}"
  IO.puts "  Invoice: #{email_job.args["invoice_id"]}"
  IO.puts "  Amount: $#{email_job.args["amount_due"] / 100}"
else
  IO.puts "❌ FAIL: No email job found"
end

IO.puts "\n=== Step 5: Check billing event ===\n"

billing_event = BillingEvent
  |> where([e], e.event_type == "invoice.payment_failed")
  |> where([e], e.stripe_event_id == ^stripe_event_id)
  |> Repo.one()

if billing_event do
  IO.puts "✅ PASS: Billing event created"
  IO.puts "  Event ID: #{billing_event.id}"
  IO.puts "  Type: #{billing_event.event_type}"
  IO.puts "  Customer: #{billing_event.customer_id}"
  IO.puts "  Amount: $#{billing_event.amount_cents / 100}"
else
  IO.puts "❌ FAIL: No billing event found"
end

IO.puts "\n=== Step 6: Test idempotency ===\n"

dup_result = WebhookProcessor.process_event(webhook_payload)
IO.puts "✓ Duplicate webhook result: #{inspect(dup_result)}"

if dup_result == {:ok, :duplicate} do
  IO.puts "✅ PASS: Duplicate correctly detected"
else
  IO.puts "❌ FAIL: Idempotency check failed"
end

IO.puts "\n=== Test Complete ===\n"
IO.puts "Test customer: #{customer.email} (ID: #{customer.id})"
IO.puts "\nTo send the dunning email, run:"
IO.puts "  Oban.drain_queue(queue: :emails)"

EOF
