# Test script for payment failure webhook dunning flow
#
# Run with: mix run test/support/payment_failure_test.exs
#
# This script tests RFC-066 dunning email functionality by:
# 1. Creating a test customer with Pro subscription
# 2. Simulating invoice.payment_failed webhook
# 3. Verifying customer state changes to "past_due"
# 4. Verifying EmailWorker job is queued
# 5. Verifying BillingEvent is created

alias Rsolv.Repo
alias Rsolv.Customers
alias Rsolv.Billing.WebhookProcessor
alias Rsolv.Billing.BillingEvent
import Ecto.Query

IO.puts("\n=== Payment Failure Webhook Test ===\n")

# Step 1: Create test customer with Pro subscription
IO.puts("1. Creating test customer with Pro subscription...")

{:ok, test_customer} =
  Customers.register_customer(%{
    name: "Payment Test Customer",
    email: "payment.test@example.com",
    password: "PaymentTest2025!",
    subscription_type: "pro",
    subscription_state: "active",
    stripe_customer_id: "cus_test_payment_failure_#{:rand.uniform(99999)}",
    stripe_subscription_id: "sub_test_payment_failure_#{:rand.uniform(99999)}",
    metadata: %{
      "type" => "test",
      "purpose" => "payment_failure_testing"
    }
  })

IO.puts("   ✓ Customer created: #{test_customer.email}")
IO.puts("   ✓ Stripe Customer ID: #{test_customer.stripe_customer_id}")
IO.puts("   ✓ Subscription State: #{test_customer.subscription_state}")
IO.puts("   ✓ Subscription Type: #{test_customer.subscription_type}")

# Step 2: Record counts before webhook
IO.puts("\n2. Recording baseline counts...")

email_jobs_before =
  from(j in Oban.Job,
    where: j.worker == "Rsolv.Workers.EmailWorker",
    where: fragment("?->>'type' = ?", j.args, "payment_failed")
  )
  |> Repo.aggregate(:count)

billing_events_before =
  BillingEvent
  |> where([e], e.event_type == "invoice.payment_failed")
  |> Repo.aggregate(:count)

IO.puts("   ✓ Email jobs (payment_failed): #{email_jobs_before}")
IO.puts("   ✓ Billing events (invoice.payment_failed): #{billing_events_before}")

# Step 3: Simulate invoice.payment_failed webhook
IO.puts("\n3. Simulating invoice.payment_failed webhook...")

# Construct realistic webhook payload
stripe_event_id = "evt_test_payment_failure_#{:rand.uniform(99999999)}"
stripe_invoice_id = "in_test_payment_failure_#{:rand.uniform(99999)}"

webhook_payload = %{
  "stripe_event_id" => stripe_event_id,
  "event_type" => "invoice.payment_failed",
  "event_data" => %{
    "object" => %{
      "id" => stripe_invoice_id,
      "customer" => test_customer.stripe_customer_id,
      "amount_due" => 2900,
      # $29.00 in cents
      "amount_paid" => 0,
      "attempt_count" => 1,
      # First retry in 23 hours
      "next_payment_attempt" => DateTime.utc_now() |> DateTime.add(23 * 3600, :second) |> DateTime.to_unix(),
      "status" => "open",
      "billing_reason" => "subscription_cycle"
    }
  }
}

IO.puts("   ✓ Stripe Event ID: #{stripe_event_id}")
IO.puts("   ✓ Stripe Invoice ID: #{stripe_invoice_id}")
IO.puts("   ✓ Amount Due: $29.00")
IO.puts("   ✓ Attempt Count: 1")

# Process the webhook
result = WebhookProcessor.process_event(webhook_payload)
IO.puts("   ✓ Webhook processed: #{inspect(result)}")

# Step 4: Verify customer state updated
IO.puts("\n4. Verifying customer state changes...")

updated_customer = Repo.reload!(test_customer)

if updated_customer.subscription_state == "past_due" do
  IO.puts("   ✅ Customer subscription_state updated to: #{updated_customer.subscription_state}")
else
  IO.puts("   ❌ FAILED: Expected 'past_due', got '#{updated_customer.subscription_state}'")
  exit(:customer_state_not_updated)
end

# Step 5: Verify email job queued
IO.puts("\n5. Verifying EmailWorker job queued...")

email_job =
  from(j in Oban.Job,
    where: j.worker == "Rsolv.Workers.EmailWorker",
    where: fragment("?->>'type' = ?", j.args, "payment_failed"),
    where: fragment("?->>'customer_id' = ?", j.args, ^to_string(test_customer.id)),
    order_by: [desc: j.inserted_at],
    limit: 1
  )
  |> Repo.one()

if email_job do
  IO.puts("   ✅ Email job found:")
  IO.puts("      Job ID: #{email_job.id}")
  IO.puts("      Queue: #{email_job.queue}")
  IO.puts("      State: #{email_job.state}")
  IO.puts("      Args:")
  IO.puts("        type: #{email_job.args["type"]}")
  IO.puts("        customer_id: #{email_job.args["customer_id"]}")
  IO.puts("        invoice_id: #{email_job.args["invoice_id"]}")
  IO.puts("        amount_due: #{email_job.args["amount_due"]}")
  IO.puts("        attempt_count: #{email_job.args["attempt_count"]}")

  if email_job.args["next_payment_attempt"] do
    next_attempt =
      email_job.args["next_payment_attempt"]
      |> DateTime.from_unix!()

    IO.puts("        next_payment_attempt: #{next_attempt}")
  end

  # Verify job has correct data
  assert email_job.args["type"] == "payment_failed"
  assert email_job.args["customer_id"] == test_customer.id
  assert email_job.args["invoice_id"] == stripe_invoice_id
  assert email_job.args["amount_due"] == 2900
  assert email_job.args["attempt_count"] == 1
else
  IO.puts("   ❌ FAILED: No email job found")
  exit(:email_job_not_queued)
end

# Step 6: Verify billing event created
IO.puts("\n6. Verifying BillingEvent created...")

billing_event =
  BillingEvent
  |> where([e], e.event_type == "invoice.payment_failed")
  |> where([e], e.stripe_event_id == ^stripe_event_id)
  |> Repo.one()

if billing_event do
  IO.puts("   ✅ Billing event created:")
  IO.puts("      Event ID: #{billing_event.id}")
  IO.puts("      Stripe Event ID: #{billing_event.stripe_event_id}")
  IO.puts("      Event Type: #{billing_event.event_type}")
  IO.puts("      Customer ID: #{billing_event.customer_id}")
  IO.puts("      Amount (cents): #{billing_event.amount_cents}")

  # Verify event data
  assert billing_event.event_type == "invoice.payment_failed"
  assert billing_event.customer_id == test_customer.id
  assert billing_event.amount_cents == 2900
else
  IO.puts("   ❌ FAILED: No billing event found")
  exit(:billing_event_not_created)
end

# Step 7: Test idempotency (duplicate webhook)
IO.puts("\n7. Testing webhook idempotency (duplicate event)...")

duplicate_result = WebhookProcessor.process_event(webhook_payload)
IO.puts("   ✓ Duplicate webhook result: #{inspect(duplicate_result)}")

if duplicate_result == {:ok, :duplicate} do
  IO.puts("   ✅ Duplicate correctly detected and ignored")
else
  IO.puts("   ❌ FAILED: Expected {:ok, :duplicate}, got #{inspect(duplicate_result)}")
  exit(:idempotency_failed)
end

# Verify no additional jobs or events created
email_jobs_after =
  from(j in Oban.Job,
    where: j.worker == "Rsolv.Workers.EmailWorker",
    where: fragment("?->>'type' = ?", j.args, "payment_failed")
  )
  |> Repo.aggregate(:count)

billing_events_after =
  BillingEvent
  |> where([e], e.event_type == "invoice.payment_failed")
  |> Repo.aggregate(:count)

IO.puts("   ✓ Email jobs after duplicate: #{email_jobs_after} (should be #{email_jobs_before + 1})")
IO.puts("   ✓ Billing events after duplicate: #{billing_events_after} (should be #{billing_events_before + 1})")

assert email_jobs_after == email_jobs_before + 1
assert billing_events_after == billing_events_before + 1

# Step 8: Summary
IO.puts("\n=== Test Summary ===")
IO.puts("✅ All tests passed!")
IO.puts("")
IO.puts("Verified:")
IO.puts("  ✓ Customer subscription_state updated to 'past_due'")
IO.puts("  ✓ EmailWorker job queued with correct data")
IO.puts("  ✓ BillingEvent created for audit trail")
IO.puts("  ✓ Webhook idempotency working (duplicate ignored)")
IO.puts("")
IO.puts("Test customer created:")
IO.puts("  Email: #{test_customer.email}")
IO.puts("  ID: #{test_customer.id}")
IO.puts("  Stripe Customer ID: #{test_customer.stripe_customer_id}")
IO.puts("")
IO.puts("Next steps:")
IO.puts("  1. Run email worker to actually send the email:")
IO.puts("     iex> Oban.drain_queue(queue: :emails)")
IO.puts("  2. Check email delivery logs")
IO.puts("  3. Verify customer receives dunning email")
IO.puts("")
