#!/usr/bin/env elixir
# Setup script for Stripe webhook testing using Ecto
# Run with: mix run --no-start test/scripts/setup_webhook_test_customer.exs

# This script uses Ecto instead of raw SQL for database consistency
# and to ensure proper schema validation and changesets

# Load the config without starting the application
Mix.Task.run("loadconfig")

# Start only the dependencies we need
Application.ensure_all_started(:postgrex)
Application.ensure_all_started(:ecto_sql)
Application.ensure_all_started(:bcrypt_elixir)

# Start the Repo manually (without full Phoenix app)
children = [
  {Rsolv.Repo, []}
]

{:ok, _pid} = Supervisor.start_link(children, strategy: :one_for_one)

alias Rsolv.Repo
alias Rsolv.Customers
alias Rsolv.Customers.Customer

# ANSI colors for output
defmodule Colors do
  def blue, do: IO.ANSI.blue()
  def green, do: IO.ANSI.green()
  def yellow, do: IO.ANSI.yellow()
  def reset, do: IO.ANSI.reset()
end

IO.puts(
  "\n#{Colors.blue()}╔═══════════════════════════════════════════════════════════╗#{Colors.reset()}"
)

IO.puts(
  "#{Colors.blue()}║   Stripe Webhook Testing - Customer Setup                ║#{Colors.reset()}"
)

IO.puts(
  "#{Colors.blue()}╚═══════════════════════════════════════════════════════════╝#{Colors.reset()}"
)

IO.puts("")

# Generate a fresh Stripe customer ID for this test run
test_stripe_id = "cus_test_webhook_#{:rand.uniform(9999)}"
test_email = "webhook-test@example.com"

IO.puts("#{Colors.yellow()}Setting up webhook test customer...#{Colors.reset()}")
IO.puts("  Email: #{test_email}")
IO.puts("  Stripe ID: #{test_stripe_id}")
IO.puts("")

# Check if customer already exists
existing_customer = Repo.get_by(Customer, email: test_email)

customer =
  if existing_customer do
    IO.puts(
      "#{Colors.green()}✓ Found existing customer (ID: #{existing_customer.id})#{Colors.reset()}"
    )

    IO.puts("  Resetting to clean state...")

    # Reset to clean state using Ecto changeset
    {:ok, updated} =
      Customers.update_customer(existing_customer, %{
        stripe_customer_id: test_stripe_id,
        credit_balance: 0,
        subscription_type: "pay_as_you_go",
        subscription_state: nil,
        stripe_subscription_id: nil,
        subscription_cancel_at_period_end: false,
        has_payment_method: false
      })

    IO.puts("#{Colors.green()}✓ Customer reset to initial state#{Colors.reset()}")
    updated
  else
    IO.puts("#{Colors.green()}✓ Creating new webhook test customer#{Colors.reset()}")

    # Create new customer using Ecto (with proper password hashing via changeset)
    {:ok, customer} =
      Customers.register_customer(%{
        name: "Webhook Test Customer",
        email: test_email,
        password: "WebhookTest123!",
        stripe_customer_id: test_stripe_id,
        credit_balance: 0,
        subscription_type: "pay_as_you_go",
        active: true,
        metadata: %{
          "type" => "test",
          "purpose" => "webhook_testing"
        }
      })

    IO.puts("#{Colors.green()}✓ Customer created successfully#{Colors.reset()}")
    customer
  end

# Display current state
IO.puts("")

IO.puts(
  "#{Colors.yellow()}─────────────────────────────────────────────────────────#{Colors.reset()}"
)

IO.puts("#{Colors.green()}Current Customer State#{Colors.reset()}")

IO.puts(
  "#{Colors.yellow()}─────────────────────────────────────────────────────────#{Colors.reset()}"
)

IO.puts("  ID: #{customer.id}")
IO.puts("  Email: #{customer.email}")
IO.puts("  Stripe Customer ID: #{customer.stripe_customer_id}")
IO.puts("  Credit Balance: #{customer.credit_balance}")
IO.puts("  Subscription Type: #{customer.subscription_type}")
IO.puts("  Subscription State: #{customer.subscription_state || "N/A"}")
IO.puts("  Stripe Subscription ID: #{customer.stripe_subscription_id || "N/A"}")
IO.puts("")

# Display testing instructions
IO.puts(
  "#{Colors.blue()}═══════════════════════════════════════════════════════════#{Colors.reset()}"
)

IO.puts("#{Colors.green()}Setup Complete!#{Colors.reset()}")

IO.puts(
  "#{Colors.blue()}═══════════════════════════════════════════════════════════#{Colors.reset()}"
)

IO.puts("")

IO.puts(
  "#{Colors.yellow()}IMPORTANT: Use this Stripe Customer ID for all test events:#{Colors.reset()}"
)

IO.puts("#{Colors.green()}  #{customer.stripe_customer_id}#{Colors.reset()}")
IO.puts("")
IO.puts("#{Colors.yellow()}Next Steps:#{Colors.reset()}")
IO.puts("")
IO.puts("1. Start Phoenix server (Terminal 1):")
IO.puts("   #{Colors.blue()}mix phx.server#{Colors.reset()}")
IO.puts("")
IO.puts("2. Start Stripe CLI forwarding (Terminal 2):")

IO.puts(
  "   #{Colors.blue()}stripe listen --forward-to http://localhost:4000/api/webhooks/stripe#{Colors.reset()}"
)

IO.puts("")
IO.puts("   Then copy the webhook secret and:")

IO.puts(
  "   #{Colors.blue()}export STRIPE_WEBHOOK_SECRET=whsec_xxxxxxxxxxxxxxxxxxxxx#{Colors.reset()}"
)

IO.puts("   Restart Phoenix server after setting the secret")
IO.puts("")
IO.puts("3. Trigger events (Terminal 3):")
IO.puts("   #{Colors.blue()}stripe trigger invoice.payment_succeeded \\")
IO.puts("     --override customer=#{customer.stripe_customer_id}#{Colors.reset()}")
IO.puts("")
IO.puts("4. Verify results:")
IO.puts("   #{Colors.blue()}test/scripts/verify_webhooks.sh#{Colors.reset()}")
IO.puts("")

IO.puts(
  "#{Colors.yellow()}See docs/STRIPE-WEBHOOK-TESTING.md for complete testing guide#{Colors.reset()}"
)

IO.puts("")
