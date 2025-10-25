#!/usr/bin/env elixir

# Simulates a Stripe invoice.payment_succeeded webhook event
#
# Usage:
#   mix run scripts/webhooks/simulate_invoice_paid.exs
#
# Environment variables:
#   WEBHOOK_URL - Target URL (default: http://localhost:4000/api/webhooks/stripe)
#   WEBHOOK_SECRET - Webhook signing secret (default: whsec_test_secret_at_least_32_chars)
#   CUSTOMER_ID - Stripe customer ID (default: cus_test123)
#   SUBSCRIPTION_ID - Stripe subscription ID (default: sub_test456)
#   AMOUNT - Amount in cents (default: 1500)

defmodule WebhookSimulator do
  def run do
    # Configuration
    webhook_url = System.get_env("WEBHOOK_URL", "http://localhost:4000/api/webhooks/stripe")
    webhook_secret = System.get_env("WEBHOOK_SECRET", "whsec_test_secret_at_least_32_chars")
    customer_id = System.get_env("CUSTOMER_ID", "cus_test123")
    subscription_id = System.get_env("SUBSCRIPTION_ID", "sub_test456")
    amount = String.to_integer(System.get_env("AMOUNT", "1500"))

    # Generate event payload
    event_id = "evt_#{:rand.uniform(999_999_999)}"
    invoice_id = "in_#{:rand.uniform(999_999_999)}"

    payload = %{
      id: event_id,
      object: "event",
      api_version: "2023-10-16",
      created: System.system_time(:second),
      type: "invoice.payment_succeeded",
      data: %{
        object: %{
          id: invoice_id,
          object: "invoice",
          customer: customer_id,
          subscription: subscription_id,
          amount_paid: amount,
          amount_due: amount,
          currency: "usd",
          status: "paid",
          paid: true,
          billing_reason: "subscription_cycle",
          period_start: System.system_time(:second) - 2_592_000,
          period_end: System.system_time(:second),
          lines: %{
            data: [
              %{
                id: "li_#{:rand.uniform(999_999_999)}",
                amount: amount,
                currency: "usd",
                description: "1 × Growth Plan (at $15.00 / month)",
                period: %{
                  start: System.system_time(:second) - 2_592_000,
                  end: System.system_time(:second)
                },
                plan: %{
                  id: "price_growth_monthly",
                  amount: amount,
                  currency: "usd",
                  interval: "month"
                }
              }
            ]
          }
        }
      },
      livemode: false
    }

    # Send webhook
    send_webhook(webhook_url, webhook_secret, payload)
  end

  defp send_webhook(url, secret, payload) do
    json = Jason.encode!(payload)
    timestamp = System.system_time(:second)
    signature = generate_signature(json, timestamp, secret)

    headers = [
      {"Content-Type", "application/json"},
      {"Stripe-Signature", signature}
    ]

    IO.puts("\n🔔 Simulating invoice.payment_succeeded webhook")
    IO.puts("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
    IO.puts("Event ID:       #{payload.id}")
    IO.puts("Customer ID:    #{payload.data.object.customer}")
    IO.puts("Subscription:   #{payload.data.object.subscription}")
    IO.puts("Amount Paid:    $#{payload.data.object.amount_paid / 100}")
    IO.puts("Invoice ID:     #{payload.data.object.id}")
    IO.puts("Target URL:     #{url}")
    IO.puts("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n")

    case HTTPoison.post(url, json, headers) do
      {:ok, %HTTPoison.Response{status_code: status, body: body}} when status in 200..299 ->
        IO.puts("✅ Webhook accepted: #{status}")
        IO.puts("Response: #{body}\n")
        :ok

      {:ok, %HTTPoison.Response{status_code: status, body: body}} ->
        IO.puts("❌ Webhook rejected: #{status}")
        IO.puts("Response: #{body}\n")
        {:error, status}

      {:error, %HTTPoison.Error{reason: reason}} ->
        IO.puts("❌ Failed to send webhook: #{inspect(reason)}\n")
        {:error, reason}
    end
  end

  defp generate_signature(payload, timestamp, secret) do
    signed_payload = "#{timestamp}.#{payload}"

    signature =
      :crypto.mac(:hmac, :sha256, secret, signed_payload)
      |> Base.encode16(case: :lower)

    "t=#{timestamp},v1=#{signature}"
  end
end

# Run the simulator
WebhookSimulator.run()
