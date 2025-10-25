#!/usr/bin/env elixir

# Simulates a Stripe invoice.payment_failed webhook event
#
# Usage:
#   mix run scripts/webhooks/simulate_invoice_failed.exs
#
# Environment variables:
#   WEBHOOK_URL - Target URL (default: http://localhost:4000/api/webhooks/stripe)
#   WEBHOOK_SECRET - Webhook signing secret
#   CUSTOMER_ID - Stripe customer ID
#   SUBSCRIPTION_ID - Stripe subscription ID
#   AMOUNT - Amount in cents (default: 1500)
#   FAILURE_CODE - Stripe error code (default: card_declined)

defmodule WebhookSimulator do
  def run do
    webhook_url = System.get_env("WEBHOOK_URL", "http://localhost:4000/api/webhooks/stripe")
    webhook_secret = System.get_env("WEBHOOK_SECRET", "whsec_test_secret_at_least_32_chars")
    customer_id = System.get_env("CUSTOMER_ID", "cus_test123")
    subscription_id = System.get_env("SUBSCRIPTION_ID", "sub_test456")
    amount = String.to_integer(System.get_env("AMOUNT", "1500"))
    failure_code = System.get_env("FAILURE_CODE", "card_declined")

    event_id = "evt_#{:rand.uniform(999_999_999)}"
    invoice_id = "in_#{:rand.uniform(999_999_999)}"

    payload = %{
      id: event_id,
      object: "event",
      api_version: "2023-10-16",
      created: System.system_time(:second),
      type: "invoice.payment_failed",
      data: %{
        object: %{
          id: invoice_id,
          object: "invoice",
          customer: customer_id,
          subscription: subscription_id,
          amount_due: amount,
          amount_paid: 0,
          amount_remaining: amount,
          currency: "usd",
          status: "open",
          paid: false,
          attempted: true,
          attempt_count: 1,
          billing_reason: "subscription_cycle",
          last_payment_error: %{
            type: "card_error",
            code: failure_code,
            message: "Your card was declined.",
            decline_code: failure_code
          },
          next_payment_attempt: System.system_time(:second) + 86400,
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
                }
              }
            ]
          }
        }
      },
      livemode: false
    }

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

    IO.puts("\n🔔 Simulating invoice.payment_failed webhook")
    IO.puts("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
    IO.puts("Event ID:       #{payload.id}")
    IO.puts("Customer ID:    #{payload.data.object.customer}")
    IO.puts("Subscription:   #{payload.data.object.subscription}")
    IO.puts("Amount Due:     $#{payload.data.object.amount_due / 100}")
    IO.puts("Invoice ID:     #{payload.data.object.id}")
    IO.puts("Failure Code:   #{payload.data.object.last_payment_error.code}")
    IO.puts("Next Retry:     #{payload.data.object.next_payment_attempt}")
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

WebhookSimulator.run()
