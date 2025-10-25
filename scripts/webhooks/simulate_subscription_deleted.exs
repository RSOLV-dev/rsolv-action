#!/usr/bin/env elixir

# Simulates a Stripe customer.subscription.deleted webhook event
#
# Usage:
#   mix run scripts/webhooks/simulate_subscription_deleted.exs
#
# Environment variables:
#   WEBHOOK_URL - Target URL
#   WEBHOOK_SECRET - Webhook signing secret
#   CUSTOMER_ID - Stripe customer ID
#   SUBSCRIPTION_ID - Stripe subscription ID
#   CANCEL_REASON - Cancellation reason (default: user_requested)

defmodule WebhookSimulator do
  def run do
    webhook_url = System.get_env("WEBHOOK_URL", "http://localhost:4000/api/webhooks/stripe")
    webhook_secret = System.get_env("WEBHOOK_SECRET", "whsec_test_secret_at_least_32_chars")
    customer_id = System.get_env("CUSTOMER_ID", "cus_test123")
    subscription_id = System.get_env("SUBSCRIPTION_ID", "sub_test456")
    cancel_reason = System.get_env("CANCEL_REASON", "user_requested")

    event_id = "evt_#{:rand.uniform(999_999_999)}"
    canceled_at = System.system_time(:second)

    payload = %{
      id: event_id,
      object: "event",
      api_version: "2023-10-16",
      created: System.system_time(:second),
      type: "customer.subscription.deleted",
      data: %{
        object: %{
          id: subscription_id,
          object: "subscription",
          customer: customer_id,
          status: "canceled",
          canceled_at: canceled_at,
          cancel_at_period_end: false,
          current_period_start: canceled_at - 2_592_000,
          current_period_end: canceled_at,
          cancellation_details: %{
            reason: cancel_reason,
            comment: nil,
            feedback: nil
          },
          items: %{
            data: [
              %{
                id: "si_#{:rand.uniform(999_999_999)}",
                price: %{
                  id: "price_growth_monthly",
                  product: "prod_growth",
                  active: true,
                  currency: "usd",
                  unit_amount: 1500,
                  recurring: %{
                    interval: "month",
                    interval_count: 1
                  }
                },
                quantity: 1
              }
            ]
          },
          metadata: %{},
          plan: %{
            id: "price_growth_monthly",
            amount: 1500,
            currency: "usd",
            interval: "month"
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

    IO.puts("\n🔔 Simulating customer.subscription.deleted webhook")
    IO.puts("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
    IO.puts("Event ID:       #{payload.id}")
    IO.puts("Customer ID:    #{payload.data.object.customer}")
    IO.puts("Subscription:   #{payload.data.object.id}")
    IO.puts("Status:         #{payload.data.object.status}")
    IO.puts("Cancel Reason:  #{payload.data.object.cancellation_details.reason}")
    IO.puts("Canceled At:    #{payload.data.object.canceled_at}")
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
