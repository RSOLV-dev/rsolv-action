#!/usr/bin/env elixir

# Simulates a Stripe customer.subscription.updated webhook event
#
# Usage:
#   mix run scripts/webhooks/simulate_subscription_updated.exs
#
# Environment variables:
#   WEBHOOK_URL - Target URL
#   WEBHOOK_SECRET - Webhook signing secret
#   CUSTOMER_ID - Stripe customer ID
#   SUBSCRIPTION_ID - Stripe subscription ID
#   OLD_PLAN - Previous plan ID (default: price_growth_monthly)
#   NEW_PLAN - New plan ID (default: price_enterprise_monthly)
#   OLD_QUANTITY - Previous quantity (default: 1)
#   NEW_QUANTITY - New quantity (default: 5)

defmodule WebhookSimulator do
  def run do
    webhook_url = System.get_env("WEBHOOK_URL", "http://localhost:4000/api/webhooks/stripe")
    webhook_secret = System.get_env("WEBHOOK_SECRET", "whsec_test_secret_at_least_32_chars")
    customer_id = System.get_env("CUSTOMER_ID", "cus_test123")
    subscription_id = System.get_env("SUBSCRIPTION_ID", "sub_test456")
    old_plan = System.get_env("OLD_PLAN", "price_growth_monthly")
    new_plan = System.get_env("NEW_PLAN", "price_enterprise_monthly")
    old_quantity = String.to_integer(System.get_env("OLD_QUANTITY", "1"))
    new_quantity = String.to_integer(System.get_env("NEW_QUANTITY", "5"))

    event_id = "evt_#{:rand.uniform(999_999_999)}"
    current_time = System.system_time(:second)

    # Plan prices
    plan_prices = %{
      "price_growth_monthly" => 1500,
      "price_enterprise_monthly" => 10000,
      "price_starter_monthly" => 500
    }

    old_amount = Map.get(plan_prices, old_plan, 1500)
    new_amount = Map.get(plan_prices, new_plan, 10000)

    payload = %{
      id: event_id,
      object: "event",
      api_version: "2023-10-16",
      created: current_time,
      type: "customer.subscription.updated",
      data: %{
        object: %{
          id: subscription_id,
          object: "subscription",
          customer: customer_id,
          status: "active",
          current_period_start: current_time - 2_592_000,
          current_period_end: current_time + 2_592_000,
          items: %{
            data: [
              %{
                id: "si_#{:rand.uniform(999_999_999)}",
                price: %{
                  id: new_plan,
                  product: "prod_enterprise",
                  active: true,
                  currency: "usd",
                  unit_amount: new_amount,
                  recurring: %{
                    interval: "month",
                    interval_count: 1
                  }
                },
                quantity: new_quantity
              }
            ]
          },
          metadata: %{
            upgrade_from: old_plan,
            upgrade_reason: "customer_requested"
          },
          plan: %{
            id: new_plan,
            amount: new_amount,
            currency: "usd",
            interval: "month"
          },
          quantity: new_quantity
        },
        previous_attributes: %{
          items: %{
            data: [
              %{
                price: %{
                  id: old_plan,
                  unit_amount: old_amount
                },
                quantity: old_quantity
              }
            ]
          },
          quantity: old_quantity
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

    old_plan = get_in(payload, [:data, :previous_attributes, :items, :data, Access.at(0), :price, :id])
    new_plan = get_in(payload, [:data, :object, :plan, :id])
    old_quantity = get_in(payload, [:data, :previous_attributes, :quantity])
    new_quantity = get_in(payload, [:data, :object, :quantity])

    IO.puts("\n🔔 Simulating customer.subscription.updated webhook")
    IO.puts("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
    IO.puts("Event ID:       #{payload.id}")
    IO.puts("Customer ID:    #{payload.data.object.customer}")
    IO.puts("Subscription:   #{payload.data.object.id}")
    IO.puts("Status:         #{payload.data.object.status}")
    IO.puts("Plan Change:    #{old_plan} → #{new_plan}")
    IO.puts("Quantity:       #{old_quantity} → #{new_quantity}")
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
