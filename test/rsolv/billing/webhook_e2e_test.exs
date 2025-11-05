defmodule Rsolv.Billing.WebhookE2ETest do
  @moduledoc """
  End-to-end test for Stripe webhook credit allocation.

  This test uses the EXACT webhook event structure from Stripe API 2025-10-29
  to verify that Pro subscription payments correctly credit customer accounts.

  Event used: evt_0SQCyj7pIu1KP146rRnJTlL4
  Invoice: in_0SQCye7pIu1KP146gaRaicas
  Customer: cus_TMeu9PZhUP9bsa
  """
  use Rsolv.DataCase, async: false

  alias Rsolv.Billing.{WebhookProcessor, BillingEvent}
  alias Rsolv.Billing.CreditLedger
  alias Rsolv.Customers
  alias Rsolv.Repo

  describe "invoice.payment_succeeded with real Stripe API format" do
    setup do
      # Create customer matching our test customer
      {:ok, customer} =
        Customers.create_customer(%{
          name: "Webhook Test Customer",
          email: "webhook-test-e2e@test.rsolv.dev",
          stripe_customer_id: "cus_TMeu9PZhUP9bsa",
          subscription_type: "pay_as_you_go",
          subscription_state: "active",
          credit_balance: 0
        })

      {:ok, customer: customer}
    end

    test "credits 60 fixes for Pro subscription payment (real API format)", %{customer: customer} do
      # Real event data from Stripe (evt_0SQCyj7pIu1KP146rRnJTlL4)
      # This is the EXACT structure returned by Stripe API 2025-10-29
      event_data = %{
        "stripe_event_id" => "evt_0SQCyj7pIu1KP146rRnJTlL4",
        "event_type" => "invoice.payment_succeeded",
        "event_data" => %{
          "object" => %{
            "id" => "in_0SQCye7pIu1KP146gaRaicas",
            "object" => "invoice",
            "customer" => "cus_TMeu9PZhUP9bsa",
            "amount_paid" => 59_900,
            "status" => "paid",
            "billing_reason" => "subscription_create",
            "lines" => %{
              "object" => "list",
              "data" => [
                %{
                  "id" => "il_0SQCyd7pIu1KP146MqPAzpiD",
                  "object" => "line_item",
                  "amount" => 59_900,
                  "currency" => "usd",
                  "description" => "1 × RSOLV Pro Subscription (at $599.00 / month)",
                  "pricing" => %{
                    "price_details" => %{
                      "price" => "price_0SPvUw7pIu1KP146qVYwNTQ8",
                      "product" => "prod_TMeovc9YOVf3EX"
                    },
                    "type" => "price_details",
                    "unit_amount_decimal" => "59900"
                  },
                  "quantity" => 1
                }
              ],
              "has_more" => false,
              "total_count" => 1
            }
          }
        }
      }

      # Process the webhook
      assert {:ok, _job_or_status} = WebhookProcessor.process_event(event_data)

      # Execute any queued jobs
      Oban.drain_queue(queue: :webhooks)

      # Verify customer was credited
      updated_customer = Repo.get!(Customers.Customer, customer.id)

      assert updated_customer.credit_balance == 60,
             "Expected credit_balance to be 60, got #{updated_customer.credit_balance}"

      # Verify credit transaction was recorded
      transactions = CreditLedger.list_transactions(updated_customer)
      assert length(transactions) == 1

      [transaction] = transactions
      assert transaction.amount == 60
      assert transaction.source == "pro_subscription_payment"
      assert transaction.metadata["stripe_invoice_id"] == "in_0SQCye7pIu1KP146gaRaicas"
      assert transaction.metadata["amount_cents"] == 59_900

      # Verify billing event was recorded for idempotency
      billing_event = Repo.get_by(BillingEvent, stripe_event_id: "evt_0SQCyj7pIu1KP146rRnJTlL4")
      assert billing_event != nil
      assert billing_event.event_type == "invoice.payment_succeeded"
      assert billing_event.customer_id == customer.id

      # Verify idempotency - processing again should not credit twice
      assert {:ok, :duplicate} = WebhookProcessor.process_event(event_data)

      still_updated_customer = Repo.get!(Customers.Customer, customer.id)

      assert still_updated_customer.credit_balance == 60,
             "Credit balance should still be 60 after duplicate event"
    end

    test "does not credit for non-Pro invoices", %{customer: customer} do
      # Invoice with different price (not Pro)
      event_data = %{
        "stripe_event_id" => "evt_test_not_pro",
        "event_type" => "invoice.payment_succeeded",
        "event_data" => %{
          "object" => %{
            "id" => "in_test_not_pro",
            "customer" => "cus_TMeu9PZhUP9bsa",
            "amount_paid" => 2000,
            "lines" => %{
              "data" => [
                %{
                  "pricing" => %{
                    "price_details" => %{
                      # Not Pro price
                      "price" => "price_different",
                      "product" => "prod_different"
                    }
                  }
                }
              ]
            }
          }
        }
      }

      assert {:ok, _job_or_status} = WebhookProcessor.process_event(event_data)
      Oban.drain_queue(queue: :webhooks)

      # Customer should NOT be credited
      updated_customer = Repo.get!(Customers.Customer, customer.id)
      assert updated_customer.credit_balance == 0
    end
  end
end
