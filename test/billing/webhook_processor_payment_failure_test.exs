defmodule Rsolv.Billing.WebhookProcessorPaymentFailureTest do
  use Rsolv.DataCase, async: false

  alias Rsolv.Customers
  alias Rsolv.Billing.{WebhookProcessor, BillingEvent}
  alias Rsolv.Repo
  import Ecto.Query

  @moduledoc """
  Test invoice.payment_failed webhook handling and dunning email flow (RFC-066).

  This test verifies:
  1. Customer subscription_state updated to "past_due"
  2. EmailWorker job queued with correct payment_failed data
  3. BillingEvent created for audit trail
  4. Webhook idempotency (duplicates ignored)
  """

  describe "invoice.payment_failed webhook" do
    setup do
      # Create test customer with Pro subscription
      {:ok, customer} =
        Customers.register_customer(%{
          name: "Payment Test Customer",
          email: "payment.test#{:rand.uniform(9999)}@example.com",
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

      stripe_event_id = "evt_test_payment_failure_#{:rand.uniform(99999999)}"
      stripe_invoice_id = "in_test_payment_failure_#{:rand.uniform(99999)}"
      next_attempt_unix = DateTime.utc_now() |> DateTime.add(23 * 3600, :second) |> DateTime.to_unix()

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
            "next_payment_attempt" => next_attempt_unix,
            "status" => "open",
            "billing_reason" => "subscription_cycle"
          }
        }
      }

      %{
        customer: customer,
        webhook_payload: webhook_payload,
        stripe_event_id: stripe_event_id,
        stripe_invoice_id: stripe_invoice_id
      }
    end

    test "updates customer subscription_state to past_due", %{customer: customer, webhook_payload: payload} do
      # Process webhook
      assert {:ok, :processed} = WebhookProcessor.process_event(payload)

      # Verify customer state updated
      updated_customer = Repo.reload!(customer)
      assert updated_customer.subscription_state == "past_due"
    end

    test "queues EmailWorker job with correct payment_failed data", %{
      customer: customer,
      webhook_payload: payload,
      stripe_invoice_id: invoice_id
    } do
      # Use manual testing mode to prevent inline job execution
      Oban.Testing.with_testing_mode(:manual, fn ->
        # Process webhook
        assert {:ok, :processed} = WebhookProcessor.process_event(payload)

        # Find the email job (should be available now)
        email_job =
          from(j in Oban.Job,
            where: j.worker == "Rsolv.Workers.EmailWorker",
            where: fragment("?->>'type' = ?", j.args, "payment_failed"),
            where: fragment("?->>'customer_id' = ?", j.args, ^to_string(customer.id)),
            order_by: [desc: j.inserted_at],
            limit: 1
          )
          |> Repo.one()

        assert email_job != nil, "EmailWorker job should be queued"
        assert email_job.queue == "emails"
        assert email_job.state == "available"

        # Verify job args
        args = email_job.args
        assert args["type"] == "payment_failed"
        assert args["customer_id"] == customer.id
        assert args["invoice_id"] == invoice_id
        assert args["amount_due"] == 2900
        assert args["attempt_count"] == 1
        assert is_integer(args["next_payment_attempt"])
      end)
    end

    test "creates BillingEvent for audit trail", %{
      customer: customer,
      webhook_payload: payload,
      stripe_event_id: event_id
    } do
      # Process webhook
      assert {:ok, :processed} = WebhookProcessor.process_event(payload)

      # Find the billing event
      billing_event =
        BillingEvent
        |> where([e], e.event_type == "invoice.payment_failed")
        |> where([e], e.stripe_event_id == ^event_id)
        |> Repo.one()

      assert billing_event != nil, "BillingEvent should be created"
      assert billing_event.event_type == "invoice.payment_failed"
      assert billing_event.customer_id == customer.id
      assert billing_event.amount_cents == 2900
      assert billing_event.stripe_event_id == event_id
    end

    test "handles duplicate webhooks (idempotency)", %{webhook_payload: payload} do
      # Process webhook first time
      assert {:ok, :processed} = WebhookProcessor.process_event(payload)

      # Count events and jobs after first processing
      event_count_after_first =
        BillingEvent
        |> where([e], e.event_type == "invoice.payment_failed")
        |> Repo.aggregate(:count)

      job_count_after_first =
        from(j in Oban.Job,
          where: j.worker == "Rsolv.Workers.EmailWorker",
          where: fragment("?->>'type' = ?", j.args, "payment_failed")
        )
        |> Repo.aggregate(:count)

      # Process duplicate webhook
      assert {:ok, :duplicate} = WebhookProcessor.process_event(payload)

      # Verify no additional events or jobs created
      event_count_after_duplicate =
        BillingEvent
        |> where([e], e.event_type == "invoice.payment_failed")
        |> Repo.aggregate(:count)

      job_count_after_duplicate =
        from(j in Oban.Job,
          where: j.worker == "Rsolv.Workers.EmailWorker",
          where: fragment("?->>'type' = ?", j.args, "payment_failed")
        )
        |> Repo.aggregate(:count)

      assert event_count_after_duplicate == event_count_after_first
      assert job_count_after_duplicate == job_count_after_first
    end

    test "logs payment failure details", %{webhook_payload: payload} do
      # Capture logs
      log =
        ExUnit.CaptureLog.capture_log(fn ->
          WebhookProcessor.process_event(payload)
        end)

      # Logger metadata doesn't appear in captured log string, just the message
      assert log =~ "Payment failed for customer"
    end
  end
end
