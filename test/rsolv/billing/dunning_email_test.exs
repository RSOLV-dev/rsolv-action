defmodule Rsolv.Billing.DunningEmailTest do
  use Rsolv.DataCase
  use Bamboo.Test
  use Oban.Testing, repo: Rsolv.Repo

  import Rsolv.CustomerFactory

  alias Rsolv.{Emails, EmailService}
  alias Rsolv.Billing.WebhookProcessor
  alias Rsolv.Workers.EmailWorker

  describe "payment_failed webhook" do
    setup do
      customer = insert(:customer) |> apply_trait!(&with_pro_plan/1)
      {:ok, customer: customer}
    end

    test "queues email job when payment fails", %{customer: customer} do
      # Simulate Stripe invoice.payment_failed webhook
      webhook_event = %{
        "stripe_event_id" => "evt_test_payment_failed_123",
        "event_type" => "invoice.payment_failed",
        "event_data" => %{
          "object" => %{
            "id" => "in_test123",
            "customer" => customer.stripe_customer_id,
            "amount_due" => 1999,
            "attempt_count" => 1,
            "next_payment_attempt" => 1_735_689_600
          }
        }
      }

      # Process the webhook
      assert {:ok, :processed} = WebhookProcessor.process_event(webhook_event)

      # Verify customer state was updated
      assert Repo.reload!(customer).subscription_state == "past_due"

      # Oban is configured with testing: :inline in test.exs, which executes jobs immediately
      # Instead of checking if job was enqueued, verify the side effect (email was sent)
      assert_email_delivered_with(subject: "Payment Failed - Action Required")
    end

    test "updates customer subscription state to past_due", %{customer: customer} do
      webhook_event = %{
        "stripe_event_id" => "evt_test_payment_failed_456",
        "event_type" => "invoice.payment_failed",
        "event_data" => %{
          "object" => %{
            "id" => "in_test456",
            "customer" => customer.stripe_customer_id,
            "amount_due" => 1999,
            "attempt_count" => 2,
            "next_payment_attempt" => nil
          }
        }
      }

      # Initial state is active
      assert customer.subscription_state == "active"

      # Process webhook
      WebhookProcessor.process_event(webhook_event)

      # Verify state changed to past_due
      assert Repo.reload!(customer).subscription_state == "past_due"
    end

    test "does not process duplicate webhook events", %{customer: customer} do
      webhook_event = %{
        "stripe_event_id" => "evt_duplicate_123",
        "event_type" => "invoice.payment_failed",
        "event_data" => %{
          "object" => %{
            "id" => "in_duplicate",
            "customer" => customer.stripe_customer_id,
            "amount_due" => 1999,
            "attempt_count" => 1,
            "next_payment_attempt" => nil
          }
        }
      }

      # Process first time
      assert {:ok, :processed} = WebhookProcessor.process_event(webhook_event)

      # Process second time - should be detected as duplicate
      assert {:ok, :duplicate} = WebhookProcessor.process_event(webhook_event)
    end
  end

  describe "email job processing" do
    setup do
      # with_pro_plan sets credit_balance to 60, override to 45 for this test
      customer = insert(:customer, name: "Jane Doe") |> apply_trait!(&with_pro_plan/1)
      {:ok, customer} = Rsolv.Customers.update_customer(customer, %{credit_balance: 45})

      {:ok, customer: customer}
    end

    test "sends payment failed email with correct content", %{customer: customer} do
      # Send the email
      {:ok, result} =
        EmailService.send_payment_failed_email(
          customer.id,
          "in_test789",
          1999,
          1_735_689_600,
          2
        )

      # Verify email was sent
      assert_delivered_email(result.email)

      # Verify email content
      email = result.email
      # Bamboo normalizes email addresses to {name, email} tuples
      assert email.to == [{nil, customer.email}]
      assert email.subject == "Payment Failed - Action Required"
      assert email.headers["X-Postmark-Tag"] == "payment-failed"

      # Check HTML body contains key information
      html_body = email.html_body
      assert html_body =~ "Hi Jane Doe"
      assert html_body =~ "$19.99"
      assert html_body =~ "in_test789"
      assert html_body =~ "Attempt Count:</strong> 2"
      assert html_body =~ "45 remaining"
      assert html_body =~ "https://rsolv.dev/dashboard/billing"

      # Check text body
      text_body = email.text_body
      assert text_body =~ "Hi Jane Doe"
      assert text_body =~ "$19.99"
      assert text_body =~ "in_test789"
      assert text_body =~ "Attempt Count: 2"
      assert text_body =~ "45 remaining"
    end

    test "formats currency correctly", %{customer: customer} do
      {:ok, result} = EmailService.send_payment_failed_email(customer.id, "in_test", 2999, nil, 1)

      email = result.email
      assert email.html_body =~ "$29.99"
      assert email.text_body =~ "$29.99"
    end

    test "includes next payment attempt when available", %{customer: customer} do
      # Unix timestamp for a specific date
      next_attempt = 1_735_689_600

      {:ok, result} =
        EmailService.send_payment_failed_email(customer.id, "in_test", 1999, next_attempt, 1)

      email = result.email
      # Should include formatted date
      assert email.html_body =~ "Next Retry:"
      assert email.text_body =~ "Next Retry:"
    end

    test "handles missing next payment attempt gracefully", %{customer: customer} do
      {:ok, result} = EmailService.send_payment_failed_email(customer.id, "in_test", 1999, nil, 1)

      email = result.email
      # Should not crash, just omit the next retry info
      assert email.html_body
      assert email.text_body
    end

    test "respects unsubscribe status", %{customer: customer} do
      # Mark customer as unsubscribed
      Rsolv.EmailOptOutService.unsubscribe(customer.email)

      # Attempt to send email
      {:skipped, result} =
        EmailService.send_payment_failed_email(customer.id, "in_test", 1999, nil, 1)

      # Verify email was not sent
      assert result.status == "unsubscribed"
      refute_delivered_email(Emails.payment_failed_email(customer, "in_test", 1999, nil, 1))
    end
  end

  describe "email worker integration" do
    setup do
      customer =
        insert(:customer, name: "Worker Test", credit_balance: 30)
        |> apply_trait!(&with_pro_plan/1)

      {:ok, customer: customer}
    end

    test "processes payment_failed job successfully", %{customer: customer} do
      # Create job args
      args = %{
        "type" => "payment_failed",
        "customer_id" => customer.id,
        "invoice_id" => "in_worker_test",
        "amount_due" => 1999,
        "attempt_count" => 1,
        "next_payment_attempt" => nil
      }

      # Create and perform job
      job = EmailWorker.new(args)
      assert :ok = perform_job(EmailWorker, args)

      # Verify email was sent
      assert_email_delivered_with(subject: "Payment Failed - Action Required")
    end

    test "handles errors gracefully", %{customer: _customer} do
      # Try to send email for non-existent customer
      args = %{
        "type" => "payment_failed",
        "customer_id" => 999_999,
        "invoice_id" => "in_error_test",
        "amount_due" => 1999,
        "attempt_count" => 1,
        "next_payment_attempt" => nil
      }

      # EmailWorker should catch the exception and return error tuple
      assert {:error, _reason} = perform_job(EmailWorker, args)
    end
  end

  describe "email content validation" do
    setup do
      customer = insert(:customer, name: "Content Test Customer", credit_balance: 75)
      {:ok, customer: customer}
    end

    test "includes all required content elements", %{customer: customer} do
      email = Emails.payment_failed_email(customer, "in_content_test", 1999, 1_735_689_600, 3)

      html = email.html_body
      text = email.text_body

      # Required elements in HTML
      assert html =~ "Payment Failed - Action Required"
      assert html =~ customer.name
      assert html =~ "$19.99"
      assert html =~ "in_content_test"
      assert html =~ "75 remaining"
      assert html =~ "Update Payment Method"
      assert html =~ "support@rsolv.dev"
      assert html =~ "Insufficient funds"
      assert html =~ "Expired card"

      # Required elements in text
      assert text =~ "Payment Failed - Action Required"
      assert text =~ customer.name
      assert text =~ "$19.99"
      assert text =~ "in_content_test"
      assert text =~ "75 remaining"
      assert text =~ "https://rsolv.dev/dashboard/billing"
      assert text =~ "support@rsolv.dev"
    end

    test "uses correct sender for billing emails", %{customer: customer} do
      email = Emails.payment_failed_email(customer, "in_sender_test", 1999, nil, 1)

      # Should use billing email, not support
      assert email.from == {"RSOLV Billing", "billing@rsolv.dev"}
    end

    test "sets correct priority headers", %{customer: customer} do
      email = Emails.payment_failed_email(customer, "in_priority_test", 1999, nil, 1)

      assert email.headers["X-Priority"] == "1"
      assert email.headers["X-Postmark-Tag"] == "payment-failed"
    end
  end

  describe "edge cases" do
    test "handles customer with minimal name gracefully" do
      # Test with very short name (single character)
      customer =
        insert(:customer, name: "X", credit_balance: 10)
        |> apply_trait!(&with_pro_plan/1)

      email = Emails.payment_failed_email(customer, "in_test", 1999, nil, 1)

      # Should not crash, email body should still render
      assert email.html_body
      assert email.text_body
      # Very short name should still appear in email
      assert email.html_body =~ "X"
    end

    test "handles zero credit balance" do
      customer =
        insert(:customer, credit_balance: 0)
        |> apply_trait!(&with_past_due/1)

      {:ok, result} = EmailService.send_payment_failed_email(customer.id, "in_test", 1999, nil, 1)

      email = result.email
      assert email.html_body =~ "0 remaining"
    end

    test "handles large attempt count" do
      customer =
        insert(:customer)
        |> apply_trait!(&with_past_due/1)

      email = Emails.payment_failed_email(customer, "in_test", 1999, nil, 15)

      assert email.html_body =~ "Attempt Count:</strong> 15"
    end
  end
end
