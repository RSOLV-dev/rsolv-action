defmodule Rsolv.Billing.WebhookProcessorTest do
  @moduledoc """
  Tests for Stripe webhook processing with idempotency.

  Tests all 5 critical webhook events:
  1. invoice.payment_succeeded - Credits Pro subscription payments
  2. invoice.payment_failed - Handles payment failures
  3. customer.subscription.created - Records new subscriptions
  4. customer.subscription.deleted - Downgrades to PAYG
  5. customer.subscription.updated - Handles status changes
  """
  use Rsolv.DataCase, async: false

  alias Rsolv.Billing.{WebhookProcessor, BillingEvent}
  alias Rsolv.Customers
  alias Rsolv.Repo

  describe "invoice.payment_succeeded" do
    setup do
      # Create customer with Pro subscription
      {:ok, customer} =
        Customers.create_customer(%{
          name: "Test Customer",
          email: "test-payment-#{System.unique_integer([:positive])}@example.com",
          stripe_customer_id: "cus_test123",
          subscription_type: "pro",
          subscription_state: "active",
          credit_balance: 0
        })

      {:ok, customer: customer}
    end

    test "credits 60 for Pro subscription payment", %{customer: customer} do
      event_data = %{
        "stripe_event_id" => "evt_test_123",
        "event_type" => "invoice.payment_succeeded",
        "event_data" => %{
          "object" => %{
            "id" => "in_test_123",
            "customer" => customer.stripe_customer_id,
            "amount_paid" => 59900,
            "lines" => %{
              "data" => [
                %{
                  "price" => %{
                    "lookup_key" => "pro_monthly",
                    "metadata" => %{"plan" => "pro"}
                  }
                }
              ]
            }
          }
        }
      }

      assert {:ok, :processed} = WebhookProcessor.process_event(event_data)

      # Verify credits were added
      updated_customer = Customers.get_customer!(customer.id)
      assert updated_customer.credit_balance == 60
    end

    test "handles idempotency - doesn't duplicate credits", %{customer: customer} do
      event_data = %{
        "stripe_event_id" => "evt_idempotent_123",
        "event_type" => "invoice.payment_succeeded",
        "event_data" => %{
          "object" => %{
            "id" => "in_test_idempotent",
            "customer" => customer.stripe_customer_id,
            "amount_paid" => 59900,
            "lines" => %{
              "data" => [
                %{
                  "price" => %{
                    "metadata" => %{"plan" => "pro"}
                  }
                }
              ]
            }
          }
        }
      }

      # Process first time
      assert {:ok, :processed} = WebhookProcessor.process_event(event_data)
      updated_customer = Customers.get_customer!(customer.id)
      assert updated_customer.credit_balance == 60

      # Process again - should detect duplicate
      assert {:ok, :duplicate} = WebhookProcessor.process_event(event_data)

      # Credits should not be doubled
      updated_customer = Customers.get_customer!(customer.id)
      assert updated_customer.credit_balance == 60
    end

    test "handles concurrent duplicate webhooks atomically (RFC-069 Bug #2)", %{customer: customer} do
      event_data = %{
        "stripe_event_id" => "evt_concurrent_race_123",
        "event_type" => "invoice.payment_succeeded",
        "event_data" => %{
          "object" => %{
            "id" => "in_concurrent_123",
            "customer" => customer.stripe_customer_id,
            "amount_paid" => 59900,
            "lines" => %{
              "data" => [
                %{
                  "price" => %{
                    "metadata" => %{"plan" => "pro"}
                  }
                }
              ]
            }
          }
        }
      }

      # Simulate concurrent webhooks by processing in parallel tasks
      # Both tasks start at the same time, simulating network-level duplication
      task1 = Task.async(fn -> WebhookProcessor.process_event(event_data) end)
      task2 = Task.async(fn -> WebhookProcessor.process_event(event_data) end)

      # Wait for both to complete
      result1 = Task.await(task1)
      result2 = Task.await(task2)

      # Exactly one should process, one should see duplicate
      results = Enum.sort([result1, result2])
      assert results == [{:ok, :duplicate}, {:ok, :processed}]

      # CRITICAL: Customer should have exactly 60 credits, not 120
      updated_customer = Customers.get_customer!(customer.id)
      assert updated_customer.credit_balance == 60

      # Verify only one billing event was recorded
      events = Repo.all(from e in BillingEvent, where: e.stripe_event_id == "evt_concurrent_race_123")
      assert length(events) == 1

      # Verify only one credit transaction was recorded
      credit_txns =
        Repo.all(
          from t in Rsolv.Billing.CreditTransaction,
            where: t.customer_id == ^customer.id and t.source == "pro_subscription_payment"
        )

      assert length(credit_txns) == 1
      assert hd(credit_txns).amount == 60
    end

    test "records billing event for audit trail", %{customer: customer} do
      event_data = %{
        "stripe_event_id" => "evt_audit_123",
        "event_type" => "invoice.payment_succeeded",
        "event_data" => %{
          "object" => %{
            "id" => "in_test_audit",
            "customer" => customer.stripe_customer_id,
            "amount_paid" => 59900,
            "lines" => %{
              "data" => [
                %{
                  "price" => %{
                    "metadata" => %{"plan" => "pro"}
                  }
                }
              ]
            }
          }
        }
      }

      assert {:ok, :processed} = WebhookProcessor.process_event(event_data)

      # Verify billing event was recorded
      event = Repo.get_by(BillingEvent, stripe_event_id: "evt_audit_123")
      assert event != nil
      assert event.event_type == "invoice.payment_succeeded"
      assert event.customer_id == customer.id
      assert event.amount_cents == 59900
    end
  end

  describe "invoice.payment_failed" do
    setup do
      {:ok, customer} =
        Customers.create_customer(%{
          name: "Test Customer",
          email: "test-failed-#{System.unique_integer([:positive])}@example.com",
          stripe_customer_id: "cus_failed123",
          subscription_type: "pro",
          subscription_state: "active"
        })

      {:ok, customer: customer}
    end

    test "updates subscription state to past_due", %{customer: customer} do
      event_data = %{
        "stripe_event_id" => "evt_failed_123",
        "event_type" => "invoice.payment_failed",
        "event_data" => %{
          "object" => %{
            "id" => "in_failed_123",
            "customer" => customer.stripe_customer_id,
            "amount_due" => 59900
          }
        }
      }

      assert {:ok, :processed} = WebhookProcessor.process_event(event_data)

      # Verify subscription state updated
      updated_customer = Customers.get_customer!(customer.id)
      assert updated_customer.subscription_state == "past_due"
    end
  end

  describe "customer.subscription.created" do
    setup do
      {:ok, customer} =
        Customers.create_customer(%{
          name: "Test Customer",
          email: "test-created-#{System.unique_integer([:positive])}@example.com",
          stripe_customer_id: "cus_new_sub123"
        })

      {:ok, customer: customer}
    end

    test "records subscription details", %{customer: customer} do
      event_data = %{
        "stripe_event_id" => "evt_sub_created_123",
        "event_type" => "customer.subscription.created",
        "event_data" => %{
          "object" => %{
            "id" => "sub_test123",
            "customer" => customer.stripe_customer_id,
            "status" => "active"
          }
        }
      }

      assert {:ok, :processed} = WebhookProcessor.process_event(event_data)

      # Verify subscription recorded
      updated_customer = Customers.get_customer!(customer.id)
      assert updated_customer.stripe_subscription_id == "sub_test123"
      assert updated_customer.subscription_type == "pro"
      assert updated_customer.subscription_state == "active"
    end
  end

  describe "customer.subscription.deleted" do
    setup do
      {:ok, customer} =
        Customers.create_customer(%{
          name: "Test Customer",
          email: "test-deleted-#{System.unique_integer([:positive])}@example.com",
          stripe_customer_id: "cus_cancel123",
          stripe_subscription_id: "sub_cancel123",
          subscription_type: "pro",
          subscription_state: "active",
          credit_balance: 45
        })

      {:ok, customer: customer}
    end

    test "downgrades to PAYG and preserves credits", %{customer: customer} do
      event_data = %{
        "stripe_event_id" => "evt_deleted_123",
        "event_type" => "customer.subscription.deleted",
        "event_data" => %{
          "object" => %{
            "id" => customer.stripe_subscription_id,
            "customer" => customer.stripe_customer_id
          }
        }
      }

      assert {:ok, :processed} = WebhookProcessor.process_event(event_data)

      # Verify downgrade to PAYG
      updated_customer = Customers.get_customer!(customer.id)
      assert updated_customer.subscription_type == "pay_as_you_go"
      assert updated_customer.subscription_state == nil
      assert updated_customer.stripe_subscription_id == nil
      assert updated_customer.subscription_cancel_at_period_end == false

      # Credits should be preserved
      assert updated_customer.credit_balance == 45
    end
  end

  describe "customer.subscription.updated" do
    setup do
      {:ok, customer} =
        Customers.create_customer(%{
          name: "Test Customer",
          email: "test-updated-#{System.unique_integer([:positive])}@example.com",
          stripe_customer_id: "cus_update123",
          stripe_subscription_id: "sub_update123",
          subscription_type: "pro",
          subscription_state: "active"
        })

      {:ok, customer: customer}
    end

    test "updates subscription state", %{customer: customer} do
      event_data = %{
        "stripe_event_id" => "evt_updated_123",
        "event_type" => "customer.subscription.updated",
        "event_data" => %{
          "object" => %{
            "id" => customer.stripe_subscription_id,
            "customer" => customer.stripe_customer_id,
            "status" => "past_due",
            "cancel_at_period_end" => false
          }
        }
      }

      assert {:ok, :processed} = WebhookProcessor.process_event(event_data)

      # Verify state updated
      updated_customer = Customers.get_customer!(customer.id)
      assert updated_customer.subscription_state == "past_due"
    end

    test "handles cancel_at_period_end flag", %{customer: customer} do
      event_data = %{
        "stripe_event_id" => "evt_cancel_scheduled_123",
        "event_type" => "customer.subscription.updated",
        "event_data" => %{
          "object" => %{
            "id" => customer.stripe_subscription_id,
            "customer" => customer.stripe_customer_id,
            "status" => "active",
            "cancel_at_period_end" => true,
            "current_period_end" => 1_735_689_600
          }
        }
      }

      assert {:ok, :processed} = WebhookProcessor.process_event(event_data)

      # Verify cancellation scheduled
      updated_customer = Customers.get_customer!(customer.id)
      assert updated_customer.subscription_cancel_at_period_end == true
      assert updated_customer.subscription_state == "active"
    end
  end

  describe "unknown event types" do
    test "ignores unknown event types" do
      event_data = %{
        "stripe_event_id" => "evt_unknown_123",
        "event_type" => "unknown.event.type",
        "event_data" => %{
          "object" => %{"id" => "test"}
        }
      }

      assert {:ok, :ignored} = WebhookProcessor.process_event(event_data)

      # Event should still be recorded for audit
      event = Repo.get_by(BillingEvent, stripe_event_id: "evt_unknown_123")
      assert event != nil
    end
  end
end
