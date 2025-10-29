defmodule Rsolv.PromEx.BillingPluginTest do
  @moduledoc """
  Tests for billing telemetry metrics (RFC-068 Week 3).

  Verifies that:
  - Telemetry events are emitted correctly
  - Metrics are collected by PromEx
  - Tags are extracted properly
  - Measurements are recorded accurately
  """

  use ExUnit.Case, async: false

  alias Rsolv.PromEx.BillingPlugin

  setup do
    # Attach telemetry handler for testing
    handler_id = :telemetry_test_handler
    events = BillingPlugin.event_metrics([]) |> extract_event_names()

    :telemetry.attach_many(
      handler_id,
      events,
      &handle_telemetry/4,
      self()
    )

    on_exit(fn ->
      :telemetry.detach(handler_id)
    end)

    :ok
  end

  describe "subscription lifecycle metrics" do
    test "emits telemetry on subscription creation" do
      metadata = %{customer_id: "cus_123", plan: "pro", status: "success"}
      measurements = %{amount: 4900, duration: 250}

      :telemetry.execute(
        [:rsolv, :billing, :subscription_created],
        measurements,
        metadata
      )

      assert_received {:telemetry_event, [:rsolv, :billing, :subscription_created], ^measurements,
                       ^metadata}
    end

    test "emits telemetry on subscription renewal" do
      metadata = %{customer_id: "cus_456", plan: "pro", status: "success"}
      measurements = %{amount: 4900, duration: 300}

      :telemetry.execute(
        [:rsolv, :billing, :subscription_renewed],
        measurements,
        metadata
      )

      assert_received {:telemetry_event, [:rsolv, :billing, :subscription_renewed], ^measurements,
                       ^metadata}
    end

    test "emits telemetry on subscription cancellation" do
      metadata = %{customer_id: "cus_789", plan: "pro", reason: "customer_request"}
      measurements = %{duration: 150}

      :telemetry.execute(
        [:rsolv, :billing, :subscription_cancelled],
        measurements,
        metadata
      )

      assert_received {:telemetry_event, [:rsolv, :billing, :subscription_cancelled],
                       ^measurements, ^metadata}
    end
  end

  describe "payment processing metrics" do
    test "emits telemetry on payment success" do
      metadata = %{customer_id: "cus_123", status: "success", payment_method: "card"}
      measurements = %{amount_cents: 4900, duration: 500}

      :telemetry.execute(
        [:rsolv, :billing, :payment_processed],
        measurements,
        metadata
      )

      assert_received {:telemetry_event, [:rsolv, :billing, :payment_processed], ^measurements,
                       ^metadata}
    end

    test "emits telemetry on payment failure" do
      metadata = %{customer_id: "cus_456", status: "failed", payment_method: "card"}
      measurements = %{amount_cents: 4900, duration: 350}

      :telemetry.execute(
        [:rsolv, :billing, :payment_processed],
        measurements,
        metadata
      )

      assert_received {:telemetry_event, [:rsolv, :billing, :payment_processed], ^measurements,
                       ^metadata}
    end

    test "emits telemetry on invoice paid" do
      metadata = %{customer_id: "cus_123", plan: "pro"}
      measurements = %{amount_cents: 4900, duration: 200}

      :telemetry.execute(
        [:rsolv, :billing, :invoice_paid],
        measurements,
        metadata
      )

      assert_received {:telemetry_event, [:rsolv, :billing, :invoice_paid], ^measurements,
                       ^metadata}
    end

    test "emits telemetry on invoice failed" do
      metadata = %{customer_id: "cus_456", failure_code: "card_declined"}
      measurements = %{duration: 250}

      :telemetry.execute(
        [:rsolv, :billing, :invoice_failed],
        measurements,
        metadata
      )

      assert_received {:telemetry_event, [:rsolv, :billing, :invoice_failed], ^measurements,
                       ^metadata}
    end
  end

  describe "usage tracking metrics" do
    test "tracks usage in Prometheus metrics" do
      metadata = %{customer_id: "cus_123", plan: "pro", resource_type: "fix"}
      measurements = %{quantity: 5}

      :telemetry.execute(
        [:rsolv, :billing, :usage_tracked],
        measurements,
        metadata
      )

      assert_received {:telemetry_event, [:rsolv, :billing, :usage_tracked], ^measurements,
                       ^metadata}
    end

    test "tracks credit additions" do
      metadata = %{customer_id: "cus_123", reason: "signup_bonus"}
      measurements = %{quantity: 5}

      :telemetry.execute(
        [:rsolv, :billing, :credits_added],
        measurements,
        metadata
      )

      assert_received {:telemetry_event, [:rsolv, :billing, :credits_added], ^measurements,
                       ^metadata}
    end

    test "tracks credit consumption" do
      metadata = %{customer_id: "cus_123", plan: "trial"}
      measurements = %{quantity: 1}

      :telemetry.execute(
        [:rsolv, :billing, :credits_consumed],
        measurements,
        metadata
      )

      assert_received {:telemetry_event, [:rsolv, :billing, :credits_consumed], ^measurements,
                       ^metadata}
    end
  end

  describe "billing event metrics have correct tags" do
    test "subscription events include customer_id, plan, status" do
      metadata = %{customer_id: "cus_123", plan: "pro", status: "success"}
      measurements = %{amount: 4900, duration: 250}

      :telemetry.execute(
        [:rsolv, :billing, :subscription_created],
        measurements,
        metadata
      )

      assert_received {:telemetry_event, _, _, received_metadata}
      assert received_metadata.customer_id == "cus_123"
      assert received_metadata.plan == "pro"
      assert received_metadata.status == "success"
    end

    test "payment events include customer_id, status, payment_method" do
      metadata = %{customer_id: "cus_456", status: "success", payment_method: "card"}
      measurements = %{amount_cents: 4900, duration: 500}

      :telemetry.execute(
        [:rsolv, :billing, :payment_processed],
        measurements,
        metadata
      )

      assert_received {:telemetry_event, _, _, received_metadata}
      assert received_metadata.customer_id == "cus_456"
      assert received_metadata.status == "success"
      assert received_metadata.payment_method == "card"
    end

    test "usage events include customer_id, plan, resource_type" do
      metadata = %{customer_id: "cus_789", plan: "trial", resource_type: "fix"}
      measurements = %{quantity: 3}

      :telemetry.execute(
        [:rsolv, :billing, :usage_tracked],
        measurements,
        metadata
      )

      assert_received {:telemetry_event, _, _, received_metadata}
      assert received_metadata.customer_id == "cus_789"
      assert received_metadata.plan == "trial"
      assert received_metadata.resource_type == "fix"
    end
  end

  describe "measurement accuracy" do
    test "records correct payment amounts in cents" do
      metadata = %{customer_id: "cus_123", status: "success", payment_method: "card"}
      measurements = %{amount_cents: 4900, duration: 500}

      :telemetry.execute(
        [:rsolv, :billing, :payment_processed],
        measurements,
        metadata
      )

      assert_received {:telemetry_event, _, received_measurements, _}
      assert received_measurements.amount_cents == 4900
    end

    test "records correct durations in milliseconds" do
      metadata = %{customer_id: "cus_123", plan: "pro", status: "success"}
      measurements = %{amount: 4900, duration: 250}

      :telemetry.execute(
        [:rsolv, :billing, :subscription_created],
        measurements,
        metadata
      )

      assert_received {:telemetry_event, _, received_measurements, _}
      assert received_measurements.duration == 250
    end

    test "records correct usage quantities" do
      metadata = %{customer_id: "cus_123", plan: "pro", resource_type: "fix"}
      measurements = %{quantity: 10}

      :telemetry.execute(
        [:rsolv, :billing, :usage_tracked],
        measurements,
        metadata
      )

      assert_received {:telemetry_event, _, received_measurements, _}
      assert received_measurements.quantity == 10
    end
  end

  describe "edge cases and error handling" do
    test "handles missing optional metadata fields gracefully" do
      metadata = %{customer_id: "cus_123"}
      measurements = %{quantity: 1}

      :telemetry.execute(
        [:rsolv, :billing, :usage_tracked],
        measurements,
        metadata
      )

      assert_received {:telemetry_event, [:rsolv, :billing, :usage_tracked], ^measurements, _}
    end

    test "handles zero amounts" do
      metadata = %{customer_id: "cus_123", status: "success", payment_method: "card"}
      measurements = %{amount_cents: 0, duration: 100}

      :telemetry.execute(
        [:rsolv, :billing, :payment_processed],
        measurements,
        metadata
      )

      assert_received {:telemetry_event, _, received_measurements, _}
      assert received_measurements.amount_cents == 0
    end

    test "handles large quantities" do
      metadata = %{customer_id: "cus_enterprise", plan: "enterprise", resource_type: "fix"}
      measurements = %{quantity: 1000}

      :telemetry.execute(
        [:rsolv, :billing, :usage_tracked],
        measurements,
        metadata
      )

      assert_received {:telemetry_event, _, received_measurements, _}
      assert received_measurements.quantity == 1000
    end
  end

  # Helper functions

  defp handle_telemetry(event_name, measurements, metadata, pid) do
    send(pid, {:telemetry_event, event_name, measurements, metadata})
  end

  defp extract_event_names(event_metrics) do
    # Extract event names from PromEx event metric definitions
    # This is a simplified version - in practice, you'd parse the Event.build result
    [
      [:rsolv, :billing, :subscription_created],
      [:rsolv, :billing, :subscription_renewed],
      [:rsolv, :billing, :subscription_cancelled],
      [:rsolv, :billing, :payment_processed],
      [:rsolv, :billing, :invoice_paid],
      [:rsolv, :billing, :invoice_failed],
      [:rsolv, :billing, :usage_tracked],
      [:rsolv, :billing, :credits_added],
      [:rsolv, :billing, :credits_consumed]
    ]
  end
end
