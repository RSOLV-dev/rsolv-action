defmodule Rsolv.PromEx.BillingPlugin do
  @moduledoc """
  PromEx plugin for billing system metrics (RFC-068).

  This plugin tracks telemetry events for:
  - Subscription lifecycle (created, renewed, cancelled)
  - Payment processing (success, failure, amounts)
  - Usage tracking (fixes consumed, credit balance changes)
  - Customer conversions (trial → billing → Pro)

  ## Telemetry Events

  ### Subscription Events
  - `[:rsolv, :billing, :subscription_created]` - New subscription created
  - `[:rsolv, :billing, :subscription_renewed]` - Subscription renewed
  - `[:rsolv, :billing, :subscription_cancelled]` - Subscription cancelled

  ### Payment Events
  - `[:rsolv, :billing, :payment_processed]` - Payment processed (success/failure)
  - `[:rsolv, :billing, :invoice_paid]` - Invoice paid successfully
  - `[:rsolv, :billing, :invoice_failed]` - Invoice payment failed

  ### Webhook Events
  - `[:rsolv, :billing, :stripe_webhook_received]` - Stripe webhook received (success/failed)

  ### Usage Events
  - `[:rsolv, :billing, :usage_tracked]` - Fix usage tracked
  - `[:rsolv, :billing, :credits_added]` - Credits added to customer
  - `[:rsolv, :billing, :credits_consumed]` - Credits consumed

  ## Usage

  Add to your PromEx configuration:

      defmodule Rsolv.PromEx do
        use PromEx, otp_app: :rsolv

        @impl true
        def plugins do
          [
            # ... other plugins
            {Rsolv.PromEx.BillingPlugin, []}
          ]
        end
      end

  ## Emitting Events

      :telemetry.execute(
        [:rsolv, :billing, :subscription_created],
        %{amount: 4900, duration: 250},
        %{customer_id: "cus_123", plan: "pro", status: "success"}
      )
  """

  use PromEx.Plugin

  @impl true
  def event_metrics(_opts) do
    Event.build(
      :billing_metrics,
      [
        # Subscription lifecycle counters
        counter(
          [:rsolv, :billing, :subscription_created, :total],
          event_name: [:rsolv, :billing, :subscription_created],
          description: "Total subscriptions created",
          tags: [:customer_id, :plan, :status],
          tag_values: &extract_subscription_tags/1
        ),
        counter(
          [:rsolv, :billing, :subscription_renewed, :total],
          event_name: [:rsolv, :billing, :subscription_renewed],
          description: "Total subscriptions renewed",
          tags: [:customer_id, :plan, :status],
          tag_values: &extract_subscription_tags/1
        ),
        counter(
          [:rsolv, :billing, :subscription_cancelled, :total],
          event_name: [:rsolv, :billing, :subscription_cancelled],
          description: "Total subscriptions cancelled",
          tags: [:customer_id, :plan, :reason],
          tag_values: &extract_cancellation_tags/1
        ),

        # Payment processing counters
        counter(
          [:rsolv, :billing, :payment_processed, :total],
          event_name: [:rsolv, :billing, :payment_processed],
          description: "Total payments processed",
          tags: [:customer_id, :status, :payment_method],
          tag_values: &extract_payment_tags/1
        ),
        counter(
          [:rsolv, :billing, :invoice_paid, :total],
          event_name: [:rsolv, :billing, :invoice_paid],
          description: "Total invoices paid successfully",
          tags: [:customer_id, :plan],
          tag_values: &extract_base_tags/1
        ),
        counter(
          [:rsolv, :billing, :invoice_failed, :total],
          event_name: [:rsolv, :billing, :invoice_failed],
          description: "Total invoice payment failures",
          tags: [:customer_id, :failure_code],
          tag_values: &extract_failure_tags/1
        ),

        # Webhook counters
        counter(
          [:rsolv, :billing, :stripe_webhook_received, :total],
          event_name: [:rsolv, :billing, :stripe_webhook_received],
          description: "Total Stripe webhooks received",
          tags: [:event_type, :status],
          tag_values: &extract_webhook_tags/1
        ),
        counter(
          [:rsolv, :billing, :stripe_webhook_failed, :total],
          event_name: [:rsolv, :billing, :stripe_webhook_received],
          description: "Total Stripe webhook failures",
          tags: [:event_type, :failure_reason],
          tag_values: &extract_webhook_failure_tags/1
        ),

        # Usage tracking counters
        counter(
          [:rsolv, :billing, :usage_tracked, :total],
          event_name: [:rsolv, :billing, :usage_tracked],
          description: "Total usage events tracked",
          tags: [:customer_id, :plan, :resource_type],
          tag_values: &extract_usage_tags/1
        ),
        counter(
          [:rsolv, :billing, :credits_added, :total],
          event_name: [:rsolv, :billing, :credits_added],
          description: "Total credit additions",
          tags: [:customer_id, :reason],
          tag_values: &extract_credit_tags/1
        ),
        counter(
          [:rsolv, :billing, :credits_consumed, :total],
          event_name: [:rsolv, :billing, :credits_consumed],
          description: "Total credit consumptions",
          tags: [:customer_id, :plan],
          tag_values: &extract_base_tags/1
        ),

        # Payment amount distributions
        distribution(
          [:rsolv, :billing, :payment_processed, :amount, :cents],
          event_name: [:rsolv, :billing, :payment_processed],
          measurement: :amount_cents,
          description: "Payment amounts processed in cents",
          tags: [:customer_id, :status, :payment_method],
          tag_values: &extract_payment_tags_success/1,
          reporter_options: [buckets: [100, 500, 1500, 4900, 10_000, 50_000]]
        ),
        distribution(
          [:rsolv, :billing, :invoice_paid, :amount, :cents],
          event_name: [:rsolv, :billing, :invoice_paid],
          measurement: :amount_cents,
          description: "Invoice amounts paid in cents",
          tags: [:customer_id, :plan],
          tag_values: &extract_base_tags/1,
          reporter_options: [buckets: [100, 500, 1500, 4900, 10_000, 50_000]]
        ),

        # Duration distributions
        distribution(
          [:rsolv, :billing, :subscription_created, :duration, :milliseconds],
          event_name: [:rsolv, :billing, :subscription_created],
          measurement: :duration,
          description: "Subscription creation duration",
          tags: [:customer_id, :plan],
          tag_values: &extract_base_tags_success/1,
          unit: {:native, :millisecond},
          reporter_options: [buckets: [50, 100, 250, 500, 1000, 2000, 5000]]
        ),
        distribution(
          [:rsolv, :billing, :payment_processed, :duration, :milliseconds],
          event_name: [:rsolv, :billing, :payment_processed],
          measurement: :duration,
          description: "Payment processing duration",
          tags: [:customer_id, :payment_method],
          tag_values: &extract_payment_duration_tags/1,
          unit: {:native, :millisecond},
          reporter_options: [buckets: [100, 250, 500, 1000, 2000, 5000, 10_000]]
        ),

        # Usage quantity distributions
        distribution(
          [:rsolv, :billing, :usage_tracked, :quantity],
          event_name: [:rsolv, :billing, :usage_tracked],
          measurement: :quantity,
          description: "Usage quantities tracked",
          tags: [:customer_id, :plan, :resource_type],
          tag_values: &extract_usage_tags/1,
          reporter_options: [buckets: [1, 5, 10, 20, 50, 100]]
        ),
        distribution(
          [:rsolv, :billing, :credits_added, :quantity],
          event_name: [:rsolv, :billing, :credits_added],
          measurement: :quantity,
          description: "Credit quantities added",
          tags: [:customer_id, :reason],
          tag_values: &extract_credit_tags/1,
          reporter_options: [buckets: [5, 10, 60, 120]]
        ),

        # Webhook duration distributions
        distribution(
          [:rsolv, :billing, :stripe_webhook_received, :duration, :milliseconds],
          event_name: [:rsolv, :billing, :stripe_webhook_received],
          measurement: :duration,
          description: "Stripe webhook processing duration",
          tags: [:event_type, :status],
          tag_values: &extract_webhook_tags/1,
          unit: {:native, :millisecond},
          reporter_options: [buckets: [10, 50, 100, 250, 500, 1000, 5000]]
        )
      ]
    )
  end

  @impl true
  def polling_metrics(_opts), do: []

  @impl true
  def manual_metrics(_opts), do: []

  # Tag extraction functions

  defp extract_subscription_tags(metadata) do
    %{
      customer_id: to_string_safe(Map.get(metadata, :customer_id, "unknown")),
      plan: to_string_safe(Map.get(metadata, :plan, "unknown")),
      status: to_string_safe(Map.get(metadata, :status, "unknown"))
    }
  end

  defp extract_cancellation_tags(metadata) do
    %{
      customer_id: to_string_safe(Map.get(metadata, :customer_id, "unknown")),
      plan: to_string_safe(Map.get(metadata, :plan, "unknown")),
      reason: to_string_safe(Map.get(metadata, :reason, "customer_request"))
    }
  end

  defp extract_payment_tags(metadata) do
    %{
      customer_id: to_string_safe(Map.get(metadata, :customer_id, "unknown")),
      status: to_string_safe(Map.get(metadata, :status, "unknown")),
      payment_method: to_string_safe(Map.get(metadata, :payment_method, "card"))
    }
  end

  defp extract_payment_tags_success(metadata) do
    if Map.get(metadata, :status) == "success" do
      %{
        customer_id: to_string_safe(Map.get(metadata, :customer_id, "unknown")),
        status: "success",
        payment_method: to_string_safe(Map.get(metadata, :payment_method, "card"))
      }
    else
      :skip
    end
  end

  defp extract_payment_duration_tags(metadata) do
    %{
      customer_id: to_string_safe(Map.get(metadata, :customer_id, "unknown")),
      payment_method: to_string_safe(Map.get(metadata, :payment_method, "card"))
    }
  end

  defp extract_failure_tags(metadata) do
    %{
      customer_id: to_string_safe(Map.get(metadata, :customer_id, "unknown")),
      failure_code: to_string_safe(Map.get(metadata, :failure_code, "unknown"))
    }
  end

  defp extract_usage_tags(metadata) do
    %{
      customer_id: to_string_safe(Map.get(metadata, :customer_id, "unknown")),
      plan: to_string_safe(Map.get(metadata, :plan, "trial")),
      resource_type: to_string_safe(Map.get(metadata, :resource_type, "fix"))
    }
  end

  defp extract_credit_tags(metadata) do
    %{
      customer_id: to_string_safe(Map.get(metadata, :customer_id, "unknown")),
      reason: to_string_safe(Map.get(metadata, :reason, "other"))
    }
  end

  defp extract_base_tags(metadata) do
    %{
      customer_id: to_string_safe(Map.get(metadata, :customer_id, "unknown")),
      plan: to_string_safe(Map.get(metadata, :plan, "unknown"))
    }
  end

  defp extract_base_tags_success(metadata) do
    if Map.get(metadata, :status) == "success" do
      %{
        customer_id: to_string_safe(Map.get(metadata, :customer_id, "unknown")),
        plan: to_string_safe(Map.get(metadata, :plan, "unknown"))
      }
    else
      :skip
    end
  end

  defp extract_webhook_tags(metadata) do
    %{
      event_type: to_string_safe(Map.get(metadata, :event_type, "unknown")),
      status: to_string_safe(Map.get(metadata, :status, "unknown"))
    }
  end

  defp extract_webhook_failure_tags(metadata) do
    if Map.get(metadata, :status) == "failed" do
      %{
        event_type: to_string_safe(Map.get(metadata, :event_type, "unknown")),
        failure_reason: to_string_safe(Map.get(metadata, :failure_reason, "unknown"))
      }
    else
      :skip
    end
  end

  defp to_string_safe(value) when is_binary(value), do: value
  defp to_string_safe(value) when is_atom(value), do: Atom.to_string(value)
  defp to_string_safe(value) when is_integer(value), do: Integer.to_string(value)
  defp to_string_safe(_), do: "unknown"
end
