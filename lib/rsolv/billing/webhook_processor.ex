defmodule Rsolv.Billing.WebhookProcessor do
  @moduledoc """
  Process Stripe webhook events with idempotency.

  Idempotency: stripe_event_id unique constraint prevents duplicate processing.
  """

  require Logger
  alias Rsolv.Repo
  alias Rsolv.Billing.{BillingEvent, CreditLedger}
  alias Rsolv.Customers

  @doc """
  Process a Stripe webhook event.

  ## Parameters
  - event_data: Map with "stripe_event_id", "event_type", and "event_data" keys

  ## Returns
  - {:ok, :processed} - Event successfully processed
  - {:ok, :duplicate} - Event already processed (idempotency)
  - {:ok, :ignored} - Event type not relevant
  - {:error, reason} - Processing failed
  """
  def process_event(%{"stripe_event_id" => event_id, "event_type" => type, "event_data" => data}) do
    case Repo.get_by(BillingEvent, stripe_event_id: event_id) do
      nil ->
        # First time seeing this event
        handle_event(type, data)
        record_event(event_id, type, data)

      %BillingEvent{} ->
        # Already processed (Stripe sends duplicates)
        Logger.info("Duplicate webhook received", stripe_event_id: event_id)
        {:ok, :duplicate}
    end
  end

  # Pattern match on event types

  # invoice.payment_succeeded - Credits customer account for Pro subscription payments
  defp handle_event("invoice.payment_succeeded", %{"object" => invoice}) do
    customer = find_customer_by_stripe_id(invoice["customer"])

    # Pro subscription payment → Credit 60 fixes
    if invoice["lines"]["data"] |> Enum.any?(&pro_subscription?/1) do
      CreditLedger.credit(customer, 60,
        source: "pro_subscription_payment",
        metadata: %{
          stripe_invoice_id: invoice["id"],
          amount_cents: invoice["amount_paid"]
        }
      )

      Logger.info("Pro subscription payment processed",
        customer_id: customer.id,
        credits_added: 60,
        stripe_invoice_id: invoice["id"]
      )
    end

    {:ok, :processed}
  end

  # invoice.payment_failed - Handle failed payments
  defp handle_event("invoice.payment_failed", %{"object" => invoice}) do
    customer = find_customer_by_stripe_id(invoice["customer"])

    # Update subscription state to past_due
    Customers.update_customer(customer, %{
      subscription_state: "past_due"
    })

    # TODO: Send email notification, trigger dunning process
    Logger.warning("Payment failed for customer",
      customer_id: customer.id,
      stripe_invoice_id: invoice["id"],
      amount: invoice["amount_due"]
    )

    {:ok, :processed}
  end

  # customer.subscription.created - Record new subscription
  defp handle_event("customer.subscription.created", %{"object" => subscription}) do
    customer = find_customer_by_stripe_id(subscription["customer"])

    Customers.update_customer(customer, %{
      stripe_subscription_id: subscription["id"],
      subscription_type: "pro",
      subscription_state: subscription["status"]
    })

    Logger.info("Subscription created",
      customer_id: customer.id,
      stripe_subscription_id: subscription["id"],
      status: subscription["status"]
    )

    {:ok, :processed}
  end

  # customer.subscription.deleted - Downgrade to PAYG
  defp handle_event("customer.subscription.deleted", %{"object" => subscription}) do
    customer = find_customer_by_stripe_id(subscription["customer"])

    # Downgrade to PAYG, preserve existing credits
    Customers.update_customer(customer, %{
      subscription_type: "pay_as_you_go",
      subscription_state: nil,
      stripe_subscription_id: nil,
      subscription_cancel_at_period_end: false
    })

    Logger.info("Subscription canceled, downgraded to PAYG",
      customer_id: customer.id,
      stripe_subscription_id: subscription["id"],
      credits_remaining: customer.credit_balance
    )

    {:ok, :processed}
  end

  # customer.subscription.updated - Handle status/cancellation changes
  defp handle_event("customer.subscription.updated", %{"object" => subscription}) do
    customer = find_customer_by_stripe_id(subscription["customer"])

    # Update subscription state from Stripe
    attrs = %{subscription_state: subscription["status"]}

    attrs =
      if subscription["cancel_at_period_end"] do
        Logger.info("Subscription scheduled for cancellation at period end",
          customer_id: customer.id,
          period_end: subscription["current_period_end"]
        )

        Map.put(attrs, :subscription_cancel_at_period_end, true)
      else
        attrs
      end

    Customers.update_customer(customer, attrs)

    {:ok, :processed}
  end

  # Ignore unknown event types
  defp handle_event(type, _data) do
    Logger.debug("Ignoring webhook event type: #{type}")
    {:ok, :ignored}
  end

  # Record event for idempotency and audit trail
  defp record_event(event_id, type, data) do
    %BillingEvent{}
    |> BillingEvent.changeset(%{
      stripe_event_id: event_id,
      event_type: type,
      customer_id: extract_customer_id(data),
      amount_cents: extract_amount(data),
      metadata: data
    })
    |> Repo.insert()
  end

  # Check if line item is for Pro subscription
  defp pro_subscription?(line_item) do
    # Check both metadata and price lookup key
    metadata_plan = get_in(line_item, ["price", "metadata", "plan"])
    lookup_key = get_in(line_item, ["price", "lookup_key"])

    metadata_plan == "pro" || lookup_key == "pro_monthly"
  end

  # Find customer by Stripe customer ID
  defp find_customer_by_stripe_id(stripe_customer_id) do
    Customers.get_customer_by_stripe_id!(stripe_customer_id)
  end

  # Extract customer ID for event recording
  defp extract_customer_id(%{"object" => %{"customer" => stripe_id}}) when is_binary(stripe_id) do
    customer = find_customer_by_stripe_id(stripe_id)
    customer.id
  end

  defp extract_customer_id(_), do: nil

  # Extract amount for event recording
  defp extract_amount(%{"object" => %{"amount_paid" => amount}}), do: amount
  defp extract_amount(%{"object" => %{"amount_due" => amount}}), do: amount
  defp extract_amount(_), do: nil
end
