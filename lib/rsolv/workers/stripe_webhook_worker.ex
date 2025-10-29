defmodule Rsolv.Workers.StripeWebhookWorker do
  @moduledoc """
  Oban worker for async Stripe webhook processing.

  Queues webhook events for processing with retry logic.
  Max attempts: 3 (pattern from RFC-065)
  """

  use Oban.Worker,
    queue: :webhooks,
    max_attempts: 3

  require Logger
  alias Rsolv.Billing.WebhookProcessor

  @impl Oban.Worker
  def perform(%Oban.Job{args: args}) do
    Logger.info("Processing Stripe webhook",
      event_type: args["event_type"],
      event_id: args["stripe_event_id"]
    )

    case WebhookProcessor.process_event(args) do
      {:ok, result} ->
        Logger.info("Webhook processed successfully",
          event_type: args["event_type"],
          result: result
        )

        :ok

      {:error, reason} ->
        Logger.error("Webhook processing failed",
          event_type: args["event_type"],
          reason: inspect(reason)
        )

        {:error, reason}
    end
  end
end
