defmodule Rsolv.Workers.EmailWorker do
  @moduledoc """
  Oban worker for processing scheduled emails in the email sequence.

  This worker replaces the file-based scheduling system with a persistent
  database-backed job queue that survives system restarts.
  """
  use Oban.Worker,
    queue: :emails,
    max_attempts: 3

  require Logger
  alias Rsolv.EmailService

  @impl Oban.Worker
  def perform(%Oban.Job{args: args}) do
    %{
      "email" => email,
      "template" => template,
      "first_name" => first_name,
      "sequence" => sequence
    } = args

    Logger.info("Processing scheduled email",
      metadata: %{
        email: email,
        template: template,
        sequence: sequence
      }
    )

    # Send the appropriate email based on template
    result =
      case template do
        "welcome" ->
          EmailService.send_welcome_email(email, first_name)

        "early_access_welcome" ->
          EmailService.send_early_access_welcome_email(email, first_name)

        "getting_started" ->
          EmailService.send_getting_started_email(email, first_name)

        "setup_verification" ->
          EmailService.send_setup_verification_email(email, first_name)

        "first_issue" ->
          EmailService.send_first_issue_email(email, first_name)

        "feature_deep_dive" ->
          EmailService.send_feature_deep_dive_email(email, first_name)

        "feedback_request" ->
          EmailService.send_feedback_request_email(email, first_name)

        "success_checkin" ->
          # Get usage stats if available
          usage_stats =
            Map.get(args, "usage_stats", %{
              "issues_fixed" => 0,
              "prs_created" => 0,
              "time_saved" => "0 hours"
            })

          EmailService.send_success_checkin_email(email, first_name, usage_stats)

        "early_access_guide" ->
          # This one needs to be implemented
          {:error, "early_access_guide template not implemented"}

        _ ->
          Logger.error("Unknown email template",
            metadata: %{
              template: template,
              email: email
            }
          )

          {:error, "Unknown template: #{template}"}
      end

    case result do
      {:ok, _} ->
        Logger.info("Successfully sent scheduled email",
          metadata: %{
            email: email,
            template: template
          }
        )

        :ok

      {:error, reason} ->
        Logger.error("Failed to send scheduled email",
          metadata: %{
            email: email,
            template: template,
            error: inspect(reason)
          }
        )

        {:error, reason}
    end
  end

  @doc """
  Schedule an email to be sent at a specific time.

  ## Examples

      EmailWorker.schedule_email(
        "user@example.com",
        "welcome",
        "User",
        :onboarding,
        scheduled_at: ~U[2025-05-28 12:00:00Z]
      )
  """
  def schedule_email(email, template, first_name, sequence, opts \\ []) do
    scheduled_at = Keyword.get(opts, :scheduled_at, DateTime.utc_now())

    args = %{
      email: email,
      template: template,
      first_name: first_name || "there",
      sequence: to_string(sequence)
    }

    Logger.info("[EmailWorker] Creating Oban job",
      args: inspect(args),
      queue: :emails,
      scheduled_at: scheduled_at
    )

    job =
      Oban.Job.new(
        args,
        queue: :emails,
        scheduled_at: scheduled_at,
        worker: __MODULE__
      )

    Logger.info("[EmailWorker] Job created",
      job: inspect(job)
    )

    result = Oban.insert(job)

    Logger.info("[EmailWorker] Insert result",
      result: inspect(result)
    )

    result
  end

  @doc """
  Schedule all emails in a sequence.

  ## Examples

      EmailWorker.schedule_sequence("user@example.com", "User", :early_access_onboarding)
  """
  def schedule_sequence(email, first_name, sequence_name) do
    alias RsolvWeb.Services.EmailSequence

    Logger.info("[EmailWorker] schedule_sequence called",
      email: email,
      first_name: first_name,
      sequence_name: sequence_name
    )

    sequences = EmailSequence.sequences()
    sequence = Map.get(sequences, sequence_name)

    Logger.info("[EmailWorker] Found sequence",
      sequence_name: sequence_name,
      sequence_exists: sequence != nil,
      sequence_length: if(sequence, do: length(sequence), else: 0)
    )

    if sequence do
      # Schedule each email in the sequence
      results =
        Enum.map(sequence, fn email_config ->
          Logger.info("[EmailWorker] Processing email config",
            email_config: inspect(email_config)
          )

          # Skip immediate emails (day 0) as they're sent directly
          if email_config.days > 0 do
            scheduled_at = DateTime.add(DateTime.utc_now(), email_config.days * 86400, :second)

            Logger.info("[EmailWorker] Scheduling email",
              template: email_config.template,
              days: email_config.days,
              scheduled_at: scheduled_at
            )

            result =
              schedule_email(
                email,
                email_config.template,
                first_name,
                sequence_name,
                scheduled_at: scheduled_at
              )

            Logger.info("[EmailWorker] Schedule result",
              result: inspect(result)
            )

            result
          else
            Logger.info("[EmailWorker] Skipping immediate email",
              template: email_config.template
            )

            {:ok, :skipped}
          end
        end)

      {:ok, results}
    else
      {:error, "Unknown sequence: #{sequence_name}"}
    end
  end
end
