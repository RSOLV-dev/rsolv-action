defmodule RSOLV.Notifications.SlackIntegration do
  @moduledoc """
  Handles Slack notifications for RSOLV fixes with intelligent throttling
  and engagement tracking.
  """

  require Logger
  alias RSOLV.Notifications.AlertThrottle
  alias RSOLV.Notifications.EngagementTracker

  @max_daily_alerts 3
  @webhook_url_key "SLACK_WEBHOOK_URL"

  defmodule FixAlert do
    @enforce_keys [:repo_name, :vulnerability_type, :severity, :impact, :fix_summary, :dashboard_url]
    defstruct [:repo_name, :vulnerability_type, :severity, :impact, :fix_summary, :dashboard_url, :pr_url, :stats]
  end

  @doc """
  Sends a fix alert to Slack if within daily throttle limits.
  Returns {:ok, message_id} or {:error, reason}
  """
  def send_fix_alert(%FixAlert{} = alert) do
    Logger.info("Starting send_fix_alert for #{alert.repo_name}")
    
    with {:ok, _} <- check_throttle(alert.repo_name),
         {:ok, message} <- format_alert_message(alert),
         {:ok, response} <- post_to_slack(message),
         {:ok, _} <- track_engagement(alert, response) do
      Logger.info("Successfully sent Slack alert")
      {:ok, response}
    else
      {:error, :throttle_exceeded} ->
        Logger.info("Slack alert throttled for #{alert.repo_name}")
        {:error, :throttled}
      
      error ->
        Logger.error("Failed to send Slack alert: #{inspect(error)}")
        error
    end
  rescue
    e ->
      Logger.error("Exception in send_fix_alert: #{inspect(e)}")
      {:error, e}
  end

  @doc """
  Sends a weekly digest of all fixes
  """
  def send_weekly_digest(org_id, fixes_summary) do
    message = format_weekly_digest(org_id, fixes_summary)
    post_to_slack(message)
  end

  defp check_throttle(repo_name) do
    case AlertThrottle.can_send_alert?(repo_name, @max_daily_alerts) do
      true -> {:ok, :allowed}
      false -> {:error, :throttle_exceeded}
    end
  end

  defp format_alert_message(%FixAlert{} = alert) do
    severity_emoji = case alert.severity do
      :critical -> "🚨"
      :high -> "🔴"
      :medium -> "🟡"
      :low -> "🟢"
    end

    blocks = [
      %{
        type: "header",
        text: %{
          type: "plain_text",
          text: "🔐 RSOLV Security Fix Alert"
        }
      },
      %{
        type: "section",
        text: %{
          type: "mrkdwn",
          text: "*#{severity_emoji} #{String.capitalize(to_string(alert.severity))} #{alert.vulnerability_type} Fixed* in `#{alert.repo_name}`"
        }
      },
      %{
        type: "section",
        fields: [
          %{
            type: "mrkdwn",
            text: "*📊 Impact:*\\n#{alert.impact}"
          },
          %{
            type: "mrkdwn",
            text: "*🛡️ Protection:*\\n#{alert.fix_summary}"
          }
        ]
      },
      %{
        type: "actions",
        elements: [
          %{
            type: "button",
            text: %{
              type: "plain_text",
              text: "📚 Learn More"
            },
            url: alert.dashboard_url,
            action_id: "learn_more_#{:os.system_time(:millisecond)}"
          }
        ]
      }
    ]

    # Add PR link if available
    blocks = if alert.pr_url do
      blocks ++ [
        %{
          type: "section",
          text: %{
            type: "mrkdwn",
            text: "*Pull Request:* <#{alert.pr_url}|View PR>"
          }
        }
      ]
    else
      blocks
    end

    # Add stats if available
    blocks = if alert.stats do
      blocks ++ [
        %{
          type: "context",
          elements: [
            %{
              type: "mrkdwn",
              text: "_Your team has fixed #{alert.stats.weekly_fixes} vulnerabilities this week (#{alert.stats.security_posture_change})_"
            }
          ]
        }
      ]
    else
      blocks
    end

    {:ok, %{blocks: blocks}}
  end

  defp format_weekly_digest(_org_id, summary) do
    %{
      blocks: [
        %{
          type: "header",
          text: %{
            type: "plain_text",
            text: "📊 Weekly Security Summary"
          }
        },
        %{
          type: "section",
          text: %{
            type: "mrkdwn",
            text: """
            *Vulnerabilities Fixed:* #{summary.total_fixes}
            *Critical Issues:* #{summary.critical_count}
            *Most Common:* #{summary.top_vulnerability_type}
            *Security Posture:* #{summary.posture_trend}
            """
          }
        },
        %{
          type: "actions",
          elements: [
            %{
              type: "button",
              text: %{
                type: "plain_text",
                text: "View Full Report"
              },
              url: summary.dashboard_url
            }
          ]
        }
      ]
    }
  end

  defp post_to_slack(message) do
    webhook_url = System.get_env(@webhook_url_key)
    
    if webhook_url do
      headers = [{"Content-Type", "application/json"}]
      body = Jason.encode!(message)
      
      case HTTPoison.post(webhook_url, body, headers) do
        {:ok, %HTTPoison.Response{status_code: 200}} ->
          {:ok, %{timestamp: :os.system_time(:millisecond)}}
        
        {:ok, %HTTPoison.Response{status_code: status_code, body: body}} ->
          {:error, "Slack API error: #{status_code} - #{body}"}
        
        {:error, %HTTPoison.Error{reason: reason}} ->
          {:error, "HTTP error: #{reason}"}
      end
    else
      Logger.warning("Slack webhook URL not configured")
      {:error, :webhook_not_configured}
    end
  end

  defp track_engagement(alert, response) do
    EngagementTracker.track_alert_sent(
      alert.repo_name,
      alert.vulnerability_type,
      response.timestamp
    )
  end
end