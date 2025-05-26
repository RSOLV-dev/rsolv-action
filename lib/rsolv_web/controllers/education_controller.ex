defmodule RSOLVWeb.EducationController do
  use RSOLVWeb, :controller
  
  alias RSOLV.Notifications.SlackIntegration
  alias RSOLV.Notifications.SlackIntegration.FixAlert
  alias RSOLV.Notifications.EngagementTracker
  
  require Logger

  @doc """
  Receives a fix notification from RSOLV-action and triggers educational content generation.
  
  POST /api/education/fix-completed
  """
  def fix_completed(conn, %{
    "repo_name" => repo_name,
    "vulnerability" => vulnerability_data,
    "fix" => fix_data,
    "pr_url" => pr_url
  }) do
    # Extract vulnerability details
    vulnerability_type = vulnerability_data["type"]
    severity = String.to_atom(vulnerability_data["severity"] || "medium")
    
    # Calculate business impact
    impact_data = calculate_business_impact(vulnerability_type, severity)
    
    # Get organization stats (in production, fetch from database)
    stats = %{
      weekly_fixes: 12,
      security_posture_change: "+15% security posture"
    }
    
    # Create dashboard URL with tracking
    dashboard_url = generate_dashboard_url(repo_name, vulnerability_type)
    
    # Build the alert
    alert = %FixAlert{
      repo_name: repo_name,
      vulnerability_type: vulnerability_type,
      severity: severity,
      impact: impact_data.description,
      fix_summary: fix_data["summary"],
      dashboard_url: dashboard_url,
      pr_url: pr_url,
      stats: stats
    }
    
    # Send Slack notification
    case SlackIntegration.send_fix_alert(alert) do
      {:ok, _response} ->
        # In production, we'd also:
        # 1. Store the fix in our knowledge base
        # 2. Trigger async educational content generation
        # 3. Update team analytics
        
        json(conn, %{
          success: true,
          message: "Fix notification sent",
          dashboard_url: dashboard_url
        })
      
      {:error, :throttled} ->
        json(conn, %{
          success: true,
          message: "Fix recorded (notification throttled)",
          dashboard_url: dashboard_url,
          throttled: true
        })
      
      {:error, reason} ->
        Logger.error("Failed to send fix notification: #{inspect(reason)}")
        
        conn
        |> put_status(:internal_server_error)
        |> json(%{
          success: false,
          error: "Failed to send notification"
        })
    end
  end

  @doc """
  Track dashboard clicks from Slack
  
  GET /api/education/track-click/:alert_id
  """
  def track_click(conn, %{"alert_id" => alert_id}) do
    EngagementTracker.track_dashboard_click(alert_id, :os.system_time(:millisecond))
    
    # Redirect to the actual dashboard
    redirect(conn, external: "https://dashboard.rsolv.ai/fixes/#{alert_id}")
  end

  @doc """
  Get engagement metrics
  
  GET /api/education/metrics
  """
  def metrics(conn, %{"range" => range}) do
    time_range = String.to_atom(range)
    metrics = EngagementTracker.get_metrics(time_range)
    
    json(conn, metrics)
  end

  # Private functions

  defp calculate_business_impact("SQL Injection", :critical) do
    %{
      potential_loss: 4_450_000,
      description: "Could expose entire database ($4.45M average breach cost)",
      compliance: ["PCI-DSS", "GDPR", "SOC2"]
    }
  end

  defp calculate_business_impact("XSS", severity) when severity in [:critical, :high] do
    %{
      potential_loss: 2_200_000,
      description: "Could expose 50K customer records ($2.2M potential loss)",
      compliance: ["GDPR", "CCPA"]
    }
  end

  defp calculate_business_impact("Command Injection", _severity) do
    %{
      potential_loss: 3_800_000,
      description: "Could compromise entire infrastructure ($3.8M recovery cost)",
      compliance: ["SOC2", "ISO 27001"]
    }
  end

  defp calculate_business_impact(_type, :high) do
    %{
      potential_loss: 1_500_000,
      description: "Significant security risk ($1.5M potential impact)",
      compliance: ["General Security Best Practices"]
    }
  end

  defp calculate_business_impact(_type, _severity) do
    %{
      potential_loss: 500_000,
      description: "Security vulnerability fixed (prevents potential breach)",
      compliance: ["Security Best Practices"]
    }
  end

  defp generate_dashboard_url(repo_name, vulnerability_type) do
    # Include tracking parameters
    alert_id = :crypto.strong_rand_bytes(8) |> Base.encode16()
    
    "https://dashboard.rsolv.ai/learn?" <>
      "repo=#{URI.encode(repo_name)}&" <>
      "type=#{URI.encode(vulnerability_type)}&" <>
      "alert_id=#{alert_id}&" <>
      "source=slack"
  end
end