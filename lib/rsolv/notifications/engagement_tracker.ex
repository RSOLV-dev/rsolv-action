defmodule Rsolv.Notifications.EngagementTracker do
  @moduledoc """
  Tracks engagement metrics for notifications to optimize delivery
  and measure educational impact.
  """

  use GenServer
  require Logger

  # Client API

  def start_link(opts) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Track that an alert was sent
  """
  def track_alert_sent(repo_name, vulnerability_type, timestamp) do
    GenServer.cast(__MODULE__, {:alert_sent, repo_name, vulnerability_type, timestamp})
  end

  @doc """
  Track that a user clicked through to the dashboard
  """
  def track_dashboard_click(alert_id, timestamp) do
    GenServer.cast(__MODULE__, {:dashboard_click, alert_id, timestamp})
  end

  @doc """
  Get engagement metrics for reporting
  """
  def get_metrics(time_range \\ :week) do
    GenServer.call(__MODULE__, {:get_metrics, time_range})
  end

  # Server Callbacks

  def init(_opts) do
    # In production, this would persist to database
    # For now, we'll use in-memory state
    state = %{
      alerts_sent: [],
      dashboard_clicks: [],
      metrics_cache: %{}
    }
    
    # Schedule periodic metrics calculation
    Process.send_after(self(), :calculate_metrics, :timer.minutes(5))
    
    {:ok, state}
  end

  def handle_cast({:alert_sent, repo_name, vulnerability_type, timestamp}, state) do
    alert = %{
      id: generate_alert_id(),
      repo_name: repo_name,
      vulnerability_type: vulnerability_type,
      timestamp: timestamp,
      clicked: false
    }
    
    new_state = %{state | alerts_sent: [alert | state.alerts_sent]}
    {:noreply, new_state}
  end

  def handle_cast({:dashboard_click, alert_id, timestamp}, state) do
    click = %{
      alert_id: alert_id,
      timestamp: timestamp
    }
    
    # Update the alert as clicked
    updated_alerts = Enum.map(state.alerts_sent, fn alert ->
      if alert.id == alert_id do
        %{alert | clicked: true}
      else
        alert
      end
    end)
    
    new_state = %{
      state | 
      alerts_sent: updated_alerts,
      dashboard_clicks: [click | state.dashboard_clicks]
    }
    
    {:noreply, new_state}
  end

  def handle_call({:get_metrics, time_range}, _from, state) do
    metrics = calculate_metrics_for_range(state, time_range)
    {:reply, metrics, state}
  end

  def handle_info(:calculate_metrics, state) do
    # Calculate and cache common metrics
    weekly_metrics = calculate_metrics_for_range(state, :week)
    daily_metrics = calculate_metrics_for_range(state, :day)
    
    new_cache = %{
      week: weekly_metrics,
      day: daily_metrics,
      updated_at: DateTime.utc_now()
    }
    
    # Schedule next calculation
    Process.send_after(self(), :calculate_metrics, :timer.minutes(5))
    
    {:noreply, %{state | metrics_cache: new_cache}}
  end

  # Private Functions

  defp generate_alert_id do
    "alert_#{:crypto.strong_rand_bytes(8) |> Base.encode16()}"
  end

  defp calculate_metrics_for_range(state, time_range) do
    cutoff_time = get_cutoff_time(time_range)
    
    recent_alerts = Enum.filter(state.alerts_sent, fn alert ->
      alert.timestamp > cutoff_time
    end)
    
    total_sent = length(recent_alerts)
    total_clicked = Enum.count(recent_alerts, & &1.clicked)
    
    click_rate = if total_sent > 0 do
      Float.round(total_clicked / total_sent * 100, 1)
    else
      0.0
    end
    
    # Group by vulnerability type
    by_type = recent_alerts
    |> Enum.group_by(& &1.vulnerability_type)
    |> Enum.map(fn {type, alerts} -> 
      {type, length(alerts)}
    end)
    |> Enum.sort_by(fn {_type, count} -> -count end)
    
    %{
      total_alerts_sent: total_sent,
      total_clicks: total_clicked,
      click_through_rate: click_rate,
      alerts_by_type: by_type,
      time_range: time_range,
      calculated_at: DateTime.utc_now()
    }
  end

  defp get_cutoff_time(:day) do
    :os.system_time(:millisecond) - :timer.hours(24)
  end

  defp get_cutoff_time(:week) do
    :os.system_time(:millisecond) - :timer.hours(24 * 7)
  end

  defp get_cutoff_time(:month) do
    :os.system_time(:millisecond) - :timer.hours(24 * 30)
  end
end