defmodule RSOLV.Notifications.AlertThrottle do
  @moduledoc """
  Manages alert throttling to prevent notification fatigue.
  Uses the existing rsolv_cache for distributed throttle management.
  """

  # Use the existing cache instead of creating a new one
  @cache_name :rsolv_cache
  @ttl :timer.hours(24)

  @doc """
  Checks if an alert can be sent for the given repository.
  Returns true if under the limit, false otherwise.
  """
  def can_send_alert?(repo_name, max_daily_alerts) do
    key = daily_key(repo_name)
    
    case Cachex.get(@cache_name, key) do
      {:ok, nil} ->
        # First alert of the day
        Cachex.put(@cache_name, key, 1)
        true
      
      {:ok, count} when count < max_daily_alerts ->
        # Under the limit
        Cachex.incr(@cache_name, key)
        true
      
      {:ok, _count} ->
        # Over the limit
        false
      
      {:error, _} ->
        # Cache error, allow the alert but log
        require Logger
        Logger.error("Alert throttle cache error for #{repo_name}")
        true
    end
  end

  @doc """
  Gets the current alert count for a repository today.
  """
  def get_daily_count(repo_name) do
    key = daily_key(repo_name)
    
    case Cachex.get(@cache_name, key) do
      {:ok, nil} -> 0
      {:ok, count} -> count
      {:error, _} -> 0
    end
  end

  @doc """
  Resets the daily count for a repository (useful for testing).
  """
  def reset_daily_count(repo_name) do
    key = daily_key(repo_name)
    Cachex.del(@cache_name, key)
  end

  defp daily_key(repo_name) do
    date = Date.utc_today() |> Date.to_string()
    "alert_throttle:#{repo_name}:#{date}"
  end
end