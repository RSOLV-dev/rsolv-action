defmodule RSOLV.RateLimiter do
  @moduledoc """
  Rate limiting for API requests.
  """
  
  require Logger
  
  # Simple counter using persistent_term for testing
  @table_key {__MODULE__, :counters}
  @window_key {__MODULE__, :windows}
  
  @doc """
  Checks if a customer has exceeded their rate limit.
  """
  def check_rate_limit(customer_id, action \\ "credential_exchange") do
    # Get current count and window
    key = "#{customer_id}:#{action}"
    current_time = System.system_time(:second)
    window_start = get_window_start(key)
    
    # If more than 60 seconds have passed, reset the counter
    if current_time - window_start > 60 do
      reset_counter(key)
    end
    
    count = get_count(key)
    
    # Rate limit: 100 requests per minute (10x increase)
    if count >= 100 do
      # Emit telemetry event for rate limit hit
      :telemetry.execute(
        [:rsolv, :rate_limiter, :limit_exceeded],
        %{count: 1},
        %{
          customer_id: customer_id,
          action: action,
          current_count: count,
          limit: 100
        }
      )
      
      Logger.warning("Rate limit exceeded for customer #{customer_id}, action: #{action}, count: #{count}")
      {:error, :rate_limited}
    else
      record_action(customer_id, action)
      
      # Emit telemetry event for successful request
      :telemetry.execute(
        [:rsolv, :rate_limiter, :request_allowed],
        %{count: 1, current_count: count + 1},
        %{
          customer_id: customer_id,
          action: action,
          limit: 100
        }
      )
      
      :ok
    end
  end
  
  @doc """
  Records an action for rate limiting.
  """
  def record_action(customer_id, action) do
    key = "#{customer_id}:#{action}"
    
    # Update counter
    counters = :persistent_term.get(@table_key, %{})
    current_count = Map.get(counters, key, 0)
    new_counters = Map.put(counters, key, current_count + 1)
    :persistent_term.put(@table_key, new_counters)
    
    # Update window start time if this is the first request
    if current_count == 0 do
      windows = :persistent_term.get(@window_key, %{})
      new_windows = Map.put(windows, key, System.system_time(:second))
      :persistent_term.put(@window_key, new_windows)
    end
    
    :ok
  end
  
  # Get current count for a key
  defp get_count(key) do
    counters = :persistent_term.get(@table_key, %{})
    Map.get(counters, key, 0)
  end
  
  # Get window start time for a key
  defp get_window_start(key) do
    windows = :persistent_term.get(@window_key, %{})
    Map.get(windows, key, System.system_time(:second))
  end
  
  # Reset counter for a key
  defp reset_counter(key) do
    # Reset counter
    counters = :persistent_term.get(@table_key, %{})
    new_counters = Map.delete(counters, key)
    :persistent_term.put(@table_key, new_counters)
    
    # Reset window
    windows = :persistent_term.get(@window_key, %{})
    new_windows = Map.delete(windows, key)
    :persistent_term.put(@window_key, new_windows)
  end
  
  @doc """
  Reset all counters (for testing).
  """
  def reset() do
    :persistent_term.put(@table_key, %{})
    :persistent_term.put(@window_key, %{})
    :ok
  end
end