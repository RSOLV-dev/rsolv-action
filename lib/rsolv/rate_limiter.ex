defmodule RSOLV.RateLimiter do
  @moduledoc """
  Rate limiting for API requests.
  """
  
  # Simple counter using persistent_term for testing
  @table_key {__MODULE__, :counters}
  
  @doc """
  Checks if a customer has exceeded their rate limit.
  """
  def check_rate_limit(customer_id, action \\ "credential_exchange") do
    # Get current count
    key = "#{customer_id}:#{action}"
    count = get_count(key)
    
    # Rate limit: 10 requests per minute for testing
    if count >= 10 do
      {:error, :rate_limited}
    else
      record_action(customer_id, action)
      :ok
    end
  end
  
  @doc """
  Records an action for rate limiting.
  """
  def record_action(customer_id, action) do
    key = "#{customer_id}:#{action}"
    counters = :persistent_term.get(@table_key, %{})
    current_count = Map.get(counters, key, 0)
    new_counters = Map.put(counters, key, current_count + 1)
    :persistent_term.put(@table_key, new_counters)
    :ok
  end
  
  # Get current count for a key
  defp get_count(key) do
    counters = :persistent_term.get(@table_key, %{})
    Map.get(counters, key, 0)
  end
  
  @doc """
  Reset all counters (for testing).
  """
  def reset() do
    :persistent_term.put(@table_key, %{})
    :ok
  end
end