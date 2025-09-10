defmodule Rsolv.RateLimiter do
  @moduledoc """
  Rate limiting for API requests using distributed Mnesia.
  
  Uses Mnesia for strong consistency across all nodes in the cluster,
  eliminating race conditions that existed with the ETS + sync approach.
  """
  
  use GenServer
  require Logger
  
  @table_name :rsolv_rate_limiter
  @window_seconds 60
  
  def start_link(opts) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end
  
  def init(_opts) do
    # Setup Mnesia schema and table
    setup_mnesia()
    
    {:ok, %{}}
  end
  
  defp setup_mnesia do
    # Ensure Mnesia is started
    case :mnesia.system_info(:is_running) do
      :no -> :mnesia.start()
      _ -> :ok
    end
    
    # Create schema if needed (for all connected nodes)
    nodes = [node() | Node.list()]
    case :mnesia.create_schema(nodes) do
      :ok -> 
        Logger.info("Created Mnesia schema on nodes: #{inspect(nodes)}")
      {:error, {_, {:already_exists, _}}} -> 
        :ok
      error -> 
        Logger.warning("Failed to create Mnesia schema: #{inspect(error)}")
    end
    
    # Create rate limiter table (use ram_copies in test environment)
    storage_type = if Mix.env() == :test, do: :ram_copies, else: :disc_copies
    
    table_opts = [
      {:attributes, [:key, :count, :window_start]},
      {storage_type, nodes},
      {:type, :set}
    ]
    
    case :mnesia.create_table(@table_name, table_opts) do
      {:atomic, :ok} -> 
        Logger.info("Created Mnesia rate limiter table")
      {:aborted, {:already_exists, @table_name}} -> 
        :ok
      error -> 
        Logger.error("Failed to create Mnesia table: #{inspect(error)}")
    end
    
    # Wait for table to be ready
    :mnesia.wait_for_tables([@table_name], 5000)
  end
  
  @doc """
  Checks if a customer has exceeded their rate limit.
  Uses Mnesia transactions for distributed consistency.
  """
  def check_rate_limit(customer_id, action \\ :credential_exchange) do
    # Normalize action for both key and config lookup
    action_normalized = normalize_action(action)
    key = {customer_id, action_normalized}
    current_time = System.system_time(:second)
    
    # Get rate limit from config
    {limit, _period} = get_rate_limit_config(action_normalized)
    
    # Use Mnesia transaction for consistency
    result = :mnesia.transaction(fn ->
      case :mnesia.read(@table_name, key) do
        [{@table_name, ^key, count, window_start}] ->
          # If more than 60 seconds have passed, reset the counter
          if current_time - window_start > @window_seconds do
            :mnesia.write({@table_name, key, 1, current_time})
            emit_allowed_telemetry(customer_id, action, 1, limit)
            :ok
          else
            # Check against rate limit
            if count >= limit do
              emit_exceeded_telemetry(customer_id, action, count, limit)
              Logger.warning("Rate limit exceeded for customer #{customer_id}, action: #{action}, count: #{count}, limit: #{limit}")
              {:error, :rate_limited}
            else
              # Increment counter
              :mnesia.write({@table_name, key, count + 1, window_start})
              emit_allowed_telemetry(customer_id, action, count + 1, limit)
              :ok
            end
          end
        [] ->
          # First request, initialize counter
          :mnesia.write({@table_name, key, 1, current_time})
          emit_allowed_telemetry(customer_id, action, 1, limit)
          :ok
      end
    end)
    
    case result do
      {:atomic, :ok} -> :ok
      {:atomic, {:error, :rate_limited}} -> {:error, :rate_limited}
      _ -> 
        Logger.error("Mnesia transaction failed: #{inspect(result)}")
        # On transaction failure, allow the request (fail open)
        :ok
    end
  end
  
  @doc """
  Gets the current count for a customer/action pair.
  Useful for testing and monitoring.
  """
  def get_current_count(customer_id, action \\ :credential_exchange) do
    action_normalized = normalize_action(action)
    key = {customer_id, action_normalized}
    current_time = System.system_time(:second)
    
    {:atomic, count} = :mnesia.transaction(fn ->
      case :mnesia.read(@table_name, key) do
        [{@table_name, ^key, count, window_start}] ->
          # Check if window is still valid
          if current_time - window_start > @window_seconds do
            0
          else
            count
          end
        [] ->
          0
      end
    end)
    
    count
  end
  
  @doc """
  Records an action for rate limiting.
  Legacy function for compatibility - now integrated into check_rate_limit.
  """
  def record_action(_customer_id, _action) do
    :ok
  end
  
  @doc """
  Reset all counters (for testing).
  """
  def reset() do
    case :mnesia.system_info(:is_running) do
      :yes ->
        :mnesia.clear_table(@table_name)
        :ok
      _ ->
        :ok
    end
  end
  
  # Private functions
  
  defp normalize_action(action) when is_binary(action), do: action
  defp normalize_action(action) when is_atom(action), do: Atom.to_string(action)
  
  defp get_rate_limit_config(action) when is_binary(action) do
    config = Application.get_env(:rsolv, :rate_limits, [])
    
    # Try to find config with action as atom key
    action_atom = String.to_atom(action)
    
    case Keyword.get(config, action_atom) do
      {limit, period} -> {limit, period}
      nil -> 
        # Default fallback
        Logger.debug("No rate limit config for action #{action}, using default: 100/minute")
        {100, :minute}
    end
  end
  
  defp emit_allowed_telemetry(customer_id, action, count, limit) do
    :telemetry.execute(
      [:rsolv, :rate_limiter, :request_allowed],
      %{count: 1, current_count: count},
      %{
        customer_id: customer_id,
        action: action,
        limit: limit
      }
    )
  end
  
  defp emit_exceeded_telemetry(customer_id, action, count, limit) do
    :telemetry.execute(
      [:rsolv, :rate_limiter, :limit_exceeded],
      %{count: 1},
      %{
        customer_id: customer_id,
        action: action,
        current_count: count,
        limit: limit
      }
    )
  end
  
  # GenServer callbacks - no sync needed with Mnesia
  
  def handle_info(:sync_with_cluster, state) do
    # No-op - Mnesia handles distribution automatically
    {:noreply, state}
  end
  
  def handle_info({:sync_data, _from_node, _data}, state) do
    # No-op - Mnesia handles distribution automatically
    {:noreply, state}
  end
  
  def handle_cast({:sync_data, _from_node, _data}, state) do
    # No-op - Mnesia handles distribution automatically
    {:noreply, state}
  end
end