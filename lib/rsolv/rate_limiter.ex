defmodule Rsolv.RateLimiter do
  @moduledoc """
  Rate limiting for API requests using distributed ETS.
  """
  
  use GenServer
  require Logger
  
  @table_name :rsolv_rate_limiter
  @sync_interval 5_000  # Sync every 5 seconds
  
  def start_link(opts) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end
  
  def init(_opts) do
    # Create ETS table for rate limiting
    :ets.new(@table_name, [:set, :public, :named_table, read_concurrency: true])
    
    # Schedule periodic sync with other nodes
    Process.send_after(self(), :sync_with_cluster, @sync_interval)
    
    {:ok, %{}}
  end
  
  @doc """
  Checks if a customer has exceeded their rate limit.
  """
  def check_rate_limit(customer_id, action \\ "credential_exchange") do
    # Get current count and window
    key = {customer_id, action}
    current_time = System.system_time(:second)
    
    # Get or initialize counter
    try do
      case :ets.lookup(@table_name, key) do
      [{^key, count, window_start}] ->
        # If more than 60 seconds have passed, reset the counter
        if current_time - window_start > 60 do
          :ets.insert(@table_name, {key, 1, current_time})
          emit_allowed_telemetry(customer_id, action, 1)
          :ok
        else
          # Check against rate limit
          if count >= 100 do
            emit_exceeded_telemetry(customer_id, action, count)
            Logger.warning("Rate limit exceeded for customer #{customer_id}, action: #{action}, count: #{count}")
            {:error, :rate_limited}
          else
            # Increment counter
            :ets.update_counter(@table_name, key, {2, 1})
            emit_allowed_telemetry(customer_id, action, count + 1)
            :ok
          end
        end
      [] ->
        # First request, initialize counter
        :ets.insert(@table_name, {key, 1, current_time})
        emit_allowed_telemetry(customer_id, action, 1)
        :ok
      end
    catch
      :error, :badarg ->
        # Table doesn't exist, allow the request
        emit_allowed_telemetry(customer_id, action, 1)
        :ok
    end
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
    case :ets.whereis(@table_name) do
      :undefined ->
        # Table doesn't exist yet, that's fine for reset
        :ok
      _ ->
        :ets.delete_all_objects(@table_name)
        :ok
    end
  end
  
  # GenServer callbacks
  
  def handle_info(:sync_with_cluster, state) do
    sync_with_nodes()
    Process.send_after(self(), :sync_with_cluster, @sync_interval)
    {:noreply, state}
  end
  
  def handle_info({:sync_data, from_node, data}, state) do
    # Merge data from other node
    merge_rate_limit_data(data)
    Logger.debug("Received sync data from #{from_node} with #{length(data)} entries")
    {:noreply, state}
  end
  
  def handle_cast({:sync_data, from_node, data}, state) do
    # Merge data from other node
    merge_rate_limit_data(data)
    Logger.debug("Received sync data from #{from_node} with #{length(data)} entries")
    {:noreply, state}
  end
  
  # Private functions
  
  defp emit_allowed_telemetry(customer_id, action, count) do
    :telemetry.execute(
      [:rsolv, :rate_limiter, :request_allowed],
      %{count: 1, current_count: count},
      %{
        customer_id: customer_id,
        action: action,
        limit: 100
      }
    )
  end
  
  defp emit_exceeded_telemetry(customer_id, action, count) do
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
  end
  
  defp sync_with_nodes() do
    # Get all connected nodes
    nodes = Node.list()
    
    if length(nodes) > 0 do
      # Get current data
      current_time = System.system_time(:second)
      data = :ets.tab2list(@table_name)
      |> Enum.filter(fn {_key, _count, window_start} ->
        # Only sync entries from the last 60 seconds
        current_time - window_start <= 60
      end)
      
      # Send to all nodes
      for node <- nodes do
        GenServer.cast({__MODULE__, node}, {:sync_data, node(), data})
      end
    end
  end
  
  defp merge_rate_limit_data(remote_data) do
    current_time = System.system_time(:second)
    
    Enum.each(remote_data, fn {key, remote_count, remote_window} ->
      case :ets.lookup(@table_name, key) do
        [{^key, local_count, local_window}] ->
          # Merge logic: use the entry with the most recent window start
          # or if windows are the same, use the higher count
          cond do
            current_time - remote_window > 60 ->
              # Remote data is expired, ignore
              :ok
            current_time - local_window > 60 ->
              # Local data is expired, use remote
              :ets.insert(@table_name, {key, remote_count, remote_window})
            remote_window > local_window ->
              # Remote window is newer, use it
              :ets.insert(@table_name, {key, remote_count, remote_window})
            remote_window == local_window and remote_count > local_count ->
              # Same window, but remote has higher count
              :ets.insert(@table_name, {key, remote_count, remote_window})
            true ->
              # Keep local data
              :ok
          end
        [] ->
          # No local data, use remote if not expired
          if current_time - remote_window <= 60 do
            :ets.insert(@table_name, {key, remote_count, remote_window})
          end
      end
    end)
  end
end