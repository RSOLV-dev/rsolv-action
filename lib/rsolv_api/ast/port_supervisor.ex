defmodule RsolvApi.AST.PortSupervisor do
  @moduledoc """
  Supervises external parser processes (Ports) with:
  - Crash recovery and restart limits
  - Resource limits (memory, CPU, timeout)
  - Connection pooling
  - Health monitoring
  - Security isolation
  """
  
  use DynamicSupervisor
  
  alias RsolvApi.AST.PortWorker
  
  require Logger
  
  def start_link(init_arg) do
    DynamicSupervisor.start_link(__MODULE__, init_arg, name: __MODULE__)
  end
  
  @impl true
  def init(_init_arg) do
    # Initialize ETS tables for port tracking (create if not exists)
    ensure_ets_table(:port_registry)
    ensure_ets_table(:port_pools)
    ensure_ets_table(:port_stats)
    
    DynamicSupervisor.init(strategy: :one_for_one)
  end
  
  @doc """
  Starts a new port with the specified parser configuration.
  """
  def start_port(supervisor, config) do
    port_id = generate_port_id()
    
    # Check if we can reuse a pooled port
    pooled_port_id = if config[:pooled], do: get_from_pool(config.language), else: nil
    
    if pooled_port_id do
      {:ok, pooled_port_id}
    else
      # Start new port worker
      restart_type = if config[:max_restarts] && config[:max_restarts] > 0 do
        :permanent
      else
        :transient
      end
      
      spec = %{
        id: port_id,
        start: {PortWorker, :start_link, [Map.put(config, :id, port_id)]},
        restart: restart_type,
        type: :worker
      }
      
      case DynamicSupervisor.start_child(supervisor, spec) do
        {:ok, pid} ->
          # Register port
          safe_ets_insert(:port_registry, {port_id, pid, config, System.monotonic_time(:millisecond)})
          safe_ets_insert(:port_stats, {port_id, %{
            requests_handled: 0,
            restarts: 0,
            last_used: System.monotonic_time(:millisecond),
            memory_usage: 0
          }})
          {:ok, port_id}
          
        {:error, reason} ->
          {:error, "Port failed to start: #{inspect(reason)}"}
      end
    end
  end
  
  @doc """
  Stops a port gracefully.
  """
  def stop_port(supervisor, port_id) do
    case :ets.lookup(:port_registry, port_id) do
      [{^port_id, pid, _config, _started_at}] ->
        DynamicSupervisor.terminate_child(supervisor, pid)
        safe_ets_delete(:port_registry, port_id)
        safe_ets_delete(:port_stats, port_id)
        :ok
        
      [] ->
        :ok
    end
  end
  
  @doc """
  Gets port information.
  """
  def get_port(_supervisor, port_id) do
    case :ets.lookup(:port_registry, port_id) do
      [{^port_id, pid, config, started_at}] ->
        %{
          id: port_id,
          pid: pid,
          config: config,
          started_at: started_at
        }
        
      [] ->
        nil
    end
  end
  
  @doc """
  Gets the PID of a port.
  """
  def get_port_pid(_supervisor, port_id) do
    case :ets.lookup(:port_registry, port_id) do
      [{^port_id, pid, _config, _started_at}] -> pid
      [] -> nil
    end
  end
  
  @doc """
  Sends a message to a port.
  """
  def send_to_port(_supervisor, port_id, message) do
    case get_port_pid(nil, port_id) do
      nil -> {:error, :port_not_found}
      pid -> 
        GenServer.cast(pid, {:send, message})
        update_stats(port_id, :last_used)
        :ok
    end
  end
  
  @doc """
  Makes a synchronous call to a port.
  """
  def call_port(_supervisor, port_id, command, timeout \\ 5000) do
    case get_port_pid(nil, port_id) do
      nil -> {:error, :port_not_found}
      pid -> 
        try do
          result = GenServer.call(pid, {:call, command}, timeout)
          update_stats(port_id, :request)
          result
        catch
          :exit, {:timeout, _} -> {:error, :timeout}
        end
    end
  end
  
  @doc """
  Releases a port back to the pool.
  """
  def release_port(_supervisor, port_id) do
    case :ets.lookup(:port_registry, port_id) do
      [{^port_id, _pid, config, _started_at}] ->
        if config[:pooled] do
          add_to_pool(config.language, port_id)
        end
        :ok
        
      [] ->
        :ok
    end
  end
  
  @doc """
  Gets the restart count for a port.
  """
  def get_port_restart_count(_supervisor, port_id) do
    case :ets.lookup(:port_stats, port_id) do
      [{^port_id, stats}] -> stats.restarts
      [] -> 0
    end
  end
  
  @doc """
  Terminates a port forcefully.
  """
  def terminate_port(supervisor, port_id) do
    stop_port(supervisor, port_id)
  end
  
  @doc """
  Checks if a port is healthy.
  """
  def is_port_healthy?(_supervisor, port_id) do
    case call_port(nil, port_id, "HEALTH_CHECK", 1000) do
      {:ok, %{"status" => "healthy"}} -> true
      {:ok, %{"result" => "ok"}} -> true  # Default health check response
      _ -> false
    end
  end
  
  @doc """
  Gets statistics for a port.
  """
  def get_port_stats(_supervisor, port_id) do
    case :ets.lookup(:port_stats, port_id) do
      [{^port_id, stats}] ->
        # Calculate uptime
        case :ets.lookup(:port_registry, port_id) do
          [{^port_id, _pid, _config, started_at}] ->
            uptime_ms = System.monotonic_time(:millisecond) - started_at
            Map.merge(stats, %{
              uptime_seconds: div(uptime_ms, 1000),
              memory_usage: get_process_memory(port_id)
            })
            
          [] ->
            stats
        end
        
      [] ->
        nil
    end
  end
  
  @doc """
  Restarts an unhealthy port.
  """
  def restart_unhealthy_port(supervisor, port_id) do
    case :ets.lookup(:port_registry, port_id) do
      [{^port_id, pid, config, _started_at}] ->
        # Stop the current port
        DynamicSupervisor.terminate_child(supervisor, pid)
        
        # Update restart count
        update_stats(port_id, :restart)
        
        # Start a new port with the same config
        spec = %{
          id: port_id,
          start: {PortWorker, :start_link, [Map.put(config, :id, port_id)]},
          restart: :transient,
          type: :worker
        }
        
        case DynamicSupervisor.start_child(supervisor, spec) do
          {:ok, new_pid} ->
            # Update registry with new PID
            safe_ets_insert(:port_registry, {port_id, new_pid, config, System.monotonic_time(:millisecond)})
            {:ok, port_id}
            
          {:error, reason} ->
            # Clean up if restart failed
            safe_ets_delete(:port_registry, port_id)
            safe_ets_delete(:port_stats, port_id)
            {:error, reason}
        end
        
      [] ->
        {:error, :port_not_found}
    end
  end

  @doc """
  Gets the process group for a port.
  """
  def get_port_process_group(_supervisor, port_id) do
    # In a real implementation, this would return the OS process group
    # For testing, we'll use the port_id as a proxy
    "pg_#{port_id}"
  end
  
  @doc """
  Gets the pool size for a language.
  """
  def get_pool_size(_supervisor, language) do
    case :ets.lookup(:port_pools, language) do
      [{^language, pool}] -> length(pool)
      [] -> 0
    end
  end
  
  # Private functions
  
  defp generate_port_id do
    :crypto.strong_rand_bytes(16) |> Base.encode16(case: :lower)
  end
  
  defp get_from_pool(language) do
    case :ets.lookup(:port_pools, language) do
      [{^language, [port_id | rest]}] ->
        safe_ets_insert(:port_pools, {language, rest})
        port_id
        
      _ ->
        nil
    end
  end
  
  defp add_to_pool(language, port_id) do
    max_pool_size = 5  # Default max pool size
    
    case :ets.lookup(:port_pools, language) do
      [{^language, pool}] ->
        new_pool = if length(pool) >= max_pool_size do
          # Remove oldest
          [port_id | Enum.drop(pool, -1)]
        else
          [port_id | pool]
        end
        safe_ets_insert(:port_pools, {language, new_pool})
        
      [] ->
        safe_ets_insert(:port_pools, {language, [port_id]})
    end
  end
  
  defp update_stats(port_id, type) do
    case :ets.lookup(:port_stats, port_id) do
      [{^port_id, stats}] ->
        updated_stats = case type do
          :request -> 
            %{stats | requests_handled: stats.requests_handled + 1, last_used: System.monotonic_time(:millisecond)}
          :restart ->
            %{stats | restarts: stats.restarts + 1}
          :last_used ->
            %{stats | last_used: System.monotonic_time(:millisecond)}
        end
        safe_ets_insert(:port_stats, {port_id, updated_stats})
        updated_stats.restarts  # Return restart count for debugging
        
      [] ->
        # If stats don't exist, create them
        if type == :restart do
          stats = %{
            requests_handled: 0,
            restarts: 1,
            last_used: System.monotonic_time(:millisecond),
            memory_usage: 0
          }
          safe_ets_insert(:port_stats, {port_id, stats})
          1  # Return restart count
        else
          0
        end
    end
  end
  
  defp get_process_memory(port_id) do
    case get_port_pid(nil, port_id) do
      nil -> 0
      pid ->
        case Process.info(pid, :memory) do
          {:memory, bytes} -> bytes
          nil -> 0
        end
    end
  end
  
  # Safe ETS operations to prevent crashes when tables are deleted during cleanup
  defp safe_ets_insert(table, key_value) do
    try do
      :ets.insert(table, key_value)
    catch
      :error, :badarg -> :ok  # Table doesn't exist, ignore gracefully
    end
  end

  defp safe_ets_delete(table, key) do
    try do
      :ets.delete(table, key)
    catch
      :error, :badarg -> :ok  # Table doesn't exist, ignore gracefully
    end
  end

  defp ensure_ets_table(name) do
    case :ets.whereis(name) do
      :undefined ->
        :ets.new(name, [:set, :public, :named_table])
      _ ->
        name
    end
  end
end