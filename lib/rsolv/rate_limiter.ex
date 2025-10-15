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
    # Subscribe to node events
    :net_kernel.monitor_nodes(true)

    # Setup Mnesia schema and table
    setup_mnesia()

    {:ok, %{}}
  end

  defp setup_mnesia do
    # Check if we have a broken Mnesia setup (nonode@nohost issue)
    fix_broken_mnesia_setup()

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

    # Ensure table exists with retry logic
    ensure_table_exists()
  end

  defp fix_broken_mnesia_setup do
    # Check if Mnesia is configured with nonode@nohost (broken setup)
    db_nodes =
      try do
        :mnesia.system_info(:db_nodes)
      rescue
        _ -> []
      end

    if db_nodes == [:nonode@nohost] and node() != :nonode@nohost do
      Logger.warning("Detected broken Mnesia setup with nonode@nohost, fixing...")

      # Stop Mnesia
      :mnesia.stop()

      # Delete the broken schema directory
      schema_dir = "/app/Mnesia.nonode@nohost"

      if File.exists?(schema_dir) do
        Logger.info("Removing broken Mnesia directory: #{schema_dir}")
        File.rm_rf!(schema_dir)
      end

      # Wait a moment for cleanup
      Process.sleep(1000)

      Logger.info("Mnesia cleanup complete, will recreate with proper node names")
    end
  end

  @doc """
  Ensures the rate limiter table exists and is properly replicated.
  This can be called manually or automatically on node join.
  """
  def ensure_table_exists do
    nodes = [node() | Node.list()]

    # Use ram_copies for all environments - rate limits are ephemeral
    # and don't need to survive restarts (60-second windows)
    storage_type = :ram_copies

    case check_and_create_table(nodes, storage_type) do
      :ok ->
        # Ensure table is replicated to all nodes
        ensure_replication(nodes, storage_type)
        :ok

      error ->
        Logger.error("Failed to ensure table exists: #{inspect(error)}")
        error
    end
  end

  defp check_and_create_table(nodes, storage_type) do
    # Check if table exists
    tables = :mnesia.system_info(:tables)

    if @table_name in tables do
      # Table exists, ensure it's loaded
      case :mnesia.wait_for_tables([@table_name], 5000) do
        :ok ->
          :ok

        {:timeout, _} ->
          # Try to force load
          :mnesia.force_load_table(@table_name)
          :ok

        error ->
          error
      end
    else
      # Table doesn't exist, create it
      create_table_with_retry(nodes, storage_type, 3)
    end
  end

  defp create_table_with_retry(nodes, storage_type, retries) when retries > 0 do
    table_opts = [
      {:attributes, [:key, :count, :window_start]},
      {storage_type, nodes},
      {:type, :set}
    ]

    case :mnesia.create_table(@table_name, table_opts) do
      {:atomic, :ok} ->
        Logger.info("Created Mnesia rate limiter table on nodes: #{inspect(nodes)}")
        :ok

      {:aborted, {:already_exists, @table_name}} ->
        Logger.debug("Table already exists")
        :ok

      {:aborted, {:not_active, @table_name, node}} ->
        Logger.warning("Node #{inspect(node)} not active, retrying with active nodes only...")
        # Retry with only active nodes
        active_nodes =
          Enum.filter(nodes, fn n ->
            n == node() or :net_adm.ping(n) == :pong
          end)

        create_table_with_retry(active_nodes, storage_type, retries - 1)

      error ->
        Logger.error("Failed to create Mnesia table: #{inspect(error)}, retrying...")
        Process.sleep(1000)
        create_table_with_retry(nodes, storage_type, retries - 1)
    end
  end

  defp create_table_with_retry(_nodes, _storage_type, 0) do
    {:error, :max_retries_exceeded}
  end

  defp ensure_replication(nodes, storage_type) do
    # Check current replicas
    case :mnesia.table_info(@table_name, storage_type) do
      current_nodes ->
        # Add replicas for nodes that don't have them
        missing_nodes = nodes -- current_nodes

        Enum.each(missing_nodes, fn node ->
          if node != node() do
            case :mnesia.add_table_copy(@table_name, node, storage_type) do
              {:atomic, :ok} ->
                Logger.info("Added table replica to node #{inspect(node)}")

              {:aborted, {:already_exists, @table_name, ^node}} ->
                Logger.debug("Table replica already exists on #{inspect(node)}")

              error ->
                Logger.warning(
                  "Could not add table replica to #{inspect(node)}: #{inspect(error)}"
                )
            end
          end
        end)
    end
  catch
    _, _ ->
      Logger.warning("Could not check table replication status")
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
    result =
      :mnesia.transaction(fn ->
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

                Logger.warning(
                  "Rate limit exceeded for customer #{customer_id}, action: #{action}, count: #{count}, limit: #{limit}"
                )

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
      {:atomic, :ok} ->
        :ok

      {:atomic, {:error, :rate_limited}} ->
        {:error, :rate_limited}

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

    {:atomic, count} =
      :mnesia.transaction(fn ->
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
      {limit, period} ->
        {limit, period}

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

  # GenServer callbacks

  def handle_info({:nodeup, node}, state) do
    Logger.info("Node joined cluster: #{inspect(node)}, ensuring table replication...")
    # When a new node joins, ensure the table is replicated there
    Task.start(fn ->
      # Give the node time to fully initialize
      Process.sleep(2000)
      ensure_table_exists()
    end)

    {:noreply, state}
  end

  def handle_info({:nodedown, node}, state) do
    Logger.info("Node left cluster: #{inspect(node)}")
    {:noreply, state}
  end

  def handle_info(:sync_with_cluster, state) do
    # Legacy compatibility - no longer needed with Mnesia
    {:noreply, state}
  end

  def handle_info({:sync_data, _from_node, _data}, state) do
    # Legacy compatibility - no longer needed with Mnesia
    {:noreply, state}
  end

  def handle_cast({:sync_data, _from_node, _data}, state) do
    # Legacy compatibility - no longer needed with Mnesia
    {:noreply, state}
  end
end
