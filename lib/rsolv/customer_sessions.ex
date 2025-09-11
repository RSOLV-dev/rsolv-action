defmodule Rsolv.CustomerSessions do
  @moduledoc """
  Distributed session management for customer authentication using Mnesia.
  
  This provides distributed sessions across all nodes in the BEAM cluster,
  ensuring session persistence when load balancing between pods.
  """
  
  use GenServer
  require Logger
  
  @table_name :customer_sessions_mnesia
  @session_ttl_hours 24 * 7  # 7 days
  
  def start_link(opts) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end
  
  def init(_opts) do
    # Subscribe to node events for cluster awareness
    :net_kernel.monitor_nodes(true)
    
    # Setup Mnesia table for distributed sessions
    setup_mnesia()
    
    # Schedule periodic cleanup of expired sessions
    schedule_cleanup()
    
    {:ok, %{}}
  end
  
  @doc """
  Stores a session token for a customer.
  """
  def put_session(token, customer_id) do
    expires_at = DateTime.add(DateTime.utc_now(), @session_ttl_hours * 3600, :second)
    
    :mnesia.transaction(fn ->
      :mnesia.write({@table_name, token, customer_id, DateTime.utc_now(), expires_at})
    end)
  end
  
  @doc """
  Retrieves a customer ID by session token.
  """
  def get_session(token) do
    case :mnesia.transaction(fn ->
      :mnesia.read(@table_name, token)
    end) do
      {:atomic, [{@table_name, ^token, customer_id, _created_at, expires_at}]} ->
        # Check if session has expired
        if DateTime.compare(DateTime.utc_now(), expires_at) == :lt do
          {:ok, customer_id}
        else
          # Clean up expired session
          delete_session(token)
          {:error, :expired}
        end
      {:atomic, []} ->
        {:error, :not_found}
      {:aborted, reason} ->
        Logger.error("Failed to read session: #{inspect(reason)}")
        {:error, :database_error}
    end
  end
  
  @doc """
  Deletes a session token.
  """
  def delete_session(token) do
    :mnesia.transaction(fn ->
      :mnesia.delete({@table_name, token})
    end)
  end
  
  @doc """
  Cleans up expired sessions.
  """
  def cleanup_expired_sessions do
    now = DateTime.utc_now()
    
    {:atomic, count} = :mnesia.transaction(fn ->
      # Find all expired sessions
      expired = :mnesia.select(@table_name, [
        {{@table_name, :"$1", :"$2", :"$3", :"$4"},
         [{:<, :"$4", now}],
         [:"$1"]}
      ])
      
      # Delete them
      Enum.each(expired, fn token ->
        :mnesia.delete({@table_name, token})
      end)
      
      length(expired)
    end)
    
    if count > 0 do
      Logger.info("Cleaned up #{count} expired sessions")
    end
    
    count
  end
  
  # GenServer callbacks
  
  def handle_info(:cleanup, state) do
    cleanup_expired_sessions()
    schedule_cleanup()
    {:noreply, state}
  end
  
  def handle_info({:nodeup, node}, state) do
    Logger.info("Node joined cluster: #{node}")
    # Mnesia will automatically sync the table
    {:noreply, state}
  end
  
  def handle_info({:nodedown, node}, state) do
    Logger.info("Node left cluster: #{node}")
    {:noreply, state}
  end
  
  def handle_info(msg, state) do
    Logger.debug("Unhandled message: #{inspect(msg)}")
    {:noreply, state}
  end
  
  # Private functions
  
  defp setup_mnesia do
    # Ensure Mnesia is running
    case :mnesia.system_info(:is_running) do
      :no -> 
        :mnesia.start()
        Process.sleep(100)
      _ -> 
        :ok
    end
    
    # Create schema for all nodes
    nodes = [node() | Node.list()]
    case :mnesia.create_schema(nodes) do
      :ok -> 
        Logger.info("Created Mnesia schema for customer sessions")
      {:error, {_, {:already_exists, _}}} -> 
        :ok
      error -> 
        Logger.warning("Could not create schema: #{inspect(error)}")
    end
    
    # Create or verify table
    ensure_table_exists()
  end
  
  defp ensure_table_exists do
    case :mnesia.create_table(@table_name, [
      attributes: [:token, :customer_id, :created_at, :expires_at],
      ram_copies: [node() | Node.list()],  # Use RAM for speed
      type: :set,
      index: [:customer_id, :expires_at]
    ]) do
      {:atomic, :ok} ->
        Logger.info("Created customer_sessions Mnesia table")
        :ok
      
      {:aborted, {:already_exists, @table_name}} ->
        # Table exists, ensure it's replicated to this node
        ensure_table_replicated()
        :ok
      
      {:aborted, reason} ->
        Logger.error("Failed to create customer_sessions table: #{inspect(reason)}")
        # Fall back to waiting and retrying
        Process.sleep(1000)
        ensure_table_replicated()
    end
  end
  
  defp ensure_table_replicated do
    case :mnesia.add_table_copy(@table_name, node(), :ram_copies) do
      {:atomic, :ok} ->
        Logger.info("Added customer_sessions table copy to node #{node()}")
        :ok
      
      {:aborted, {:already_exists, @table_name, _}} ->
        Logger.debug("Table already replicated on node #{node()}")
        :ok
      
      {:aborted, reason} ->
        Logger.warning("Could not replicate table: #{inspect(reason)}")
        :ok
    end
  end
  
  defp schedule_cleanup do
    # Run cleanup every hour
    Process.send_after(self(), :cleanup, :timer.hours(1))
  end
end