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
  Returns all active sessions for debugging/testing.
  """
  def all_sessions do
    {:atomic, sessions} = :mnesia.transaction(fn ->
      :mnesia.match_object({@table_name, :_, :_, :_, :_})
    end)
    sessions
  end
  
  @doc """
  Cleans up expired sessions.
  """
  def cleanup_expired_sessions do
    now = DateTime.utc_now()
    
    {:atomic, count} = :mnesia.transaction(fn ->
      # Find all expired sessions by iterating through all records
      all_sessions = :mnesia.match_object({@table_name, :_, :_, :_, :_})
      
      expired = Enum.filter(all_sessions, fn {_, _, _, _, expires_at} ->
        DateTime.compare(expires_at, now) == :lt
      end)
      
      # Delete expired sessions
      Enum.each(expired, fn {_, token, _, _, _} ->
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
    # Ensure the new node gets a table copy
    spawn(fn ->
      Process.sleep(1000)  # Give the node time to initialize
      ensure_node_has_table(node)
    end)
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
    
    # Join Mnesia cluster if there are other nodes
    if length(Node.list()) > 0 do
      join_mnesia_cluster()
    else
      # First node - create schema only for self
      case :mnesia.create_schema([node()]) do
        :ok -> 
          Logger.info("Created Mnesia schema for first node")
        {:error, {_, {:already_exists, _}}} -> 
          :ok
        error -> 
          Logger.warning("Could not create schema: #{inspect(error)}")
      end
    end
    
    # Create or verify table
    ensure_table_exists()
  end
  
  defp join_mnesia_cluster do
    # Try to find a node that has Mnesia running
    existing_node = Enum.find(Node.list(), fn n ->
      case :rpc.call(n, :mnesia, :system_info, [:is_running]) do
        :yes -> true
        _ -> false
      end
    end)
    
    if existing_node do
      Logger.info("Joining Mnesia cluster via node: #{existing_node}")
      
      # Stop Mnesia if running
      :mnesia.stop()
      
      # Delete any local schema
      :mnesia.delete_schema([node()])
      
      # Start Mnesia
      :mnesia.start()
      
      # Connect to the cluster
      case :mnesia.change_config(:extra_db_nodes, [existing_node]) do
        {:ok, nodes} ->
          Logger.info("Successfully joined Mnesia cluster with nodes: #{inspect(nodes)}")
          
          # Wait for tables to sync
          case :mnesia.wait_for_tables([:schema, @table_name], 10000) do
            :ok ->
              Logger.info("Tables synced successfully")
            {:timeout, bad_tables} ->
              Logger.warning("Some tables timed out: #{inspect(bad_tables)}")
            {:error, reason} ->
              Logger.error("Table sync error: #{inspect(reason)}")
          end
        
        {:error, reason} ->
          Logger.error("Failed to join Mnesia cluster: #{inspect(reason)}")
          # Fall back to creating own schema
          :mnesia.create_schema([node()])
      end
    else
      # No other nodes with Mnesia, create own schema
      case :mnesia.create_schema([node()]) do
        :ok -> 
          Logger.info("Created Mnesia schema (no other nodes available)")
        {:error, {_, {:already_exists, _}}} -> 
          :ok
        error -> 
          Logger.warning("Could not create schema: #{inspect(error)}")
      end
    end
  end
  
  defp ensure_table_exists do
    # Check if table already exists on any node
    case :mnesia.table_info(@table_name, :attributes) do
      [:token, :customer_id, :created_at, :expires_at] ->
        Logger.info("customer_sessions table already exists, ensuring replication")
        ensure_table_replicated()
        :ok
      _ ->
        # Table doesn't exist or has wrong attributes, try to create it
        create_new_table()
    end
  rescue
    _ ->
      # Table doesn't exist, create it
      create_new_table()
  end
  
  defp create_new_table do
    # Get all connected nodes for replication
    nodes = [node() | Node.list()]
    
    # Use disc_copies in production, ram_copies in tests/dev
    # Check if we're in a real distributed environment
    storage_type = if Node.alive?() and length(Node.list()) > 0 do
      :disc_copies
    else
      :ram_copies
    end
    
    table_opts = [
      attributes: [:token, :customer_id, :created_at, :expires_at],
      type: :set,
      index: [:customer_id, :expires_at]
    ] ++ [{storage_type, nodes}]
    
    case :mnesia.create_table(@table_name, table_opts) do
      {:atomic, :ok} ->
        Logger.info("Created customer_sessions Mnesia table with #{storage_type}")
        :ok
      
      {:aborted, {:already_exists, @table_name}} ->
        # Table exists, ensure it's replicated to this node
        Logger.info("Table already exists, ensuring replication")
        ensure_table_replicated()
        :ok
      
      {:aborted, {:bad_type, @table_name, type, other_node}} ->
        # Table exists on another node with different storage type
        Logger.warning("Table exists on #{inspect(other_node)} with type #{inspect(type)}, adapting...")
        # Try to add a copy with whatever type the existing table has
        adapt_to_existing_table()
        :ok
        
      {:aborted, reason} ->
        Logger.error("Failed to create customer_sessions table: #{inspect(reason)}")
        # Fall back to waiting and retrying
        Process.sleep(1000)
        ensure_table_replicated()
    end
  end
  
  defp adapt_to_existing_table do
    # Try to detect what storage type the existing table has
    try do
      disc_nodes = :mnesia.table_info(@table_name, :disc_copies)
      ram_nodes = :mnesia.table_info(@table_name, :ram_copies)
      disc_only_nodes = :mnesia.table_info(@table_name, :disc_only_copies)
      
      cond do
        length(disc_nodes) > 0 ->
          # Table uses disc_copies, add ourselves as disc_copies
          add_table_copy_safe(:disc_copies)
        length(ram_nodes) > 0 ->
          # Table uses ram_copies, add ourselves as ram_copies  
          add_table_copy_safe(:ram_copies)
        length(disc_only_nodes) > 0 ->
          # Table uses disc_only_copies, add ourselves as disc_only_copies
          add_table_copy_safe(:disc_only_copies)
        true ->
          Logger.error("Could not determine storage type of existing table")
          # Default to ram_copies as safest option
          add_table_copy_safe(:ram_copies)
      end
    rescue
      error ->
        Logger.error("Error adapting to existing table: #{inspect(error)}")
        # Default to ram_copies as safest option
        add_table_copy_safe(:ram_copies)
    end
  end
  
  defp add_table_copy_safe(storage_type) do
    case :mnesia.add_table_copy(@table_name, node(), storage_type) do
      {:atomic, :ok} ->
        Logger.info("Added #{storage_type} table copy to node #{node()}")
        :ok
      {:aborted, {:already_exists, @table_name, _}} ->
        Logger.debug("Table copy already exists on node #{node()}")
        :ok
      {:aborted, reason} ->
        Logger.warning("Could not add table copy: #{inspect(reason)}")
        :ok
    end
  end
  
  defp ensure_table_replicated do
    # Adapt to whatever storage type the table is already using
    adapt_to_existing_table()
  end
  
  defp schedule_cleanup do
    # Run cleanup every hour
    Process.send_after(self(), :cleanup, :timer.hours(1))
  end
  
  defp ensure_node_has_table(node) do
    # Check if the node has the table
    case :rpc.call(node, :mnesia, :table_info, [@table_name, :disc_copies]) do
      {:badrpc, _} ->
        Logger.debug("Could not check table on node #{node}")
      copies when is_list(copies) ->
        if node not in copies do
          # Add table copy to the new node
          case :mnesia.add_table_copy(@table_name, node, :disc_copies) do
            {:atomic, :ok} ->
              Logger.info("Added table copy to node #{node}")
            {:aborted, reason} ->
              Logger.warning("Could not add table copy to #{node}: #{inspect(reason)}")
          end
        else
          Logger.debug("Node #{node} already has table copy")
        end
    end
  end
end