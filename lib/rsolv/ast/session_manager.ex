defmodule Rsolv.AST.SessionManager do
  @moduledoc """
  Manages encrypted sessions for AST analysis service.
  
  Features:
  - Secure session creation with unique IDs
  - Per-customer session isolation
  - Automatic expiration and cleanup
  - Encryption key management
  - Concurrent access support
  """
  
  use GenServer
  require Logger
  
  alias Rsolv.AST.Encryption
  
  @default_ttl_seconds 3600  # 1 hour
  @max_sessions_per_customer 10
  @cleanup_interval :timer.minutes(5)
  @sessions_table :ast_sessions
  @customer_sessions_table :ast_customer_sessions
  
  # Session struct
  defmodule Session do
    @enforce_keys [:id, :customer_id, :encryption_key, :created_at, :expires_at]
    defstruct [:id, :customer_id, :encryption_key, :created_at, :expires_at, :metadata]
  end
  
  # Client API
  
  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end
  
  @doc """
  Creates a new session for a customer.
  Returns {:ok, session} or {:error, reason}.
  """
  def create_session(customer_id, ttl_seconds \\ @default_ttl_seconds) do
    GenServer.call(__MODULE__, {:create_session, customer_id, ttl_seconds})
  end
  
  @doc """
  Retrieves a session by ID and customer ID.
  Returns {:ok, session} or {:error, reason}.
  """
  def get_session(session_id, customer_id) do
    GenServer.call(__MODULE__, {:get_session, session_id, customer_id})
  end
  
  @doc """
  Deletes a session.
  """
  def delete_session(session_id, customer_id) do
    GenServer.call(__MODULE__, {:delete_session, session_id, customer_id})
  end
  
  @doc """
  Manually triggers cleanup of expired sessions.
  """
  def cleanup_expired_sessions do
    GenServer.cast(__MODULE__, :cleanup_expired)
  end
  
  @doc """
  Returns count of active sessions.
  """
  def count_active_sessions do
    GenServer.call(__MODULE__, :count_active)
  end
  
  # Server callbacks
  
  @impl true
  def init(_opts) do
    # Create ETS tables for clustering support
    create_ets_tables()
    
    # Schedule periodic cleanup
    schedule_cleanup()
    
    {:ok, %{}}
  end
  
  @impl true
  def handle_call({:create_session, customer_id, ttl_seconds}, _from, state) do
    # Generate session data
    session_id = generate_session_id()
    encryption_key = Encryption.generate_key()
    now = DateTime.utc_now()
    expires_at = DateTime.add(now, ttl_seconds, :second)
    
    session = %Session{
      id: session_id,
      customer_id: customer_id,
      encryption_key: encryption_key,
      created_at: now,
      expires_at: expires_at,
      metadata: %{}
    }
    
    # Store in ETS
    add_session_to_ets(session)
    enforce_session_limit_ets(customer_id)
    
    {:reply, {:ok, session}, state}
  end
  
  @impl true
  def handle_call({:get_session, session_id, customer_id}, _from, state) do
    case get_session_from_ets(session_id) do
      nil ->
        {:reply, {:error, :session_not_found}, state}
      
      %Session{customer_id: ^customer_id} = session ->
        if session_expired?(session) do
          # Remove expired session
          remove_session_from_ets(session_id)
          {:reply, {:error, :session_expired}, state}
        else
          {:reply, {:ok, session}, state}
        end
      
      %Session{} ->
        # Session exists but belongs to different customer
        {:reply, {:error, :session_not_found}, state}
    end
  end
  
  @impl true
  def handle_call({:delete_session, session_id, customer_id}, _from, state) do
    case get_session_from_ets(session_id) do
      %Session{customer_id: ^customer_id} ->
        # Clean up any associated parsers before removing session
        cleanup_session_parsers(session_id)
        remove_session_from_ets(session_id)
        {:reply, :ok, state}
      
      _ ->
        # Session doesn't exist or belongs to different customer
        {:reply, :ok, state}
    end
  end
  
  @impl true
  def handle_call(:count_active, _from, state) do
    count = try do
      :ets.foldl(fn {_id, session}, acc ->
        if session_expired?(session) do
          acc
        else
          acc + 1
        end
      end, 0, @sessions_table)
    rescue
      _ -> 0  # Table might not exist yet
    end
    
    {:reply, count, state}
  end
  
  @impl true
  def handle_cast(:cleanup_expired, state) do
    cleanup_sessions_ets()
    {:noreply, state}
  end
  
  @impl true
  def handle_info(:cleanup_timer, state) do
    cleanup_sessions_ets()
    schedule_cleanup()
    {:noreply, state}
  end
  
  # Private functions
  
  defp create_ets_tables do
    # Create tables if they don't exist
    if :ets.whereis(@sessions_table) == :undefined do
      :ets.new(@sessions_table, [:set, :public, :named_table, {:read_concurrency, true}])
    end
    
    if :ets.whereis(@customer_sessions_table) == :undefined do
      :ets.new(@customer_sessions_table, [:set, :public, :named_table, {:read_concurrency, true}])
    end
  end
  
  defp add_session_to_ets(session) do
    # Store session
    safe_ets_insert(@sessions_table, {session.id, session})
    
    # Update customer session list
    customer_sessions = case :ets.lookup(@customer_sessions_table, session.customer_id) do
      [{_customer_id, existing_list}] -> [session.id | existing_list]
      [] -> [session.id]
    end
    
    safe_ets_insert(@customer_sessions_table, {session.customer_id, customer_sessions})
  end
  
  defp get_session_from_ets(session_id) do
    case :ets.lookup(@sessions_table, session_id) do
      [{^session_id, session}] -> session
      [] -> nil
    end
  end
  
  defp remove_session_from_ets(session_id) do
    case get_session_from_ets(session_id) do
      nil ->
        :ok
      
      %Session{customer_id: customer_id} = session ->
        # Remove from sessions table
        safe_ets_delete(@sessions_table, session_id)
        
        # Remove from customer sessions list
        case :ets.lookup(@customer_sessions_table, customer_id) do
          [{^customer_id, session_list}] ->
            updated_list = Enum.reject(session_list, &(&1 == session_id))
            if updated_list == [] do
              safe_ets_delete(@customer_sessions_table, customer_id)
            else
              safe_ets_insert(@customer_sessions_table, {customer_id, updated_list})
            end
          [] ->
            :ok
        end
        
        # Clear encryption key from memory (best effort)
        clear_encryption_key(session.encryption_key)
      
      other ->
        # Handle unexpected data - just remove from sessions table
        Logger.warning("Unexpected data type in session table for #{session_id}: #{inspect(other)}")
        safe_ets_delete(@sessions_table, session_id)
    end
  end
  
  defp enforce_session_limit_ets(customer_id) do
    case :ets.lookup(@customer_sessions_table, customer_id) do
      [] ->
        :ok
      
      [{^customer_id, session_list}] when length(session_list) <= @max_sessions_per_customer ->
        :ok
      
      [{^customer_id, session_list}] ->
        # Get sessions with timestamps
        sessions_by_age = session_list
        |> Enum.map(fn id -> {id, get_session_from_ets(id)} end)
        |> Enum.filter(fn {_id, session} -> session != nil end)
        |> Enum.sort_by(fn {_id, session} -> session.created_at end, DateTime)
        
        # Remove oldest sessions
        to_remove = sessions_by_age
        |> Enum.take(length(sessions_by_age) - @max_sessions_per_customer)
        |> Enum.map(fn {id, _session} -> id end)
        
        Enum.each(to_remove, &remove_session_from_ets/1)
    end
  end
  
  defp cleanup_sessions_ets do
    expired_sessions = try do
      :ets.foldl(fn {session_id, session}, acc ->
        if session_expired?(session) do
          [session_id | acc]
        else
          acc
        end
      end, [], @sessions_table)
    rescue
      _ -> []  # Table might not exist or have invalid data
    end
    
    Logger.info("Cleaning up #{length(expired_sessions)} expired sessions")
    
    Enum.each(expired_sessions, &remove_session_from_ets/1)
  end
  
  defp session_expired?(%Session{expires_at: expires_at}) do
    DateTime.compare(DateTime.utc_now(), expires_at) == :gt
  end
  
  defp session_expired?(_other) do
    # Handle unexpected data gracefully
    true
  end
  
  defp cleanup_session_parsers(session_id) do
    # Clean up any parsers associated with this session
    # Query ParserRegistry to find and stop parsers for this session
    try do
      # Get all languages that might have parsers
      languages = ["python", "javascript", "typescript", "java", "php", "ruby", "go"]
      
      Enum.each(languages, fn language ->
        # Try to stop parser for this session/language combination
        case GenServer.call(Rsolv.AST.ParserRegistry, {:cleanup_session_parser, session_id, language}, 5000) do
          :ok -> Logger.debug("Cleaned up #{language} parser for session #{session_id}")
          _ -> :ok  # Parser didn't exist or already cleaned up
        end
      end)
    rescue
      error ->
        Logger.warning("Failed to cleanup parsers for session #{session_id}: #{inspect(error)}")
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

  defp generate_session_id do
    :crypto.strong_rand_bytes(16) |> Base.encode16(case: :lower)
  end
  
  defp schedule_cleanup do
    Process.send_after(self(), :cleanup_timer, @cleanup_interval)
  end
  
  defp clear_encryption_key(key) when is_binary(key) do
    # Best effort to clear key from memory
    # In Erlang/Elixir, we can't directly clear memory,
    # but we can overwrite the reference
    _cleared = :crypto.exor(key, key)
    :ok
  end
end