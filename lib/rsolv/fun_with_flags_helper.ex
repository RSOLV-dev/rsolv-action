defmodule Rsolv.FunWithFlagsHelper do
  @moduledoc """
  Helper module to manage FunWithFlags cache issues.
  Provides utilities to flush cache and force reload of flags.
  """
  
  require Logger
  
  @doc """
  Flushes the FunWithFlags cache and forces a reload from the database.
  """
  def flush_and_reload do
    Logger.info("Flushing FunWithFlags cache...")
    
    # Flush the ETS cache
    try do
      FunWithFlags.Store.Cache.flush()
      Logger.info("Cache flushed successfully")
    rescue
      e ->
        Logger.error("Failed to flush cache: #{inspect(e)}")
    end
    
    # Force a read of the flag to populate cache from database
    case FunWithFlags.enabled?(:false_positive_caching) do
      {:ok, enabled} ->
        Logger.info("Feature flag false_positive_caching is now: #{enabled}")
        {:ok, enabled}
      error ->
        Logger.error("Failed to read flag: #{inspect(error)}")
        error
    end
  end
  
  @doc """
  Checks the current state of the false_positive_caching flag.
  """
  def check_flag_status do
    # Check cache state
    cache_contents = try do
      FunWithFlags.Store.Cache.dump()
    rescue
      _ -> %{}
    end
    
    # Check database state
    db_state = Rsolv.Repo.query!(
      "SELECT enabled FROM fun_with_flags_toggles WHERE flag_name = 'false_positive_caching'",
      []
    )
    
    # Check runtime state
    runtime_state = FunWithFlags.enabled?(:false_positive_caching)
    
    %{
      cache: cache_contents[:false_positive_caching],
      database: db_state.rows,
      runtime: runtime_state
    }
  end
end