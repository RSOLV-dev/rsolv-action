defmodule Rsolv.ValidationCache do
  @moduledoc """
  Main interface for the false positive caching system.
  
  Stores and retrieves cached validation results to avoid
  re-validating known false positives.
  
  ## Overview
  
  This module provides a caching layer for vulnerability validation results,
  specifically designed to reduce redundant API calls to the AST validation
  service. When a vulnerability is determined to be a false positive, the
  result is cached for 90 days.
  
  ## Features
  
  - Forge-account scoped caching for security isolation
  - Automatic TTL of 90 days  
  - File hash validation for cache invalidation
  - Upsert semantics for cache updates
  """
  
  import Ecto.Query
  alias Rsolv.Repo
  alias Rsolv.ValidationCache.{KeyGenerator, CachedValidation}
  
  require Logger
  
  @ttl_days 90
  
  @doc """
  Stores a validation result in the cache.
  
  Updates existing entries with the same cache key (upsert).
  
  ## Parameters
  
    - attrs: Map containing validation data including:
      - forge_account_id: Integer ID of the forge account
      - repository: String repository identifier  
      - locations: List of location maps with :file_path and :line
      - vulnerability_type: String vulnerability type
      - file_hashes: Map of file paths to SHA-256 hashes
      - is_false_positive: Boolean indicating false positive
      - confidence: Float between 0 and 1
      - reason: String explanation (optional)
      - full_result: Map with complete validation data (optional)
  
  ## Returns
  
    - `{:ok, cached_validation}` on success
    - `{:error, changeset}` on validation failure
  
  ## Examples
  
      iex> ValidationCache.store(%{
      ...>   forge_account_id: 1,
      ...>   repository: "org/repo",
      ...>   locations: [%{file_path: "app.js", line: 42}],
      ...>   vulnerability_type: "sql-injection",
      ...>   file_hashes: %{"app.js" => "sha256:abc123"},
      ...>   is_false_positive: true,
      ...>   confidence: 0.95,
      ...>   reason: "No user input flow"
      ...> })
      {:ok, %CachedValidation{...}}
  """
  def store(attrs) do
    cache_key = generate_cache_key(attrs)
    
    attrs_with_metadata = attrs
    |> add_cache_key(cache_key)
    |> add_timestamps()
    
    insert_or_update_cache(attrs_with_metadata)
  end
  
  # Private functions
  
  defp generate_cache_key(attrs) do
    KeyGenerator.generate_key(
      attrs.forge_account_id,
      attrs.repository,
      attrs.locations,
      attrs.vulnerability_type
    )
  end
  
  defp add_cache_key(attrs, cache_key) do
    Map.put(attrs, :cache_key, cache_key)
  end
  
  defp add_timestamps(attrs) do
    now = DateTime.utc_now()
    
    attrs
    |> Map.put(:cached_at, now)
    |> Map.put(:ttl_expires_at, DateTime.add(now, @ttl_days, :day))
  end
  
  defp insert_or_update_cache(attrs) do
    result = %CachedValidation{}
    |> CachedValidation.changeset(attrs)
    |> Repo.insert(
      on_conflict: {:replace_all_except, [:id]},
      conflict_target: :cache_key,
      returning: true
    )
    
    case result do
      {:ok, cached} ->
        Logger.debug("Cached validation stored", 
          cache_key: cached.cache_key,
          is_false_positive: cached.is_false_positive
        )
        {:ok, cached}
        
      {:error, changeset} ->
        Logger.warn("Failed to store cached validation",
          errors: inspect(changeset.errors)
        )
        {:error, changeset}
    end
  end
end