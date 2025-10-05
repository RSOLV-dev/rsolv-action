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

  # Normalize forge_account_id to string (field is :string type)
  defp normalize_forge_account_id(id) when is_integer(id), do: Integer.to_string(id)
  defp normalize_forge_account_id(id) when is_binary(id), do: id

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
    # Ensure forge_account_id is a string (support both integer and string IDs)
    attrs = ensure_forge_account_id_string(attrs)

    cache_key = generate_cache_key(attrs)

    attrs_with_metadata = attrs
    |> add_cache_key(cache_key)
    |> add_timestamps()

    insert_or_update_cache(attrs_with_metadata)
  end

  # Private functions

  defp ensure_forge_account_id_string(%{forge_account_id: id} = attrs) when is_integer(id) do
    Map.put(attrs, :forge_account_id, to_string(id))
  end
  defp ensure_forge_account_id_string(attrs), do: attrs
  
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
  
  @doc """
  Retrieves a cached validation result if it exists and is valid.
  
  Checks cache validity based on TTL expiration and optional file hash validation.
  This is the primary method for checking if we've already validated a vulnerability
  as a false positive.
  
  ## Parameters
  
    - forge_account_id: Integer ID of the forge account
    - repository: String repository identifier (e.g., "RSOLV-dev/nodegoat")
    - locations: List of location maps with :file_path and :line keys
    - vulnerability_type: String vulnerability type (e.g., "sql-injection")
    - file_hashes: Optional map of file paths to SHA-256 hashes for validation
  
  ## Returns
  
    - `{:ok, cached_validation}` - Cache hit with valid entry
    - `{:miss, nil}` - No cache entry found
    - `{:expired, nil}` - Entry found but past TTL
    - `{:invalidated, nil}` - Entry found but file content changed
  
  ## Examples
  
      # Basic retrieval without file hash checking
      iex> ValidationCache.get(1, "org/repo", [%{file_path: "app.js", line: 42}], "xss")
      {:ok, %CachedValidation{...}}
      
      # With file hash validation
      iex> ValidationCache.get(
      ...>   1, "org/repo", 
      ...>   [%{file_path: "app.js", line: 42}],
      ...>   "xss",
      ...>   %{"app.js" => "sha256:abc123"}
      ...> )
      {:invalidated, nil}  # If hash doesn't match
  
  ## Cache Hit Rate Tracking
  
  The return tuple's first element can be used to track cache effectiveness:
  - `:ok` = cache hit
  - `:miss`, `:expired`, `:invalidated` = cache miss
  """
  def get(forge_account_id, repository, locations, vulnerability_type, file_hashes \\ nil) do
    cache_key = generate_lookup_key(forge_account_id, repository, locations, vulnerability_type)
    
    cache_key
    |> fetch_cache_entry()
    |> validate_cache_entry(file_hashes)
    |> log_cache_result(cache_key)
  end
  
  # Private retrieval functions
  
  defp generate_lookup_key(forge_account_id, repository, locations, vulnerability_type) do
    KeyGenerator.generate_key(
      forge_account_id,
      repository,
      locations,
      vulnerability_type
    )
  end
  
  defp fetch_cache_entry(cache_key) do
    # Don't return invalidated entries
    query = from c in CachedValidation,
      where: c.cache_key == ^cache_key,
      where: is_nil(c.invalidated_at)
    
    case Repo.one(query) do
      nil -> {:miss, nil}
      cached -> {:found, cached}
    end
  end
  
  defp validate_cache_entry({:miss, nil}, _file_hashes), do: {:miss, nil}
  
  defp validate_cache_entry({:found, cached}, file_hashes) do
    cond do
      entry_expired?(cached) ->
        {:expired, nil}
        
      hashes_mismatch?(cached, file_hashes) ->
        {:invalidated, nil}
        
      true ->
        {:ok, cached}
    end
  end
  
  defp entry_expired?(cached) do
    DateTime.compare(DateTime.utc_now(), cached.ttl_expires_at) == :gt
  end
  
  defp hashes_mismatch?(_cached, nil), do: false
  defp hashes_mismatch?(cached, provided_hashes) do
    !Map.equal?(cached.file_hashes, provided_hashes)
  end
  
  defp log_cache_result(result, cache_key) do
    case result do
      {:ok, _cached} ->
        Logger.debug("Cache hit", cache_key: cache_key)
        
      {:miss, _} ->
        Logger.debug("Cache miss", cache_key: cache_key)
        
      {:expired, _} ->
        Logger.debug("Cache expired", cache_key: cache_key)
        
      {:invalidated, _} ->
        Logger.debug("Cache invalidated by file change", cache_key: cache_key)
    end
    
    result
  end
  
  # Cache Invalidation Functions
  
  @doc """
  Invalidates a specific cache entry by ID.
  
  Marks the entry as invalidated with a timestamp and reason, preventing
  it from being returned by future cache lookups.
  
  ## Parameters
  
    - cache_id: Integer ID of the cache entry
    - reason: Atom or string reason for invalidation
      - `:file_change` or `"file_change"` - File content changed
      - `:ttl_expired` or `"ttl_expired"` - TTL expiration
      - `:manual` or `"manual"` - Manual invalidation
  
  ## Returns
  
    - `{:ok, invalidated_entry}` on success
    - `{:error, :not_found}` if entry doesn't exist
  
  ## Examples
  
      iex> ValidationCache.invalidate(123, :file_change)
      {:ok, %CachedValidation{invalidated_at: ~U[...], invalidation_reason: "file_change"}}
      
      iex> ValidationCache.invalidate(999999, :manual)
      {:error, :not_found}
  """
  def invalidate(cache_id, reason) when is_atom(reason) do
    invalidate(cache_id, Atom.to_string(reason))
  end
  
  def invalidate(cache_id, reason) when is_binary(reason) do
    with {:fetch, cached} when not is_nil(cached) <- {:fetch, Repo.get(CachedValidation, cache_id)},
         {:update, {:ok, invalidated}} <- {:update, do_invalidate(cached, reason)} do
      Logger.info("Cache entry invalidated", 
        cache_id: cache_id,
        reason: reason
      )
      {:ok, invalidated}
    else
      {:fetch, nil} -> 
        {:error, :not_found}
      {:update, {:error, changeset}} -> 
        {:error, changeset}
    end
  end
  
  @doc """
  Invalidates all cache entries containing a specific file.
  
  This is the primary invalidation method called when a file is modified.
  It finds all cache entries where the file appears in the locations array
  and marks them as invalidated.
  
  ## Parameters
  
    - forge_account_id: Integer ID of the forge account
    - repository: String repository identifier (e.g., "RSOLV-dev/nodegoat")
    - file_path: String path of the file that changed (e.g., "app/routes/profile.js")
  
  ## Returns
  
    - `{:ok, count}` with number of invalidated entries
  
  ## Examples
  
      iex> ValidationCache.invalidate_by_file(1, "org/repo", "app.js")
      {:ok, 3}  # Invalidated 3 cache entries containing app.js
      
      iex> ValidationCache.invalidate_by_file(1, "org/repo", "nonexistent.js")
      {:ok, 0}  # No entries to invalidate
  
  ## Performance Note
  
  Uses PostgreSQL JSONB operators for efficient array searching.
  The query is optimized with indexes on forge_account_id and repository.
  """
  def invalidate_by_file(forge_account_id, repository, file_path) do
    count = forge_account_id
    |> build_file_invalidation_query(repository, file_path)
    |> perform_bulk_invalidation("file_change")
    
    Logger.info("Invalidated cache entries for file change",
      forge_account_id: forge_account_id,
      repository: repository,
      file_path: file_path,
      count: count
    )
    
    {:ok, count}
  end
  
  @doc """
  Invalidates all cache entries for a repository.
  
  Used for bulk invalidation when major changes occur to a repository
  (e.g., branch switch, rebase, force push).
  
  ## Parameters
  
    - forge_account_id: Integer ID of the forge account
    - repository: String repository identifier
  
  ## Returns
  
    - `{:ok, count}` with number of invalidated entries
  
  ## Examples
  
      iex> ValidationCache.invalidate_by_repository(1, "org/repo")
      {:ok, 42}  # Invalidated all 42 cache entries for the repository
  """
  def invalidate_by_repository(forge_account_id, repository) do
    count = forge_account_id
    |> build_repository_invalidation_query(repository)
    |> perform_bulk_invalidation("repository_change")
    
    Logger.info("Invalidated all cache entries for repository",
      forge_account_id: forge_account_id,
      repository: repository,
      count: count
    )
    
    {:ok, count}
  end
  
  # Private invalidation helpers
  
  defp do_invalidate(cached, reason) do
    cached
    |> Ecto.Changeset.change(%{
      invalidated_at: DateTime.utc_now(),
      invalidation_reason: reason
    })
    |> Repo.update()
  end
  
  defp build_file_invalidation_query(forge_account_id, repository, file_path) do
    forge_account_id_str = normalize_forge_account_id(forge_account_id)

    from c in CachedValidation,
      where: c.forge_account_id == ^forge_account_id_str,
      where: c.repository == ^repository,
      where: is_nil(c.invalidated_at),
      where: fragment(
        "EXISTS (SELECT 1 FROM jsonb_array_elements(?) AS loc WHERE loc->>'file_path' = ?)",
        c.locations, 
        ^file_path
      )
  end
  
  defp build_repository_invalidation_query(forge_account_id, repository) do
    forge_account_id_str = normalize_forge_account_id(forge_account_id)

    from c in CachedValidation,
      where: c.forge_account_id == ^forge_account_id_str,
      where: c.repository == ^repository,
      where: is_nil(c.invalidated_at)
  end
  
  defp perform_bulk_invalidation(query, reason) do
    {count, _} = Repo.update_all(query, 
      set: [
        invalidated_at: DateTime.utc_now(),
        invalidation_reason: reason
      ]
    )
    count
  end
end