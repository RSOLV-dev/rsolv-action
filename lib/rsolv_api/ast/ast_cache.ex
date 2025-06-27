defmodule RsolvApi.AST.ASTCache do
  @moduledoc """
  High-performance AST caching layer with TTL expiration and memory management.
  
  Features:
  - File hash-based caching with language specificity
  - Configurable TTL with optional refresh-on-access
  - Memory usage tracking and automatic eviction
  - Cache warming for frequently accessed files
  - Concurrent access safe operations
  - Detailed metrics and monitoring
  """
  
  use GenServer
  require Logger
  
  @default_max_entries 10_000
  @default_max_memory_mb 500
  @default_ttl_seconds 3600  # 1 hour
  @cleanup_interval_ms 60_000  # 1 minute
  
  defmodule CacheEntry do
    @enforce_keys [:ast, :language, :inserted_at, :last_accessed_at]
    defstruct [
      :ast,
      :language,
      :inserted_at,
      :last_accessed_at,
      :access_count,
      :size_bytes
    ]
  end
  
  defmodule CacheState do
    @enforce_keys [:config]
    defstruct [
      :config,
      entries: %{},
      stats: %{
        total_entries: 0,
        hit_count: 0,
        miss_count: 0,
        eviction_count: 0,
        memory_usage_bytes: 0
      }
    ]
  end
  
  defmodule CacheConfig do
    @enforce_keys []
    defstruct [
      max_entries: 10_000,
      max_memory_mb: 500,
      ttl_seconds: 3600,
      refresh_ttl_on_access: false,
      enable_memory_tracking: true
    ]
  end
  
  # Client API
  
  def start_link(config \\ %{}) do
    GenServer.start_link(__MODULE__, config)
  end
  
  def get(cache, file_hash, language) do
    GenServer.call(cache, {:get, file_hash, language})
  end
  
  def put(cache, file_hash, ast, language) do
    GenServer.cast(cache, {:put, file_hash, ast, language})
  end
  
  def invalidate(cache, file_hash, language) do
    GenServer.cast(cache, {:invalidate, file_hash, language})
  end
  
  def invalidate_by_language(cache, language) do
    GenServer.call(cache, {:invalidate_by_language, language})
  end
  
  def get_cache_stats(cache) do
    GenServer.call(cache, :get_cache_stats)
  end
  
  def get_config(cache) do
    GenServer.call(cache, :get_config)
  end
  
  def warm_cache(cache, files, ast_generator_fn) do
    GenServer.call(cache, {:warm_cache, files, ast_generator_fn})
  end
  
  # Server callbacks
  
  @impl true
  def init(config) do
    cache_config = %CacheConfig{
      max_entries: config[:max_entries] || @default_max_entries,
      max_memory_mb: config[:max_memory_mb] || @default_max_memory_mb,
      ttl_seconds: config[:ttl_seconds] || @default_ttl_seconds,
      refresh_ttl_on_access: config[:refresh_ttl_on_access] || false,
      enable_memory_tracking: config[:enable_memory_tracking] != false
    }
    
    state = %CacheState{
      config: cache_config,
      entries: %{},
      stats: %{
        total_entries: 0,
        hit_count: 0,
        miss_count: 0,
        eviction_count: 0,
        memory_usage_bytes: 0
      }
    }
    
    # Schedule periodic cleanup
    Process.send_after(self(), :cleanup_expired, @cleanup_interval_ms)
    
    {:ok, state}
  end
  
  @impl true
  def handle_call({:get, file_hash, language}, _from, state) do
    cache_key = {file_hash, language}
    now = System.system_time(:second)
    
    case Map.get(state.entries, cache_key) do
      nil ->
        # Cache miss
        updated_stats = %{state.stats | miss_count: state.stats.miss_count + 1}
        updated_state = %{state | stats: updated_stats}
        {:reply, {:miss, :not_found}, updated_state}
        
      entry ->
        # Check TTL expiration
        if expired?(entry, now, state.config.ttl_seconds, state.config.refresh_ttl_on_access) do
          # Expired entry
          updated_entries = Map.delete(state.entries, cache_key)
          updated_stats = %{state.stats | 
            miss_count: state.stats.miss_count + 1,
            total_entries: state.stats.total_entries - 1,
            memory_usage_bytes: state.stats.memory_usage_bytes - (entry.size_bytes || 0)
          }
          updated_state = %{state | entries: updated_entries, stats: updated_stats}
          {:reply, {:miss, :expired}, updated_state}
        else
          # Cache hit
          updated_entry = if state.config.refresh_ttl_on_access do
            %{entry | 
              last_accessed_at: now,
              access_count: (entry.access_count || 0) + 1
            }
          else
            %{entry | 
              access_count: (entry.access_count || 0) + 1
            }
          end
          
          updated_entries = Map.put(state.entries, cache_key, updated_entry)
          updated_stats = %{state.stats | hit_count: state.stats.hit_count + 1}
          updated_state = %{state | entries: updated_entries, stats: updated_stats}
          
          {:reply, {:ok, entry.ast}, updated_state}
        end
    end
  end
  
  @impl true
  def handle_call({:invalidate_by_language, language}, _from, state) do
    {entries_to_remove, remaining_entries} = Enum.split_with(state.entries, fn
      {{_hash, lang}, _entry} -> lang == language
    end)
    
    removed_count = length(entries_to_remove)
    removed_memory = Enum.reduce(entries_to_remove, 0, fn {_key, entry}, acc ->
      acc + (entry.size_bytes || 0)
    end)
    
    updated_stats = %{state.stats |
      total_entries: state.stats.total_entries - removed_count,
      memory_usage_bytes: state.stats.memory_usage_bytes - removed_memory
    }
    
    updated_state = %{state |
      entries: Map.new(remaining_entries),
      stats: updated_stats
    }
    
    {:reply, removed_count, updated_state}
  end
  
  @impl true
  def handle_call(:get_cache_stats, _from, state) do
    {:reply, state.stats, state}
  end
  
  @impl true
  def handle_call(:get_config, _from, state) do
    {:reply, state.config, state}
  end
  
  @impl true
  def handle_call({:warm_cache, files, ast_generator_fn}, _from, state) do
    {warmed_count, updated_state} = Enum.reduce(files, {0, state}, fn {file_or_hash, language}, {count, acc_state} ->
      cache_key = {file_or_hash, language}
      
      # Skip if already cached
      if Map.has_key?(acc_state.entries, cache_key) do
        {count, acc_state}
      else
        # Generate AST and cache it
        ast = ast_generator_fn.({file_or_hash, language})
        {_, new_state} = do_put(acc_state, file_or_hash, ast, language)
        {count + 1, new_state}
      end
    end)
    
    {:reply, warmed_count, updated_state}
  end
  
  @impl true
  def handle_cast({:put, file_hash, ast, language}, state) do
    {_, updated_state} = do_put(state, file_hash, ast, language)
    {:noreply, updated_state}
  end
  
  @impl true
  def handle_cast({:invalidate, file_hash, language}, state) do
    cache_key = {file_hash, language}
    
    case Map.get(state.entries, cache_key) do
      nil ->
        {:noreply, state}
        
      entry ->
        updated_entries = Map.delete(state.entries, cache_key)
        updated_stats = %{state.stats |
          total_entries: state.stats.total_entries - 1,
          memory_usage_bytes: state.stats.memory_usage_bytes - (entry.size_bytes || 0)
        }
        
        updated_state = %{state | entries: updated_entries, stats: updated_stats}
        {:noreply, updated_state}
    end
  end
  
  @impl true
  def handle_info(:cleanup_expired, state) do
    now = System.system_time(:second)
    ttl_seconds = state.config.ttl_seconds
    
    {expired_entries, valid_entries} = Enum.split_with(state.entries, fn {_key, entry} ->
      expired?(entry, now, ttl_seconds, state.config.refresh_ttl_on_access)
    end)
    
    expired_count = length(expired_entries)
    expired_memory = Enum.reduce(expired_entries, 0, fn {_key, entry}, acc ->
      acc + (entry.size_bytes || 0)
    end)
    
    if expired_count > 0 do
      Logger.debug("Cleaned up #{expired_count} expired cache entries")
    end
    
    updated_stats = %{state.stats |
      total_entries: state.stats.total_entries - expired_count,
      memory_usage_bytes: state.stats.memory_usage_bytes - expired_memory
    }
    
    updated_state = %{state |
      entries: Map.new(valid_entries),
      stats: updated_stats
    }
    
    # Schedule next cleanup
    Process.send_after(self(), :cleanup_expired, @cleanup_interval_ms)
    
    {:noreply, updated_state}
  end
  
  # Private functions
  
  defp do_put(state, file_hash, ast, language) do
    cache_key = {file_hash, language}
    now = System.system_time(:second)
    
    # Calculate entry size if memory tracking enabled
    size_bytes = if state.config.enable_memory_tracking do
      estimate_size(ast)
    else
      0
    end
    
    new_entry = %CacheEntry{
      ast: ast,
      language: language,
      inserted_at: now,
      last_accessed_at: now,
      access_count: 0,
      size_bytes: size_bytes
    }
    
    # Check if we need to evict entries
    state_after_eviction = maybe_evict_entries(state, size_bytes)
    
    # Add new entry
    updated_entries = Map.put(state_after_eviction.entries, cache_key, new_entry)
    updated_stats = %{state_after_eviction.stats |
      total_entries: state_after_eviction.stats.total_entries + 1,
      memory_usage_bytes: state_after_eviction.stats.memory_usage_bytes + size_bytes
    }
    
    updated_state = %{state_after_eviction | entries: updated_entries, stats: updated_stats}
    {:ok, updated_state}
  end
  
  defp maybe_evict_entries(state, new_entry_size) do
    max_entries = state.config.max_entries
    max_memory_bytes = state.config.max_memory_mb * 1024 * 1024
    
    current_entries = state.stats.total_entries
    current_memory = state.stats.memory_usage_bytes
    
    cond do
      # Evict by entry count
      current_entries >= max_entries ->
        evict_lru_entries(state, current_entries - max_entries + 1)
        
      # Evict by memory usage
      state.config.enable_memory_tracking and 
      current_memory + new_entry_size > max_memory_bytes ->
        evict_until_memory_limit(state, max_memory_bytes - new_entry_size)
        
      true ->
        state
    end
  end
  
  defp evict_lru_entries(state, count_to_evict) do
    if count_to_evict <= 0 do
      state
    else
      # Sort entries by last access time (LRU first)
      sorted_entries = state.entries
      |> Enum.sort_by(fn {_key, entry} -> entry.last_accessed_at end)
      |> Enum.take(count_to_evict)
      
      evicted_memory = Enum.reduce(sorted_entries, 0, fn {_key, entry}, acc ->
        acc + (entry.size_bytes || 0)
      end)
      
      # Remove evicted entries
      entries_to_remove = MapSet.new(sorted_entries, fn {key, _entry} -> key end)
      remaining_entries = Map.drop(state.entries, MapSet.to_list(entries_to_remove))
      
      updated_stats = %{state.stats |
        total_entries: state.stats.total_entries - count_to_evict,
        eviction_count: state.stats.eviction_count + count_to_evict,
        memory_usage_bytes: state.stats.memory_usage_bytes - evicted_memory
      }
      
      %{state | entries: remaining_entries, stats: updated_stats}
    end
  end
  
  defp evict_until_memory_limit(state, target_memory) do
    if state.stats.memory_usage_bytes <= target_memory do
      state
    else
      # Sort by LRU and evict until under memory limit
      sorted_entries = state.entries
      |> Enum.sort_by(fn {_key, entry} -> entry.last_accessed_at end)
      
      {to_evict, _to_keep} = Enum.reduce_while(sorted_entries, {[], state.stats.memory_usage_bytes}, 
        fn {key, entry}, {evict_acc, current_memory} ->
          if current_memory - (entry.size_bytes || 0) <= target_memory do
            {:halt, {evict_acc, current_memory}}
          else
            {:cont, {[key | evict_acc], current_memory - (entry.size_bytes || 0)}}
          end
        end)
      
      evicted_count = length(to_evict)
      evicted_memory = Enum.reduce(to_evict, 0, fn key, acc ->
        entry = state.entries[key]
        acc + (entry.size_bytes || 0)
      end)
      
      remaining_entries = Map.drop(state.entries, to_evict)
      
      updated_stats = %{state.stats |
        total_entries: state.stats.total_entries - evicted_count,
        eviction_count: state.stats.eviction_count + evicted_count,
        memory_usage_bytes: state.stats.memory_usage_bytes - evicted_memory
      }
      
      %{state | entries: remaining_entries, stats: updated_stats}
    end
  end
  
  defp expired?(entry, now, ttl_seconds, refresh_ttl_on_access) do
    # Use last_accessed_at if refresh_ttl_on_access is enabled, otherwise inserted_at
    expiry_time = if refresh_ttl_on_access && entry.last_accessed_at do
      entry.last_accessed_at
    else
      entry.inserted_at
    end
    
    now - expiry_time > ttl_seconds
  end
  
  defp estimate_size(data) do
    # Simple size estimation - could be more sophisticated
    data
    |> Jason.encode!()
    |> byte_size()
  rescue
    _ -> 1000  # Fallback estimate
  end
end