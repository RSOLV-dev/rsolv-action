defmodule Rsolv.Cache.ValidationCache do
  @moduledoc """
  Caching layer for AST vulnerability validation results.
  Uses ETS for fast in-memory caching with TTL support.
  """

  use GenServer
  require Logger

  @table_name :validation_cache
  @stats_table :validation_cache_stats
  @default_ttl :timer.minutes(15)
  @cleanup_interval :timer.minutes(5)

  # Client API

  def start_link(_opts) do
    GenServer.start_link(__MODULE__, [], name: __MODULE__)
  end

  def get(key) do
    case :ets.lookup(@table_name, key) do
      [{^key, value, expiry}] ->
        now = System.monotonic_time(:millisecond)

        if now < expiry do
          increment_stat(:cache_hits)
          {:ok, value}
        else
          # Expired entry
          :ets.delete(@table_name, key)
          increment_stat(:cache_misses)
          :error
        end

      [] ->
        increment_stat(:cache_misses)
        :error
    end
  end

  def put(key, value, ttl \\ nil) do
    ttl = ttl || get_ttl()
    expiry = System.monotonic_time(:millisecond) + ttl
    :ets.insert(@table_name, {key, value, expiry})
    :ok
  end

  def clear_all() do
    :ets.delete_all_objects(@table_name)
    reset_stats()
    :ok
  end

  def clear() do
    :ets.delete_all_objects(@table_name)
    :ok
  end

  def clear_pattern(_pattern_id) do
    # Since we use hashed keys, we can't efficiently clear by pattern
    # For now, clear all cache when a pattern changes
    clear()
  end

  def get_stats() do
    case :ets.lookup(@stats_table, :stats) do
      [{:stats, stats}] ->
        stats

      [] ->
        %{
          "cache_hits" => 0,
          "cache_misses" => 0,
          "internal_hits" => 0
        }
    end
  end

  def increment_internal_hits() do
    increment_stat(:internal_hits)
  end

  # Server callbacks

  @impl true
  def init([]) do
    # Create ETS tables
    :ets.new(@table_name, [:named_table, :public, :set, read_concurrency: true])
    :ets.new(@stats_table, [:named_table, :public, :set])

    # Initialize stats
    reset_stats()

    # Schedule periodic cleanup
    schedule_cleanup()

    {:ok, %{}}
  end

  @impl true
  def handle_info(:cleanup, state) do
    cleanup_expired_entries()
    schedule_cleanup()
    {:noreply, state}
  end

  # Cache key generation

  def generate_key(vulnerability, file_content) do
    # Create a unique key based on vulnerability details and file content
    # Don't include ID since the same vulnerability might be reported multiple times
    # Uses standardized field names: type and file
    pattern_id = vulnerability["type"] || vulnerability[:type]
    file_path = vulnerability["file"] || vulnerability[:file]
    line = vulnerability["line"] || vulnerability[:line]
    code = vulnerability["code"] || vulnerability[:code]

    data = {
      pattern_id,
      file_path,
      line,
      code,
      # Include a hash of the file content to detect changes
      :crypto.hash(:sha256, file_content)
    }

    :erlang.phash2(data)
  end

  # Private functions

  defp get_ttl() do
    Application.get_env(:rsolv, :validation_cache_ttl, @default_ttl)
  end

  defp increment_stat(stat) do
    stat_key =
      case stat do
        :cache_hits -> "cache_hits"
        :cache_misses -> "cache_misses"
        :internal_hits -> "internal_hits"
        _ -> Atom.to_string(stat)
      end

    case :ets.lookup(@stats_table, :stats) do
      [{:stats, stats}] ->
        updated_stats = Map.update(stats, stat_key, 1, &(&1 + 1))
        :ets.insert(@stats_table, {:stats, updated_stats})

      [] ->
        :ets.insert(@stats_table, {:stats, %{stat_key => 1}})
    end
  end

  defp reset_stats() do
    :ets.insert(
      @stats_table,
      {:stats,
       %{
         "cache_hits" => 0,
         "cache_misses" => 0,
         "internal_hits" => 0
       }}
    )
  end

  defp schedule_cleanup() do
    Process.send_after(self(), :cleanup, @cleanup_interval)
  end

  defp cleanup_expired_entries() do
    now = System.monotonic_time(:millisecond)

    # Match and delete expired entries
    expired =
      :ets.select(@table_name, [
        {{:"$1", :"$2", :"$3"}, [{:<, :"$3", now}], [:"$1"]}
      ])

    Enum.each(expired, &:ets.delete(@table_name, &1))

    if length(expired) > 0 do
      Logger.debug("Cleaned up #{length(expired)} expired cache entries")
    end
  end
end
