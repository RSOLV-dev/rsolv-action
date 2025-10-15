defmodule Rsolv.ValidationCacheHelpers do
  @moduledoc """
  Helper functions for validation cache testing.

  Provides common test data builders and assertion helpers
  for validation cache tests.
  """

  import ExUnit.Assertions
  alias Rsolv.ValidationCache

  @doc """
  Builds default validation data for testing.

  ## Options
    - :forge_account_id - Required
    - :repository - Defaults to "RSOLV-dev/nodegoat"
    - :locations - Defaults to single location
    - :vulnerability_type - Defaults to "sql-injection"
    - :file_hashes - Auto-generated from locations
    - :is_false_positive - Defaults to true
    - :confidence - Defaults to 0.95
    - :reason - Defaults to "Test reason"
  """
  def build_validation_data(opts) do
    forge_account_id = Keyword.fetch!(opts, :forge_account_id)
    repository = Keyword.get(opts, :repository, "RSOLV-dev/nodegoat")
    locations = Keyword.get(opts, :locations, [%{file_path: "app.js", line: 42}])
    vulnerability_type = Keyword.get(opts, :vulnerability_type, "sql-injection")

    # Auto-generate file hashes if not provided
    file_hashes =
      Keyword.get_lazy(opts, :file_hashes, fn ->
        locations
        |> Enum.map(& &1.file_path)
        |> Enum.uniq()
        |> Map.new(fn path ->
          {path, "sha256:#{:crypto.hash(:sha256, path) |> Base.encode16()}"}
        end)
      end)

    %{
      forge_account_id: forge_account_id,
      repository: repository,
      locations: locations,
      vulnerability_type: vulnerability_type,
      file_hashes: file_hashes,
      is_false_positive: Keyword.get(opts, :is_false_positive, true),
      confidence: Keyword.get(opts, :confidence, 0.95),
      reason: Keyword.get(opts, :reason, "Test reason")
    }
  end

  @doc """
  Asserts a cache lookup returns the expected result type.

  ## Examples
      assert_cache_hit(result)
      assert_cache_miss(result)
      assert_cache_expired(result)
      assert_cache_invalidated(result)
  """
  def assert_cache_hit({:ok, cached}) when not is_nil(cached), do: cached

  def assert_cache_hit(result) do
    flunk("Expected cache hit {:ok, cached}, got: #{inspect(result)}")
  end

  def assert_cache_miss({:miss, nil}), do: :ok

  def assert_cache_miss(result) do
    flunk("Expected cache miss {:miss, nil}, got: #{inspect(result)}")
  end

  def assert_cache_expired({:expired, nil}), do: :ok

  def assert_cache_expired(result) do
    flunk("Expected cache expired {:expired, nil}, got: #{inspect(result)}")
  end

  def assert_cache_invalidated({:invalidated, nil}), do: :ok

  def assert_cache_invalidated(result) do
    flunk("Expected cache invalidated {:invalidated, nil}, got: #{inspect(result)}")
  end

  @doc """
  Calculates cache statistics from a list of cache operations.

  ## Example
      operations = [
        ValidationCache.get(...),  # Returns {:miss, nil}
        ValidationCache.get(...),  # Returns {:ok, cached}
        ValidationCache.get(...)   # Returns {:invalidated, nil}
      ]

      stats = calculate_cache_stats(operations)
      # => %{hits: 1, misses: 1, invalidated: 1, expired: 0, hit_rate: 33.33}
  """
  def calculate_cache_stats(operations) do
    stats =
      Enum.reduce(operations, %{hits: 0, misses: 0, expired: 0, invalidated: 0}, fn
        {:ok, _}, acc -> %{acc | hits: acc.hits + 1}
        {:miss, _}, acc -> %{acc | misses: acc.misses + 1}
        {:expired, _}, acc -> %{acc | expired: acc.expired + 1}
        {:invalidated, _}, acc -> %{acc | invalidated: acc.invalidated + 1}
        _, acc -> acc
      end)

    total = stats.hits + stats.misses + stats.expired + stats.invalidated
    hit_rate = if total > 0, do: stats.hits / total * 100, else: 0

    Map.put(stats, :hit_rate, hit_rate)
  end

  @doc """
  Measures the execution time of a function and asserts it's under a threshold.

  ## Example
      assert_performance(10_000, fn ->
        ValidationCache.get(...)
      end)
      # Asserts the operation completes in under 10ms
  """
  def assert_performance(max_microseconds, fun) do
    {time, result} = :timer.tc(fun)

    if time > max_microseconds do
      flunk("Operation took #{time}μs, expected under #{max_microseconds}μs")
    end

    result
  end

  @doc """
  Creates multiple cache entries for performance testing.

  ## Example
      create_bulk_cache_entries(forge_account_id, 100)
      # Creates 100 cache entries with unique files
  """
  def create_bulk_cache_entries(forge_account_id, count, repository \\ "test/repo") do
    for i <- 1..count do
      data =
        build_validation_data(
          forge_account_id: forge_account_id,
          repository: repository,
          locations: [%{file_path: "file#{i}.js", line: i * 10}],
          vulnerability_type: random_vulnerability_type(),
          confidence: 0.5 + :rand.uniform() * 0.5,
          reason: "Bulk test entry #{i}"
        )

      {:ok, cached} = ValidationCache.store(data)
      cached
    end
  end

  defp random_vulnerability_type do
    Enum.random(["sql-injection", "xss", "eval", "hardcoded-secret", "path-traversal"])
  end
end
