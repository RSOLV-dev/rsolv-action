defmodule Rsolv.Security.PatternServer do
  @moduledoc """
  GenServer for managing security patterns with hot-reloading and caching.
  
  This server provides:
  - Fast concurrent reads via ETS
  - Hot reloading of patterns
  - Pattern compilation and caching
  - Telemetry events for monitoring
  """
  
  use GenServer
  require Logger
  
  @ets_table :security_patterns
  @refresh_interval :timer.minutes(5)
  
  # Client API
  
  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end
  
  @doc """
  Get patterns for a specific language.
  
  ## Examples
  
      iex> PatternServer.get_patterns("javascript")
      {:ok, [%Pattern{}, ...]}
  """
  def get_patterns(language) when is_binary(language) do
    start_time = System.monotonic_time()
    
    result = case :ets.lookup(@ets_table, language) do
      [{_key, patterns}] ->
        :telemetry.execute([:pattern, :cache, :hit], %{count: 1}, %{language: language})
        {:ok, patterns}
      [] ->
        :telemetry.execute([:pattern, :cache, :miss], %{count: 1}, %{language: language})
        GenServer.call(__MODULE__, {:load_patterns, language})
    end
    
    duration = System.monotonic_time() - start_time
    :telemetry.execute([:pattern, :fetch], %{duration: duration}, %{language: language})
    
    result
  end
  
  # Backward compatibility for tier-based calls
  def get_patterns(language, _tier) when is_binary(language) do
    get_patterns(language)
  end
  
  @doc """
  Reload all patterns from modules.
  """
  def reload_patterns do
    GenServer.cast(__MODULE__, :reload_patterns)
  end
  
  @doc """
  Get pattern statistics.
  """
  def get_stats do
    GenServer.call(__MODULE__, :get_stats)
  end
  
  # Server Callbacks
  
  @impl true
  def init(_opts) do
    # Create ETS table with optimal settings for concurrent reads
    :ets.new(@ets_table, [
      :named_table,
      :set,
      :public,
      read_concurrency: true,
      write_concurrency: :auto
    ])
    
    # Load patterns asynchronously
    {:ok, %{loaded_at: nil, stats: %{}}, {:continue, :initial_load}}
  end
  
  @impl true
  def handle_continue(:initial_load, state) do
    Logger.info("PatternServer: Loading initial patterns...")
    
    stats = load_all_patterns()
    schedule_refresh()
    
    {:noreply, %{state | loaded_at: DateTime.utc_now(), stats: stats}}
  end
  
  @impl true
  def handle_call({:load_patterns, language}, _from, state) do
    Logger.debug("PatternServer: Loading patterns for #{language}")
    
    patterns = load_patterns_for(language)
    
    # Cache the loaded patterns
    :ets.insert(@ets_table, {language, patterns})
    
    {:reply, {:ok, patterns}, state}
  end
  
  @impl true
  def handle_call(:get_stats, _from, state) do
    stats = Map.merge(state.stats, %{
      loaded_at: state.loaded_at,
      ets_size: :ets.info(@ets_table, :size),
      memory: :ets.info(@ets_table, :memory)
    })
    
    {:reply, stats, state}
  end
  
  @impl true
  def handle_cast(:reload_patterns, state) do
    Logger.info("PatternServer: Reloading all patterns...")
    
    stats = load_all_patterns()
    
    {:noreply, %{state | loaded_at: DateTime.utc_now(), stats: stats}}
  end
  
  @impl true
  def handle_info(:refresh_patterns, state) do
    Logger.debug("PatternServer: Scheduled pattern refresh")
    
    stats = load_all_patterns()
    schedule_refresh()
    
    {:noreply, %{state | stats: stats}}
  end
  
  # Private Functions
  
  defp load_all_patterns do
    languages = ["javascript", "python", "ruby", "java", "elixir", "php", "django", "rails", "common"]
    
    # Load patterns for each language
    stats = for language <- languages, reduce: %{total: 0, by_language: %{}} do
      acc ->
        patterns = load_patterns_for(language)
        
        # Store patterns by language only
        :ets.insert(@ets_table, {language, patterns})
        
        acc
        |> Map.update(:total, length(patterns), &(&1 + length(patterns)))
        |> Map.put(:by_language, Map.put(acc.by_language, language, length(patterns)))
    end
    
    Logger.info("PatternServer: Loaded #{stats.total} unique patterns")
    Logger.info("Patterns by language: #{inspect(stats.by_language)}")
    stats
  end
  
  defp load_patterns_for(language) do
    # Get the appropriate module
    module = get_pattern_module(language)
    
    # Check if enhanced patterns are enabled
    if Application.get_env(:rsolv, :use_enhanced_patterns, false) do
      enhanced_module = get_enhanced_pattern_module(language)
      
      if Code.ensure_loaded?(enhanced_module) and function_exported?(enhanced_module, :all, 0) do
        apply(enhanced_module, :all, [])
      else
        # Fallback to standard patterns
        get_standard_patterns(module)
      end
    else
      get_standard_patterns(module)
    end
  end
  
  defp get_standard_patterns(module) do
    if Code.ensure_loaded?(module) and function_exported?(module, :all, 0) do
      apply(module, :all, [])
    else
      []
    end
  end
  
  defp get_pattern_module("javascript"), do: Rsolv.Security.Patterns.Javascript
  defp get_pattern_module("python"), do: Rsolv.Security.Patterns.Python
  defp get_pattern_module("ruby"), do: Rsolv.Security.Patterns.Ruby
  defp get_pattern_module("java"), do: Rsolv.Security.Patterns.Java
  defp get_pattern_module("elixir"), do: Rsolv.Security.Patterns.Elixir
  defp get_pattern_module("php"), do: Rsolv.Security.Patterns.Php
  defp get_pattern_module("django"), do: Rsolv.Security.Patterns.Django
  defp get_pattern_module("rails"), do: Rsolv.Security.Patterns.Rails
  defp get_pattern_module("common"), do: Rsolv.Security.Patterns.Common
  defp get_pattern_module("cve"), do: Rsolv.Security.Patterns.Cve
  defp get_pattern_module(_), do: nil
  
  defp get_enhanced_pattern_module(language) do
    Module.concat(Rsolv.Security.Patterns, "#{String.capitalize(language)}Enhanced")
  end
  
  defp schedule_refresh do
    Process.send_after(self(), :refresh_patterns, @refresh_interval)
  end
end