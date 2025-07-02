defmodule RsolvApi.Security.PatternTelemetry do
  @moduledoc """
  Telemetry instrumentation for pattern operations.
  
  Emits the following events:
  - [:pattern, :fetch] - Pattern fetch duration
  - [:pattern, :cache, :hit] - Cache hit
  - [:pattern, :cache, :miss] - Cache miss
  - [:pattern, :compile] - AST rule compilation
  - [:pattern, :match] - Pattern matching operation
  - [:ai, :review] - AI review operation
  """
  
  use GenServer
  require Logger
  
  def start_link(opts) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end
  
  @impl true
  def init(_opts) do
    # Attach telemetry handlers
    handlers = [
      {[:pattern, :fetch], &handle_pattern_fetch/4},
      {[:pattern, :cache, :hit], &handle_cache_event/4},
      {[:pattern, :cache, :miss], &handle_cache_event/4},
      {[:pattern, :compile], &handle_compile_event/4},
      {[:pattern, :match], &handle_match_event/4},
      {[:ai, :review], &handle_ai_review/4}
    ]
    
    Enum.each(handlers, fn {event, handler} ->
      :telemetry.attach(
        "#{__MODULE__}-#{Enum.join(event, "-")}",
        event,
        handler,
        nil
      )
    end)
    
    # Start metrics aggregation
    schedule_metrics_report()
    
    {:ok, %{metrics: %{}}}
  end
  
  @impl true
  def handle_info(:report_metrics, state) do
    report_metrics(state.metrics)
    schedule_metrics_report()
    
    # Reset some metrics
    {:noreply, %{state | metrics: reset_metrics(state.metrics)}}
  end
  
  # Telemetry Handlers
  
  defp handle_pattern_fetch(_event, measurements, metadata, _config) do
    duration_ms = measurements.duration / 1_000_000
    
    Logger.debug("Pattern fetch completed",
      language: metadata.language,
      tier: Map.get(metadata, :tier, "all"),
      duration_ms: duration_ms
    )
    
    # Update Prometheus metrics if available
    if function_exported?(:prometheus_histogram, :observe, 2) do
      :prometheus_histogram.observe(
        :pattern_fetch_duration_milliseconds,
        [metadata.language, to_string(Map.get(metadata, :tier, "all"))],
        duration_ms
      )
    end
  end
  
  defp handle_cache_event([:pattern, :cache, type], _measurements, metadata, _config) do
    Logger.debug("Pattern cache #{type}",
      language: metadata.language,
      tier: Map.get(metadata, :tier, "all")
    )
    
    # Increment counter
    if function_exported?(:prometheus_counter, :inc, 2) do
      :prometheus_counter.inc(
        :pattern_cache_operations_total,
        [to_string(type), metadata.language, to_string(Map.get(metadata, :tier, "all"))]
      )
    end
  end
  
  defp handle_compile_event(_event, measurements, metadata, _config) do
    duration_ms = measurements.duration / 1_000_000
    
    Logger.info("Pattern compilation completed",
      pattern_id: metadata.pattern_id,
      duration_ms: duration_ms
    )
  end
  
  defp handle_match_event(_event, measurements, metadata, _config) do
    duration_ms = measurements.duration / 1_000_000
    
    Logger.debug("Pattern match completed",
      pattern_id: metadata.pattern_id,
      matched: metadata.matched,
      confidence: metadata.confidence,
      duration_ms: duration_ms
    )
    
    # Track match rates
    if function_exported?(:prometheus_counter, :inc, 2) do
      :prometheus_counter.inc(
        :pattern_matches_total,
        [metadata.pattern_id, to_string(metadata.matched)]
      )
    end
  end
  
  defp handle_ai_review(_event, measurements, metadata, _config) do
    duration_ms = measurements.duration / 1_000_000
    
    Logger.info("AI review completed",
      pattern_id: metadata.pattern_id,
      confidence_before: metadata.confidence_before,
      confidence_after: metadata.confidence_after,
      duration_ms: duration_ms,
      cost: metadata.cost
    )
    
    # Track AI costs
    if function_exported?(:prometheus_counter, :inc, 2) do
      :prometheus_counter.inc(
        :ai_review_cost_cents,
        [metadata.provider],
        round(metadata.cost * 100)
      )
    end
  end
  
  # Metrics Reporting
  
  defp schedule_metrics_report do
    # Report every 5 minutes
    Process.send_after(self(), :report_metrics, :timer.minutes(5))
  end
  
  defp report_metrics(metrics) do
    Logger.info("Pattern system metrics report", metrics)
    
    # Could send to external monitoring service
    # ExternalMetrics.send(metrics)
  end
  
  defp reset_metrics(metrics) do
    # Keep cumulative metrics, reset per-interval metrics
    Map.take(metrics, [:total_patterns, :cache_size])
  end
  
  # Public API for custom metrics
  
  @doc """
  Record a custom metric.
  """
  def record_metric(name, value, metadata \\ %{}) do
    :telemetry.execute(
      [:pattern, :custom, name],
      %{value: value},
      metadata
    )
  end
end