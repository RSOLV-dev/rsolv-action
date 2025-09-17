defmodule Rsolv.Telemetry.ValidationReporter do
  @moduledoc """
  Telemetry reporter for AST validation metrics.
  Subscribes to validation events and reports them to monitoring systems.
  """
  use GenServer
  require Logger

  alias Rsolv.Utils.MathHelpers

  @metrics_interval :timer.seconds(60)  # Report metrics every 60 seconds

  def start_link(opts) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  def init(_opts) do
    # Attach telemetry handlers
    :telemetry.attach_many(
      "validation-reporter",
      [
        [:rsolv, :validation, :request],
        [:rsolv, :validation, :false_positive],
        [:rsolv, :validation, :cache_hit],
        [:rsolv, :validation, :cache_miss]
      ],
      &handle_event/4,
      nil
    )

    # Schedule periodic metric reporting
    Process.send_after(self(), :report_metrics, @metrics_interval)

    {:ok, %{
      requests: %{total: 0, success: 0, error: 0},
      durations: [],
      false_positives: %{total: 0, rejected: 0},
      cache: %{hits: 0, misses: 0},
      pattern_rejections: %{}
    }}
  end

  def handle_event([:rsolv, :validation, :request], measurements, metadata, _config) do
    GenServer.cast(__MODULE__, {:request, measurements, metadata})
  end

  def handle_event([:rsolv, :validation, :false_positive], measurements, metadata, _config) do
    GenServer.cast(__MODULE__, {:false_positive, measurements, metadata})
  end

  def handle_event([:rsolv, :validation, :cache_hit], _measurements, _metadata, _config) do
    GenServer.cast(__MODULE__, :cache_hit)
  end

  def handle_event([:rsolv, :validation, :cache_miss], _measurements, _metadata, _config) do
    GenServer.cast(__MODULE__, :cache_miss)
  end

  def handle_cast({:request, measurements, metadata}, state) do
    new_state = state
    |> update_in([:requests, :total], &(&1 + 1))
    |> update_in([:requests, metadata.result], &((&1 || 0) + 1))
    |> update_in([:durations], &([measurements.duration | &1] |> Enum.take(1000)))  # Keep last 1000

    {:noreply, new_state}
  end

  def handle_cast({:false_positive, measurements, metadata}, state) do
    new_state = state
    |> update_in([:false_positives, :total], &(&1 + measurements.total_count))
    |> update_in([:false_positives, :rejected], &(&1 + measurements.rejected_count))

    # Track which patterns are being rejected
    pattern_state = Enum.reduce(metadata.pattern_ids || [], new_state.pattern_rejections, fn pattern_id, acc ->
      Map.update(acc, pattern_id, 1, &(&1 + 1))
    end)

    {:noreply, %{new_state | pattern_rejections: pattern_state}}
  end

  def handle_cast(:cache_hit, state) do
    {:noreply, update_in(state, [:cache, :hits], &(&1 + 1))}
  end

  def handle_cast(:cache_miss, state) do
    {:noreply, update_in(state, [:cache, :misses], &(&1 + 1))}
  end

  def handle_info(:report_metrics, state) do
    # Calculate metrics
    if state.requests.total > 0 do
      # Calculate durations
      durations = Enum.sort(state.durations)
      p50 = percentile(durations, 0.5)
      p95 = percentile(durations, 0.95)
      p99 = percentile(durations, 0.99)

      # Calculate rates
      false_positive_rate = if state.false_positives.total > 0 do
        (state.false_positives.rejected / state.false_positives.total) * 100
      else
        0.0
      end

      cache_hit_rate = if (state.cache.hits + state.cache.misses) > 0 do
        (state.cache.hits / (state.cache.hits + state.cache.misses)) * 100
      else
        0.0
      end

      # Log metrics
      Logger.info("""
      AST Validation Metrics (last 60s):
      =====================================
      Requests: #{state.requests.total} (Success: #{state.requests.success}, Error: #{state.requests.error})
      Response Times: p50=#{p50}ms, p95=#{p95}ms, p99=#{p99}ms
      False Positive Rate: #{MathHelpers.safe_round(false_positive_rate, 2)}% (#{state.false_positives.rejected}/#{state.false_positives.total})
      Cache Hit Rate: #{MathHelpers.safe_round(cache_hit_rate, 2)}% (#{state.cache.hits} hits, #{state.cache.misses} misses)
      """)

      # Log top rejected patterns
      if map_size(state.pattern_rejections) > 0 do
        top_patterns = state.pattern_rejections
        |> Enum.sort_by(fn {_, count} -> -count end)
        |> Enum.take(5)
        |> Enum.map(fn {pattern, count} -> "  #{pattern}: #{count}" end)
        |> Enum.join("\n")

        Logger.info("Top Rejected Patterns:\n#{top_patterns}")
      end

      # Report to external monitoring (Prometheus/Grafana)
      report_to_prometheus(state, %{
        p50: p50,
        p95: p95,
        p99: p99,
        false_positive_rate: false_positive_rate,
        cache_hit_rate: cache_hit_rate
      })
    end

    # Reset counters for next interval
    Process.send_after(self(), :report_metrics, @metrics_interval)
    
    {:noreply, %{state | 
      requests: %{total: 0, success: 0, error: 0},
      durations: [],
      false_positives: %{total: 0, rejected: 0},
      cache: %{hits: 0, misses: 0},
      pattern_rejections: %{}
    }}
  end

  defp percentile([], _), do: 0
  defp percentile(sorted_list, p) do
    k = round(p * (length(sorted_list) - 1))
    Enum.at(sorted_list, k, 0)
  end

  defp report_to_prometheus(state, calculated_metrics) do
    # This would integrate with your Prometheus exporter
    # For now, we'll use Telemetry.Metrics format
    measurements = %{
      request_count: state.requests.total,
      request_duration_p50: calculated_metrics.p50,
      request_duration_p95: calculated_metrics.p95,
      request_duration_p99: calculated_metrics.p99,
      false_positive_rate: calculated_metrics.false_positive_rate,
      cache_hit_rate: calculated_metrics.cache_hit_rate
    }

    :telemetry.execute([:rsolv, :validation, :metrics], measurements, %{})
  end
end