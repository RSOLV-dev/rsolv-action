defmodule RsolvWeb.Telemetry.ValidationTelemetry do
  @moduledoc """
  Telemetry events for AST validation monitoring (RFC-036).

  Emits the following events:
  - [:rsolv, :validation, :request] - For each validation request
  - [:rsolv, :validation, :false_positive] - For false positive tracking
  - [:rsolv, :validation, :cache_hit] - For cache hit tracking
  - [:rsolv, :validation, :cache_miss] - For cache miss tracking
  """

  @doc """
  Emit validation request telemetry event.
  """
  def emit_validation_request(start_time, validation_results, cached? \\ false) do
    duration = System.monotonic_time(:millisecond) - start_time

    :telemetry.execute(
      [:rsolv, :validation, :request],
      %{
        duration: duration,
        vulnerabilities_count: length(validation_results.validated),
        rejected_count: Map.get(validation_results.stats, "rejected", 0),
        validated_count: Map.get(validation_results.stats, "validated", 0),
        false_positive_rate: calculate_false_positive_rate(validation_results)
      },
      %{
        result: :success,
        cached: cached?
      }
    )
  end

  @doc """
  Emit validation error telemetry event.
  """
  def emit_validation_error(start_time, error) do
    duration = System.monotonic_time(:millisecond) - start_time

    :telemetry.execute(
      [:rsolv, :validation, :request],
      %{
        duration: duration,
        vulnerabilities_count: 0,
        rejected_count: 0,
        validated_count: 0
      },
      %{
        result: :error,
        error: inspect(error)
      }
    )
  end

  @doc """
  Emit false positive detection telemetry event.
  """
  def emit_false_positive(validation_results, customer_id) do
    rejected_vulns =
      Enum.filter(validation_results.validated, fn v ->
        !Map.get(v, "isValid", true)
      end)

    if length(rejected_vulns) > 0 do
      :telemetry.execute(
        [:rsolv, :validation, :false_positive],
        %{
          rejected_count: Map.get(validation_results.stats, "rejected", 0),
          total_count: Map.get(validation_results.stats, "total", 0),
          reduction_rate: calculate_false_positive_rate(validation_results)
        },
        %{
          customer_id: customer_id,
          pattern_ids:
            Enum.map(rejected_vulns, fn v -> Map.get(v, "patternId") end)
            |> Enum.uniq()
            |> Enum.reject(&is_nil/1)
        }
      )
    end
  end

  @doc """
  Emit cache hit event.
  """
  def emit_cache_hit() do
    :telemetry.execute(
      [:rsolv, :validation, :cache_hit],
      %{count: 1},
      %{}
    )
  end

  @doc """
  Emit cache miss event.
  """
  def emit_cache_miss() do
    :telemetry.execute(
      [:rsolv, :validation, :cache_miss],
      %{count: 1},
      %{}
    )
  end

  # Private functions

  defp calculate_false_positive_rate(%{stats: stats}) do
    total = Map.get(stats, "total", 0)
    rejected = Map.get(stats, "rejected", 0)

    if total > 0 do
      rejected / total * 100
    else
      0.0
    end
  end

  defp calculate_false_positive_rate(_), do: 0.0
end
