defmodule Rsolv.PromEx.ValidationPlugin do
  @moduledoc """
  PromEx plugin for RFC-060 validation and mitigation metrics.
  """
  use PromEx.Plugin
  alias Telemetry.Metrics

  @impl true
  def event_metrics(_opts) do
    Event.build(
      :rfc_060_validation_metrics,
      [
        # Validation counters
        counter(
          [:rsolv, :validation, :executions, :total],
          event_name: [:rsolv, :validation, :complete],
          description: "Total validation executions",
          tags: [:repo, :language, :framework, :status],
          tag_values: &extract_validation_tags/1
        ),

        counter(
          [:rsolv, :validation, :test_generated, :total],
          event_name: [:rsolv, :validation, :test_generated],
          description: "Total tests generated",
          tags: [:repo, :language, :framework],
          tag_values: &extract_base_tags/1
        ),

        # Validation duration distribution
        distribution(
          [:rsolv, :validation, :duration, :milliseconds],
          event_name: [:rsolv, :validation, :complete],
          measurement: :duration,
          description: "Validation phase duration",
          tags: [:repo, :language, :framework],
          tag_values: &extract_base_tags/1,
          unit: {:native, :millisecond},
          reporter_options: [buckets: [1000, 5000, 10000, 30000, 60000, 120000, 300000]]
        ),

        # Mitigation counters
        counter(
          [:rsolv, :mitigation, :executions, :total],
          event_name: [:rsolv, :mitigation, :complete],
          description: "Total mitigation executions",
          tags: [:repo, :language, :framework, :status],
          tag_values: &extract_validation_tags/1
        ),

        # Trust score distribution
        distribution(
          [:rsolv, :mitigation, :trust_score, :value],
          event_name: [:rsolv, :mitigation, :trust_score],
          measurement: :trust_score,
          description: "Mitigation trust scores",
          tags: [:repo, :language, :framework],
          tag_values: &extract_base_tags/1,
          reporter_options: [buckets: [0, 25, 50, 60, 70, 80, 90, 95, 100]]
        )
      ]
    )
  end

  @impl true
  def polling_metrics(_opts), do: []

  @impl true
  def manual_metrics(_opts), do: []

  # Tag extraction functions
  defp extract_validation_tags(metadata) do
    %{
      repo: Map.get(metadata, :repo, "unknown"),
      language: to_string_safe(Map.get(metadata, :language, "unknown")),
      framework: to_string_safe(Map.get(metadata, :framework, "none")),
      status: to_string_safe(Map.get(metadata, :status, "unknown"))
    }
  end

  defp extract_base_tags(metadata) do
    %{
      repo: Map.get(metadata, :repo, "unknown"),
      language: to_string_safe(Map.get(metadata, :language, "unknown")),
      framework: to_string_safe(Map.get(metadata, :framework, "none"))
    }
  end

  defp to_string_safe(value) when is_binary(value), do: value
  defp to_string_safe(value) when is_atom(value), do: Atom.to_string(value)
  defp to_string_safe(_), do: "unknown"
end
