defmodule Rsolv.PromEx.ValidationPlugin do
  @moduledoc """
  PromEx plugin for RFC-060 validation and mitigation metrics.
  """
  use PromEx.Plugin

  @impl true
  def event_metrics(_opts) do
    Event.build(
      :rfc_060_validation_metrics,
      [
        # Test Integration API metrics (RFC-060 - Backend)
        counter(
          [:rsolv, :test_integration, :analyze, :total],
          event_name: [:rsolv, :test_integration, :analyze],
          description: "Total test file analysis requests",
          tags: [:customer_id, :language, :framework, :status],
          tag_values: &extract_integration_tags/1
        ),
        counter(
          [:rsolv, :test_integration, :generate, :total],
          event_name: [:rsolv, :test_integration, :generate],
          description: "Total test integration requests",
          tags: [:customer_id, :language, :framework, :method, :status],
          tag_values: &extract_generate_tags/1
        ),

        # Test Integration duration distributions
        distribution(
          [:rsolv, :test_integration, :analyze, :duration, :milliseconds],
          event_name: [:rsolv, :test_integration, :analyze],
          measurement: :duration,
          description: "Test file analysis duration",
          tags: [:customer_id, :language, :framework],
          tag_values: &extract_integration_tags_success/1,
          unit: {:native, :millisecond},
          reporter_options: [buckets: [10, 50, 100, 250, 500, 1000, 2000]]
        ),
        distribution(
          [:rsolv, :test_integration, :generate, :duration, :milliseconds],
          event_name: [:rsolv, :test_integration, :generate],
          measurement: :duration,
          description: "Test integration duration",
          tags: [:customer_id, :language, :framework, :method],
          tag_values: &extract_generate_tags_success/1,
          unit: {:native, :millisecond},
          reporter_options: [buckets: [100, 500, 1000, 2000, 5000, 10_000, 30_000]]
        ),

        # Test Integration quality metrics
        distribution(
          [:rsolv, :test_integration, :generate, :lines, :integrated],
          event_name: [:rsolv, :test_integration, :generate],
          measurement: :lines_integrated,
          description: "Lines of test code integrated",
          tags: [:customer_id, :language, :framework],
          tag_values: &extract_integration_tags_success/1,
          reporter_options: [buckets: [5, 10, 20, 50, 100, 200]]
        ),

        # Legacy RFC-060 metrics (for future frontend implementation)
        # These are kept for dashboard compatibility but won't have data until
        # frontend push metrics are implemented

        # Validation counters (FUTURE)
        counter(
          [:rsolv, :validation, :executions, :total],
          event_name: [:rsolv, :validation, :complete],
          description: "Total validation executions (frontend workflow)",
          tags: [:repo, :language, :framework, :status],
          tag_values: &extract_validation_tags/1
        ),
        counter(
          [:rsolv, :validation, :test_generated, :total],
          event_name: [:rsolv, :validation, :test_generated],
          description: "Total tests generated (frontend workflow)",
          tags: [:repo, :language, :framework],
          tag_values: &extract_base_tags/1
        ),

        # Validation duration distribution (FUTURE)
        distribution(
          [:rsolv, :validation, :duration, :milliseconds],
          event_name: [:rsolv, :validation, :complete],
          measurement: :duration,
          description: "Validation phase duration (frontend workflow)",
          tags: [:repo, :language, :framework],
          tag_values: &extract_base_tags/1,
          unit: {:native, :millisecond},
          reporter_options: [buckets: [1000, 5000, 10_000, 30_000, 60_000, 120_000, 300_000]]
        ),

        # Mitigation counters (FUTURE)
        counter(
          [:rsolv, :mitigation, :executions, :total],
          event_name: [:rsolv, :mitigation, :complete],
          description: "Total mitigation executions (frontend workflow)",
          tags: [:repo, :language, :framework, :status],
          tag_values: &extract_validation_tags/1
        ),

        # Trust score distribution (FUTURE)
        distribution(
          [:rsolv, :mitigation, :trust_score, :value],
          event_name: [:rsolv, :mitigation, :trust_score],
          measurement: :trust_score,
          description: "Mitigation trust scores (frontend workflow)",
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

  # Test Integration API tags
  defp extract_integration_tags(metadata) do
    %{
      customer_id: to_string_safe(Map.get(metadata, :customer_id, "unknown")),
      language: to_string_safe(Map.get(metadata, :language, "unknown")),
      framework: to_string_safe(Map.get(metadata, :framework, "unknown")),
      status: to_string_safe(Map.get(metadata, :status, "unknown"))
    }
  end

  defp extract_integration_tags_success(metadata) do
    # Only extract for successful requests (status = completed)
    if Map.get(metadata, :status) == "completed" do
      %{
        customer_id: to_string_safe(Map.get(metadata, :customer_id, "unknown")),
        language: to_string_safe(Map.get(metadata, :language, "unknown")),
        framework: to_string_safe(Map.get(metadata, :framework, "unknown"))
      }
    else
      :skip
    end
  end

  defp extract_generate_tags(metadata) do
    %{
      customer_id: to_string_safe(Map.get(metadata, :customer_id, "unknown")),
      language: to_string_safe(Map.get(metadata, :language, "unknown")),
      framework: to_string_safe(Map.get(metadata, :framework, "unknown")),
      method: to_string_safe(Map.get(metadata, :method, "unknown")),
      status: to_string_safe(Map.get(metadata, :status, "unknown"))
    }
  end

  defp extract_generate_tags_success(metadata) do
    # Only extract for successful requests (status = completed)
    if Map.get(metadata, :status) == "completed" do
      %{
        customer_id: to_string_safe(Map.get(metadata, :customer_id, "unknown")),
        language: to_string_safe(Map.get(metadata, :language, "unknown")),
        framework: to_string_safe(Map.get(metadata, :framework, "unknown")),
        method: to_string_safe(Map.get(metadata, :method, "unknown"))
      }
    else
      :skip
    end
  end

  # Legacy validation tags (for future frontend implementation)
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
  defp to_string_safe(value) when is_integer(value), do: Integer.to_string(value)
  defp to_string_safe(_), do: "unknown"
end
