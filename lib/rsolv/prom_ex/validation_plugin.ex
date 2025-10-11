defmodule Rsolv.PromEx.ValidationPlugin do
  @moduledoc """
  PromEx plugin for RFC-060 validation and mitigation metrics.

  Tracks metrics for the VALIDATE and MITIGATE phases:
  - Validation execution count and success rate
  - Test generation and execution duration
  - Mitigation trust scores
  - Phase-level performance metrics

  Emits metrics based on telemetry events from Rsolv.Phases context.
  """
  use PromEx.Plugin

  @impl true
  def event_metrics(_opts) do
    [
      # Validation phase metrics
      validation_execution_metrics(),
      validation_performance_metrics(),
      validation_outcome_metrics(),

      # Mitigation phase metrics
      mitigation_execution_metrics(),
      mitigation_performance_metrics(),
      mitigation_trust_metrics()
    ]
    |> List.flatten()
  end

  @impl true
  def polling_metrics(_opts) do
    []
  end

  @impl true
  def manual_metrics(_opts) do
    []
  end

  # Validation execution counters
  defp validation_execution_metrics do
    [
      counter("rsolv.validation.executions.total",
        event_name: [:rsolv, :validation, :complete],
        description: "Total number of validation phase executions",
        tags: [:repo, :language, :framework, :status],
        tag_values: &validation_tags/1
      ),

      counter("rsolv.validation.test_generated.total",
        event_name: [:rsolv, :validation, :test_generated],
        description: "Total number of validation tests generated",
        tags: [:repo, :language, :framework, :test_type],
        tag_values: &validation_test_tags/1
      ),

      counter("rsolv.validation.test_executed.total",
        event_name: [:rsolv, :validation, :test_executed],
        description: "Total number of validation tests executed",
        tags: [:repo, :language, :framework, :result],
        tag_values: &validation_test_execution_tags/1
      )
    ]
  end

  # Validation performance metrics (durations)
  defp validation_performance_metrics do
    [
      distribution("rsolv.validation.test_generation.duration.milliseconds",
        event_name: [:rsolv, :validation, :test_generated],
        measurement: :duration,
        description: "Duration of validation test generation in milliseconds",
        tags: [:repo, :language, :framework],
        tag_values: &validation_test_tags/1,
        unit: {:native, :millisecond},
        reporter_options: [
          buckets: [10, 50, 100, 250, 500, 1000, 2500, 5000, 10000, 30000]
        ]
      ),

      distribution("rsolv.validation.test_execution.duration.milliseconds",
        event_name: [:rsolv, :validation, :test_executed],
        measurement: :duration,
        description: "Duration of validation test execution in milliseconds",
        tags: [:repo, :language, :framework],
        tag_values: &validation_test_execution_tags/1,
        unit: {:native, :millisecond},
        reporter_options: [
          buckets: [100, 500, 1000, 2500, 5000, 10000, 30000, 60000]
        ]
      ),

      distribution("rsolv.validation.total.duration.milliseconds",
        event_name: [:rsolv, :validation, :complete],
        measurement: :duration,
        description: "Total duration of validation phase in milliseconds",
        tags: [:repo, :language, :framework],
        tag_values: &validation_tags/1,
        unit: {:native, :millisecond},
        reporter_options: [
          buckets: [1000, 5000, 10000, 30000, 60000, 120000, 300000]
        ]
      )
    ]
  end

  # Validation outcome metrics (success rates, etc)
  defp validation_outcome_metrics do
    [
      last_value("rsolv.validation.success_rate.percent",
        event_name: [:rsolv, :validation, :complete],
        measurement: :success_rate,
        description: "Success rate of validation phase executions (0-100)",
        tags: [:repo, :language, :framework],
        tag_values: &validation_tags/1
      ),

      last_value("rsolv.validation.tests_generated.count",
        event_name: [:rsolv, :validation, :complete],
        measurement: :tests_generated,
        description: "Number of tests generated in validation phase",
        tags: [:repo, :language, :framework],
        tag_values: &validation_tags/1
      ),

      last_value("rsolv.validation.tests_passed.count",
        event_name: [:rsolv, :validation, :complete],
        measurement: :tests_passed,
        description: "Number of tests that passed in validation phase",
        tags: [:repo, :language, :framework],
        tag_values: &validation_tags/1
      ),

      last_value("rsolv.validation.tests_failed.count",
        event_name: [:rsolv, :validation, :complete],
        measurement: :tests_failed,
        description: "Number of tests that failed in validation phase",
        tags: [:repo, :language, :framework],
        tag_values: &validation_tags/1
      )
    ]
  end

  # Mitigation execution counters
  defp mitigation_execution_metrics do
    [
      counter("rsolv.mitigation.executions.total",
        event_name: [:rsolv, :mitigation, :complete],
        description: "Total number of mitigation phase executions",
        tags: [:repo, :language, :framework, :status],
        tag_values: &mitigation_tags/1
      ),

      counter("rsolv.mitigation.pr_created.total",
        event_name: [:rsolv, :mitigation, :pr_created],
        description: "Total number of mitigation PRs created",
        tags: [:repo, :language, :framework],
        tag_values: &mitigation_tags/1
      )
    ]
  end

  # Mitigation performance metrics
  defp mitigation_performance_metrics do
    [
      distribution("rsolv.mitigation.total.duration.milliseconds",
        event_name: [:rsolv, :mitigation, :complete],
        measurement: :duration,
        description: "Total duration of mitigation phase in milliseconds",
        tags: [:repo, :language, :framework],
        tag_values: &mitigation_tags/1,
        unit: {:native, :millisecond},
        reporter_options: [
          buckets: [1000, 5000, 10000, 30000, 60000, 120000, 300000, 600000]
        ]
      )
    ]
  end

  # Mitigation trust score metrics
  defp mitigation_trust_metrics do
    [
      distribution("rsolv.mitigation.trust_score.value",
        event_name: [:rsolv, :mitigation, :trust_score],
        measurement: :trust_score,
        description: "Trust score for mitigation (0-100)",
        tags: [:repo, :language, :framework],
        tag_values: &mitigation_trust_score_tags/1,
        reporter_options: [
          buckets: [0, 25, 50, 60, 70, 80, 90, 95, 100]
        ]
      ),

      last_value("rsolv.mitigation.trust_score.latest",
        event_name: [:rsolv, :mitigation, :trust_score],
        measurement: :trust_score,
        description: "Latest trust score for mitigation (0-100)",
        tags: [:repo, :language, :framework],
        tag_values: &mitigation_trust_score_tags/1
      )
    ]
  end

  # Tag extraction functions
  defp validation_tags(metadata) do
    %{
      repo: extract_repo(metadata),
      language: extract_language(metadata),
      framework: extract_framework(metadata),
      status: extract_status(metadata)
    }
  end

  defp validation_test_tags(metadata) do
    %{
      repo: extract_repo(metadata),
      language: extract_language(metadata),
      framework: extract_framework(metadata),
      test_type: Map.get(metadata, :test_type, "unknown")
    }
  end

  defp validation_test_execution_tags(metadata) do
    %{
      repo: extract_repo(metadata),
      language: extract_language(metadata),
      framework: extract_framework(metadata),
      result: Map.get(metadata, :result, "unknown")
    }
  end

  defp mitigation_tags(metadata) do
    %{
      repo: extract_repo(metadata),
      language: extract_language(metadata),
      framework: extract_framework(metadata),
      status: extract_status(metadata)
    }
  end

  defp mitigation_trust_score_tags(metadata) do
    %{
      repo: extract_repo(metadata),
      language: extract_language(metadata),
      framework: extract_framework(metadata)
    }
  end

  # Helper functions for extracting tag values
  defp extract_repo(metadata) do
    case Map.get(metadata, :repo) do
      nil -> "unknown"
      repo when is_binary(repo) -> repo
      _ -> "unknown"
    end
  end

  defp extract_language(metadata) do
    case Map.get(metadata, :language) do
      nil -> "unknown"
      lang when is_binary(lang) -> lang
      lang when is_atom(lang) -> Atom.to_string(lang)
      _ -> "unknown"
    end
  end

  defp extract_framework(metadata) do
    case Map.get(metadata, :framework) do
      nil -> "none"
      framework when is_binary(framework) -> framework
      framework when is_atom(framework) -> Atom.to_string(framework)
      _ -> "none"
    end
  end

  defp extract_status(metadata) do
    case Map.get(metadata, :status) do
      nil -> "unknown"
      status when is_binary(status) -> status
      status when is_atom(status) -> Atom.to_string(status)
      _ -> "unknown"
    end
  end
end
