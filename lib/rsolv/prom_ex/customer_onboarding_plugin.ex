defmodule Rsolv.PromEx.CustomerOnboardingPlugin do
  @moduledoc """
  PromEx plugin for RFC-065 customer onboarding metrics.

  Tracks customer signup, provisioning, and onboarding flow metrics.

  ## Metrics

  - `rsolv.customer_onboarding.complete.total` - Counter of successful onboardings
  - `rsolv.customer_onboarding.failed.total` - Counter of failed onboarding attempts
  - `rsolv.customer_onboarding.duration.milliseconds` - Distribution of onboarding durations
  """
  use PromEx.Plugin
  import Rsolv.PromEx.Helpers

  @impl true
  def event_metrics(_opts) do
    Event.build(
      :customer_onboarding_metrics,
      [
        counter(
          [:rsolv, :customer_onboarding, :complete, :total],
          event_name: [:rsolv, :customer_onboarding, :complete],
          description: "Total successful customer onboarding completions",
          tags: [:status, :source],
          tag_values: &extract_base_tags/1
        ),
        counter(
          [:rsolv, :customer_onboarding, :failed, :total],
          event_name: [:rsolv, :customer_onboarding, :failed],
          description: "Total failed customer onboarding attempts",
          tags: [:source, :reason],
          tag_values: &extract_failure_tags/1
        ),
        distribution(
          [:rsolv, :customer_onboarding, :duration, :milliseconds],
          event_name: [:rsolv, :customer_onboarding, :complete],
          measurement: :duration,
          description: "Customer onboarding completion duration",
          tags: [:source],
          tag_values: &extract_success_tags/1,
          unit: {:native, :millisecond},
          reporter_options: [buckets: [100, 250, 500, 1000, 2000, 5000, 10_000]]
        )
      ]
    )
  end

  @impl true
  def polling_metrics(_opts), do: []

  @impl true
  def manual_metrics(_opts), do: []

  # Tag extraction functions

  defp extract_base_tags(metadata) do
    %{
      status: extract_tag(metadata, :status),
      source: extract_tag(metadata, :source)
    }
  end

  defp extract_success_tags(metadata) do
    if Map.get(metadata, :status) == "success" do
      %{source: extract_tag(metadata, :source)}
    else
      :skip
    end
  end

  defp extract_failure_tags(metadata) do
    %{
      source: extract_tag(metadata, :source),
      reason: metadata |> Map.get(:reason, "unknown") |> categorize_error()
    }
  end
end
