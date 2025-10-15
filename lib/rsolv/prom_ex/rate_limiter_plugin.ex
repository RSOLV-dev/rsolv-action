defmodule Rsolv.PromEx.RateLimiterPlugin do
  @moduledoc """
  PromEx plugin for rate limiter metrics.
  """
  use PromEx.Plugin

  import Telemetry.Metrics

  @impl true
  def event_metrics(_opts) do
    [
      # Rate limit exceeded counter
      counter("rsolv.rate_limiter.limit_exceeded.total",
        event_name: [:rsolv, :rate_limiter, :limit_exceeded],
        description: "Total number of rate limit exceeded events",
        tags: [:customer_id, :action]
      ),

      # Requests allowed counter
      counter("rsolv.rate_limiter.requests_allowed.total",
        event_name: [:rsolv, :rate_limiter, :request_allowed],
        description: "Total number of requests allowed by rate limiter",
        tags: [:customer_id, :action]
      ),

      # Current count gauge (shows current usage within window)
      last_value("rsolv.rate_limiter.current_count",
        event_name: [:rsolv, :rate_limiter, :request_allowed],
        measurement: :current_count,
        description: "Current count of requests in the rate limit window",
        tags: [:customer_id, :action]
      )
    ]
  end

  @impl true
  def polling_metrics(_opts) do
    []
  end

  @impl true
  def manual_metrics(_opts) do
    []
  end
end
