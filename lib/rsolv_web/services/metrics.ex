defmodule RsolvWeb.Services.Metrics do
  @moduledoc """
  Prometheus metrics for the RSOLV landing page application.
  Includes system metrics, application metrics, and business metrics.
  Uses PrometheusHelper for standardized dependency handling.
  """
  require Logger
  alias RsolvWeb.Services.PrometheusHelper
  
  # Counters for HTTP requests
  @http_requests_counter :phoenix_http_requests_total
  @http_request_duration :phoenix_http_request_duration_milliseconds
  
  # Counters for business metrics
  @signups_counter :rsolv_signups_total
  @signups_by_source_counter :rsolv_signups_by_source
  @feedback_submissions_counter :rsolv_feedback_submissions_total
  @conversions_counter :rsolv_conversions_total
  
  # Celebration metrics for alerts
  @signup_events_counter :rsolv_signup_events_total
  @signups_by_domain_counter :rsolv_signups_by_domain
  @signup_milestone_gauge :rsolv_signup_milestone_reached
  
  @doc """
  Initialize all metrics. This should be called when the application starts.
  """
  def setup do
    if PrometheusHelper.metrics_available?() do
      # HTTP metrics
      PrometheusHelper.declare_counter(
        name: @http_requests_counter,
        help: "Total number of HTTP requests processed",
        labels: [:method, :path, :status]
      )
      
      PrometheusHelper.declare_histogram(
        name: @http_request_duration,
        help: "HTTP request duration in milliseconds",
        labels: [:method, :path],
        buckets: [10, 50, 100, 250, 500, 1000, 2500, 5000, 10000]
      )
      
      # Business metrics
      PrometheusHelper.declare_counter(
        name: @signups_counter,
        help: "Total number of early access signups"
      )
      
      PrometheusHelper.declare_counter(
        name: @signups_by_source_counter,
        help: "Number of signups by referral source",
        labels: [:source]
      )
      
      PrometheusHelper.declare_counter(
        name: @feedback_submissions_counter,
        help: "Total number of feedback submissions",
        labels: [:type, :status]
      )
      
      PrometheusHelper.declare_counter(
        name: @conversions_counter,
        help: "Total number of conversions by type",
        labels: [:type]
      )
      
      # Celebration metrics for alerts
      PrometheusHelper.declare_counter(
        name: @signup_events_counter,
        help: "Signup events for celebration alerts",
        labels: [:event_type]
      )
      
      PrometheusHelper.declare_counter(
        name: @signups_by_domain_counter,
        help: "Signups by email domain",
        labels: [:domain]
      )
      
      PrometheusHelper.declare_gauge(
        name: @signup_milestone_gauge,
        help: "Current signup milestone reached"
      )
      
      :ok
    else
      Logger.info("Metrics module loaded but monitoring is disabled")
      :ok
    end
  end
  
  @doc """
  Count an HTTP request with the given method, path, and status code.
  """
  def count_http_request(method, path, status) do
    PrometheusHelper.increment_counter(
      name: @http_requests_counter, 
      labels: [method, path, status]
    )
  end
  
  @doc """
  Record the duration of an HTTP request.
  """
  def observe_http_request_duration(method, path, duration_ms) do
    PrometheusHelper.observe_histogram(
      name: @http_request_duration, 
      labels: [method, path], 
      value: duration_ms
    )
  end
  
  @doc """
  Count a signup.
  """
  def count_signup do
    PrometheusHelper.increment_counter(name: @signups_counter)
  end
  
  @doc """
  Count a signup with a specific referral source.
  """
  def count_signup_by_source(source) do
    source = source || "unknown"
    PrometheusHelper.increment_counter(
      name: @signups_by_source_counter, 
      labels: [source]
    )
  end
  
  @doc """
  Count a feedback submission.
  """
  def count_feedback_submission(type, status) do
    type = type || "general"
    status = status || "success"
    
    PrometheusHelper.increment_counter(
      name: @feedback_submissions_counter, 
      labels: [type, status]
    )
  end
  
  @doc """
  Count a conversion.
  """
  def count_conversion(type) do
    type = type || "generic"
    
    PrometheusHelper.increment_counter(
      name: @conversions_counter, 
      labels: [type]
    )
  end
  
  @doc """
  Track a signup event for celebration alerts.
  """
  def track_signup_event(event_type) do
    PrometheusHelper.increment_counter(
      name: @signup_events_counter,
      labels: [event_type]
    )
  end
  
  @doc """
  Track signup by email domain.
  """
  def track_signup_by_domain(email) do
    domain = case String.split(email, "@") do
      [_, domain] -> domain
      _ -> "unknown"
    end
    
    PrometheusHelper.increment_counter(
      name: @signups_by_domain_counter,
      labels: [domain]
    )
  end
  
  @doc """
  Update signup milestone gauge.
  """
  def update_signup_milestone(count) do
    PrometheusHelper.set_gauge(
      name: @signup_milestone_gauge,
      value: count
    )
  end
end