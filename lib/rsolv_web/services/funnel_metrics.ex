defmodule RsolvWeb.Services.FunnelMetrics do
  @moduledoc """
  Implementation of Prometheus metrics specifically for the signup funnel.
  This module defines and tracks metrics for the entire signup funnel process from 
  initial page visit to completed signup.
  """
  require Logger
  alias RsolvWeb.Services.PrometheusHelper
  alias RsolvWeb.Services.Metrics
  
  # Funnel stage metrics
  @funnel_stage_counter :rsolv_signup_funnel_stage_total
  @funnel_completion_counter :rsolv_signup_funnel_completion_total
  @funnel_dropoff_counter :rsolv_signup_funnel_dropoff_total
  @funnel_conversion_time :rsolv_signup_funnel_conversion_time_seconds
  
  # Define funnel stages in order
  @funnel_stages [
    "page_visit",       # Initial landing page visit
    "signup_view",      # User viewed the signup form
    "form_interact",    # User interacted with the form (typing)
    "form_submit",      # User submitted the form
    "validation_pass",  # Form passed validation
    "confirmation_sent", # Confirmation email sent
    "confirmation_open", # User opened confirmation email
    "account_complete"  # User completed account setup
  ]
  
  @doc """
  Initialize all funnel metrics. Should be called when the application starts.
  """
  def setup do
    if PrometheusHelper.metrics_available?() do
      # Counter for total visitors at each funnel stage
      PrometheusHelper.declare_counter(
        name: @funnel_stage_counter,
        help: "Number of visitors reaching each funnel stage",
        labels: [:stage, :source]
      )
      
      # Counter for funnel completion
      PrometheusHelper.declare_counter(
        name: @funnel_completion_counter,
        help: "Number of completed signup funnels from start to finish",
        labels: [:source]
      )
      
      # Counter for dropoffs at each stage
      PrometheusHelper.declare_counter(
        name: @funnel_dropoff_counter,
        help: "Number of visitors who dropped off at each funnel stage",
        labels: [:stage, :source]
      )
      
      # Histogram for time to convert from first page visit to signup
      PrometheusHelper.declare_histogram(
        name: @funnel_conversion_time,
        help: "Time in seconds from first page visit to successful signup",
        labels: [:source],
        buckets: [10, 30, 60, 120, 300, 600, 1800, 3600, 7200]
      )
      
      :ok
    else
      Logger.info("Funnel metrics module loaded but monitoring is disabled")
      :ok
    end
  end
  
  @doc """
  Track a visitor reaching a specific stage in the signup funnel.
  
  ## Parameters
  
  - `stage`: The funnel stage reached (string or atom)
  - `source`: The traffic source (optional, defaults to "unknown")
  - `session_id`: The visitor's session ID (optional)
  - `timestamp`: The timestamp of the event (optional)
  
  ## Returns
  
  - `:ok`
  """
  def track_funnel_stage(stage, source \\ "unknown", session_id \\ nil, timestamp \\ nil) do
    stage = to_string(stage)
    source = source || "unknown"
    
    # Increment the stage counter
    PrometheusHelper.increment_counter(
      name: @funnel_stage_counter, 
      labels: [stage, source]
    )
    
    # If this is the final stage, increment the completion counter
    if stage == List.last(@funnel_stages) do
      track_funnel_completion(source, session_id, timestamp)
    end
    
    :ok
  end
  
  @doc """
  Track a visitor dropping off at a specific stage in the signup funnel.
  
  ## Parameters
  
  - `stage`: The funnel stage where dropoff occurred (string or atom)
  - `source`: The traffic source (optional, defaults to "unknown")
  
  ## Returns
  
  - `:ok`
  """
  def track_funnel_dropoff(stage, source \\ "unknown") do
    stage = to_string(stage)
    source = source || "unknown"
    
    PrometheusHelper.increment_counter(
      name: @funnel_dropoff_counter, 
      labels: [stage, source]
    )
    
    :ok
  end
  
  @doc """
  Track a completed signup funnel, recording the time taken.
  
  ## Parameters
  
  - `source`: The traffic source (defaults to "unknown")
  - `session_id`: The visitor's session ID (optional)
  - `timestamp`: The completion timestamp (optional)
  - `start_timestamp`: The funnel start timestamp (optional)
  
  ## Returns
  
  - `:ok`
  """
  def track_funnel_completion(source \\ "unknown", _session_id \\ nil, timestamp \\ nil, start_timestamp \\ nil) do
    source = source || "unknown"
    
    # Increment completion counter
    PrometheusHelper.increment_counter(
      name: @funnel_completion_counter, 
      labels: [source]
    )
    
    # Also increment the standard signup counter
    Metrics.count_signup()
    Metrics.count_signup_by_source(source)
    
    # Record conversion time if we have start and end timestamps
    if timestamp && start_timestamp do
      conversion_time = DateTime.diff(timestamp, start_timestamp)
      
      PrometheusHelper.observe_histogram(
        name: @funnel_conversion_time,
        labels: [source],
        value: conversion_time
      )
    end
    
    :ok
  end
  
  @doc """
  Get all the defined funnel stages in order.
  
  ## Returns
  
  - List of funnel stage names
  """
  def get_funnel_stages do
    @funnel_stages
  end
  
  @doc """
  Convert analytics data to funnel metrics and send to Prometheus.
  This allows historical analytics data to be used to populate Prometheus
  metrics for dashboard visualization.
  
  ## Parameters
  
  - `analytics_data`: Map with page_views, form_events, and conversions data
  
  ## Returns
  
  - `:ok`
  """
  def backfill_metrics_from_analytics(analytics_data) do
    # Only proceed if Prometheus is available
    if PrometheusHelper.metrics_available?() do
      try do
        %{
          "page_views" => page_views,
          "form_events" => form_events,
          "conversions" => conversions
        } = analytics_data
        
        # Group by session ID (could be IP or other identifier)
        sessions = group_by_session(page_views, form_events, conversions)
        
        # Process each session through the funnel
        Enum.each(sessions, fn {session_id, events} ->
          process_session_funnel(session_id, events)
        end)
        
        :ok
      rescue
        e ->
          Logger.error("Failed to backfill metrics from analytics: #{inspect(e)}")
          :error
      end
    else
      :not_available
    end
  end
  
  # Group events by session ID
  defp group_by_session(page_views, form_events, conversions) do
    # This is a simplified implementation
    # In a real system, you would use proper session tracking
    # For this example, we'll use IP or a session cookie
    
    # Combine all events into a single list with a session ID
    all_events = 
      (page_views |> Enum.map(fn ev -> Map.put(ev, "type", "page_view") end)) ++
      (form_events |> Enum.map(fn ev -> Map.put(ev, "type", "form_event") end)) ++
      (conversions |> Enum.map(fn ev -> Map.put(ev, "type", "conversion") end))
    
    # Group by a session identifier (simplified)
    all_events
    |> Enum.group_by(fn event -> 
      event["session_id"] || event["user_id"] || event["ip"] || event["email"] || "unknown"
    end)
  end
  
  # Process a single user's session through the funnel
  defp process_session_funnel(session_id, events) do
    # Sort events by timestamp
    sorted_events = Enum.sort_by(events, fn event -> event["timestamp"] end)
    
    # Extract the source if available
    source = 
      events
      |> Enum.find_value("unknown", fn
        %{"utm_source" => source} when not is_nil(source) -> source
        %{"source" => source} when not is_nil(source) -> source
        _ -> nil
      end)
    
    # Track each reached stage
    {reached_stages, _} = Enum.reduce(@funnel_stages, {[], nil}, fn stage, {stages, last_time} ->
      case find_stage_event(sorted_events, stage) do
        nil -> {stages, last_time}
        event -> 
          track_funnel_stage(stage, source, session_id, event["timestamp"])
          {[stage | stages], event["timestamp"]}
      end
    end)
    
    # If we have a full completion and timestamps, record conversion time
    if Enum.count(reached_stages) == Enum.count(@funnel_stages) do
      first_event = List.first(sorted_events)
      last_event = List.last(sorted_events)
      
      if first_event && last_event do
        first_time = first_event["timestamp"]
        last_time = last_event["timestamp"]
        
        track_funnel_completion(source, session_id, last_time, first_time)
      end
    end
    
    # Find where the funnel was abandoned
    last_reached_stage = List.first(reached_stages) || "none"
    next_stage_index = Enum.find_index(@funnel_stages, &(&1 == last_reached_stage)) + 1
    
    if next_stage_index < Enum.count(@funnel_stages) do
      dropoff_stage = Enum.at(@funnel_stages, next_stage_index)
      track_funnel_dropoff(dropoff_stage, source)
    end
  end
  
  # Find the event corresponding to a funnel stage
  defp find_stage_event(events, stage) do
    case stage do
      "page_visit" ->
        Enum.find(events, &(&1["type"] == "page_view" && &1["path"] == "/"))
        
      "signup_view" ->
        Enum.find(events, &(&1["type"] == "page_view" && &1["path"] == "/signup")) ||
        Enum.find(events, &(&1["type"] == "form_event" && &1["event"] == "form_view" && &1["form"] == "signup"))
        
      "form_interact" ->
        Enum.find(events, &(&1["type"] == "form_event" && &1["event"] == "form_change" && &1["form"] == "signup"))
        
      "form_submit" ->
        Enum.find(events, &(&1["type"] == "form_event" && &1["event"] == "form_submit" && &1["form"] == "signup"))
        
      "validation_pass" ->
        Enum.find(events, &(&1["type"] == "form_event" && &1["event"] == "form_valid" && &1["form"] == "signup"))
        
      "confirmation_sent" ->
        Enum.find(events, &(&1["type"] == "conversion" && &1["event"] == "signup"))
        
      "confirmation_open" ->
        Enum.find(events, &(&1["type"] == "email_event" && &1["event"] == "open" && &1["type"] == "confirmation"))
        
      "account_complete" ->
        Enum.find(events, &(&1["type"] == "conversion" && &1["event"] == "account_setup"))
        
      _ ->
        nil
    end
  end
end