defmodule Rsolv.Analytics do
  @moduledoc """
  Analytics service for tracking page views, events, conversions, and UTM parameters.
  
  This service provides both in-memory tracking for performance and database persistence
  for important events and conversions.
  """
  
  use GenServer
  import Ecto.Query, warn: false
  alias Rsolv.Repo
  alias Rsolv.Analytics.{Event, PageView, Conversion}
  require Logger
  
  # Client API
  
  def start_link(opts) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end
  
  @doc """
  Track a page view with optional UTM parameters and user context.
  
  ## Examples
  
      iex> Rsolv.Analytics.track_page_view("/", "127.0.0.1", %{utm_source: "twitter"})
      :ok
      
      iex> Rsolv.Analytics.track_page_view("/blog/security-patterns", "127.0.0.1", %{}, user_id: 123)
      :ok
  """
  def track_page_view(path, user_ip, utm_params \\ %{}, opts \\ []) do
    page_view = %{
      path: path,
      user_ip: anonymize_ip(user_ip),
      utm_source: Map.get(utm_params, :utm_source),
      utm_medium: Map.get(utm_params, :utm_medium),
      utm_campaign: Map.get(utm_params, :utm_campaign),
      utm_term: Map.get(utm_params, :utm_term),
      utm_content: Map.get(utm_params, :utm_content),
      user_id: Keyword.get(opts, :user_id),
      session_id: Keyword.get(opts, :session_id),
      user_agent: Keyword.get(opts, :user_agent),
      referrer: Keyword.get(opts, :referrer),
      timestamp: DateTime.utc_now()
    }
    
    GenServer.cast(__MODULE__, {:track_page_view, page_view})
  end
  
  @doc """
  Track a conversion event (signup, subscription, etc.).
  
  ## Examples
  
      iex> Rsolv.Analytics.track_conversion("early_access_signup", %{email: "user@example.com"})
      :ok
      
      iex> Rsolv.Analytics.track_conversion("api_key_created", %{customer_id: 123})
      :ok
  """
  def track_conversion(event_name, properties \\ %{}, opts \\ []) do
    conversion = %{
      event_name: event_name,
      properties: properties,
      user_id: Keyword.get(opts, :user_id),
      session_id: Keyword.get(opts, :session_id),
      timestamp: DateTime.utc_now()
    }
    
    GenServer.cast(__MODULE__, {:track_conversion, conversion})
  end
  
  @doc """
  Track a custom event.
  
  ## Examples
  
      iex> Rsolv.Analytics.track_event("button_click", %{button_id: "cta_signup"})
      :ok
  """
  def track_event(event_name, properties \\ %{}, opts \\ []) do
    event = %{
      event_name: event_name,
      properties: properties,
      user_id: Keyword.get(opts, :user_id),
      session_id: Keyword.get(opts, :session_id),
      timestamp: DateTime.utc_now()
    }
    
    GenServer.cast(__MODULE__, {:track_event, event})
  end
  
  @doc """
  Get analytics metrics for a specific time period.
  
  ## Examples
  
      iex> Rsolv.Analytics.get_metrics(Date.utc_today() |> Date.add(-7), Date.utc_today())
      %{
        page_views: 1234,
        unique_visitors: 567,
        conversions: 23,
        top_pages: [%{path: "/", views: 456}, ...],
        utm_sources: [%{source: "twitter", views: 123}, ...]
      }
  """
  def get_metrics(start_date, end_date) do
    GenServer.call(__MODULE__, {:get_metrics, start_date, end_date})
  end
  
  @doc """
  Get real-time analytics from memory.
  """
  def get_realtime_metrics do
    GenServer.call(__MODULE__, :get_realtime_metrics)
  end
  
  # Server Implementation
  
  @impl true
  def init(_opts) do
    # Initialize in-memory state for real-time tracking
    state = %{
      page_views: [],
      events: [],
      conversions: [],
      last_flush: DateTime.utc_now()
    }
    
    # Schedule periodic flush to database
    schedule_flush()
    
    {:ok, state}
  end
  
  @impl true
  def handle_cast({:track_page_view, page_view}, state) do
    # Add to in-memory tracking
    new_state = %{state | page_views: [page_view | state.page_views]}
    
    # Log for debugging
    Logger.debug("Page view tracked: #{page_view.path}")
    
    {:noreply, new_state}
  end
  
  @impl true
  def handle_cast({:track_conversion, conversion}, state) do
    # Add to in-memory tracking
    new_state = %{state | conversions: [conversion | state.conversions]}
    
    # Conversions are important - persist immediately
    Task.start(fn -> persist_conversion(conversion) end)
    
    Logger.info("Conversion tracked: #{conversion.event_name}")
    
    {:noreply, new_state}
  end
  
  @impl true
  def handle_cast({:track_event, event}, state) do
    # Add to in-memory tracking
    new_state = %{state | events: [event | state.events]}
    
    Logger.debug("Event tracked: #{event.event_name}")
    
    {:noreply, new_state}
  end
  
  @impl true
  def handle_call({:get_metrics, start_date, end_date}, _from, state) do
    metrics = get_database_metrics(start_date, end_date)
    {:reply, metrics, state}
  end
  
  @impl true
  def handle_call(:get_realtime_metrics, _from, state) do
    metrics = %{
      page_views_last_hour: count_recent_items(state.page_views, 3600),
      page_views_last_day: count_recent_items(state.page_views, 86400),
      events_last_hour: count_recent_items(state.events, 3600),
      conversions_last_hour: count_recent_items(state.conversions, 3600),
      top_pages_today: get_top_pages_realtime(state.page_views),
      current_visitors: estimate_current_visitors(state.page_views)
    }
    
    {:reply, metrics, state}
  end
  
  @impl true
  def handle_info(:flush_to_db, state) do
    # Flush accumulated data to database
    flush_to_database(state)
    
    # Reset in-memory state but keep recent data for real-time metrics
    cutoff = DateTime.add(DateTime.utc_now(), -3600) # Keep last hour
    
    new_state = %{
      page_views: filter_recent(state.page_views, cutoff),
      events: filter_recent(state.events, cutoff),
      conversions: filter_recent(state.conversions, cutoff),
      last_flush: DateTime.utc_now()
    }
    
    # Schedule next flush
    schedule_flush()
    
    {:noreply, new_state}
  end
  
  # Private Functions
  
  defp anonymize_ip(ip) when is_binary(ip) do
    # Simple IP anonymization - remove last octet for IPv4
    case String.split(ip, ".") do
      [a, b, c, _d] -> "#{a}.#{b}.#{c}.0"
      _ -> "0.0.0.0" # Fallback for invalid IPs
    end
  end
  
  defp anonymize_ip(_), do: "0.0.0.0"
  
  defp schedule_flush do
    # Flush to database every 5 minutes
    Process.send_after(self(), :flush_to_db, 5 * 60 * 1000)
  end
  
  defp count_recent_items(items, seconds_ago) do
    cutoff = DateTime.add(DateTime.utc_now(), -seconds_ago)
    Enum.count(items, fn item -> DateTime.compare(item.timestamp, cutoff) == :gt end)
  end
  
  defp filter_recent(items, cutoff) do
    Enum.filter(items, fn item -> DateTime.compare(item.timestamp, cutoff) == :gt end)
  end
  
  defp get_top_pages_realtime(page_views) do
    page_views
    |> Enum.group_by(& &1.path)
    |> Enum.map(fn {path, views} -> %{path: path, views: length(views)} end)
    |> Enum.sort_by(& &1.views, :desc)
    |> Enum.take(10)
  end
  
  defp estimate_current_visitors(page_views) do
    # Estimate based on unique sessions in last 30 minutes
    cutoff = DateTime.add(DateTime.utc_now(), -1800) # 30 minutes
    
    page_views
    |> Enum.filter(fn pv -> DateTime.compare(pv.timestamp, cutoff) == :gt end)
    |> Enum.map(& &1.session_id)
    |> Enum.reject(&is_nil/1)
    |> Enum.uniq()
    |> length()
  end
  
  defp flush_to_database(state) do
    try do
      # Batch insert page views
      if length(state.page_views) > 0 do
        page_view_data = Enum.map(state.page_views, &prepare_page_view_for_db/1)
        Repo.insert_all(PageView, page_view_data, on_conflict: :nothing)
        Logger.debug("Flushed #{length(page_view_data)} page views to database")
      end
      
      # Batch insert events
      if length(state.events) > 0 do
        event_data = Enum.map(state.events, &prepare_event_for_db/1)
        Repo.insert_all(Event, event_data, on_conflict: :nothing)
        Logger.debug("Flushed #{length(event_data)} events to database")
      end
      
      # Conversions are already persisted immediately
      
    rescue
      error ->
        Logger.error("Failed to flush analytics to database: #{inspect(error)}")
    end
  end
  
  defp prepare_page_view_for_db(page_view) do
    %{
      path: page_view.path,
      user_ip: page_view.user_ip,
      utm_source: page_view.utm_source,
      utm_medium: page_view.utm_medium,
      utm_campaign: page_view.utm_campaign,
      utm_term: page_view.utm_term,
      utm_content: page_view.utm_content,
      user_id: page_view.user_id,
      session_id: page_view.session_id,
      user_agent: page_view.user_agent,
      referrer: page_view.referrer,
      inserted_at: page_view.timestamp,
      updated_at: page_view.timestamp
    }
  end
  
  defp prepare_event_for_db(event) do
    %{
      event_name: event.event_name,
      properties: event.properties,
      user_id: event.user_id,
      session_id: event.session_id,
      inserted_at: event.timestamp,
      updated_at: event.timestamp
    }
  end
  
  defp persist_conversion(conversion) do
    try do
      %Conversion{}
      |> Conversion.changeset(%{
        event_name: conversion.event_name,
        properties: conversion.properties,
        user_id: conversion.user_id,
        session_id: conversion.session_id
      })
      |> Repo.insert()
      
      Logger.info("Conversion persisted: #{conversion.event_name}")
    rescue
      error ->
        Logger.error("Failed to persist conversion: #{inspect(error)}")
    end
  end
  
  defp get_database_metrics(_start_date, _end_date) do
    # TODO: Implement actual database queries for comprehensive metrics
    # For now, return basic structure
    %{
      page_views: 0,
      unique_visitors: 0,
      conversions: 0,
      top_pages: [],
      utm_sources: [],
      conversion_rate: 0.0
    }
  end
end