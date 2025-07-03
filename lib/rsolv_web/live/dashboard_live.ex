defmodule RsolvWeb.DashboardLive do
  use RsolvWeb, :live_view
  require Logger
  alias Rsolv.Analytics
  import RsolvWeb.Helpers.DashboardHelpers
  
  @refresh_interval 60_000 # Refresh dashboard data every 60 seconds
  
  @impl true
  def mount(_params, _session, socket) do
    if connected?(socket) do
      # Set up periodic refresh for real-time updates
      :timer.send_interval(@refresh_interval, self(), :refresh_data)
    end
    
    # Load initial data
    socket = assign(socket, :current_path, "/dashboard/analytics")
    {:ok, fetch_dashboard_data(socket)}
  end
  
  @impl true
  def handle_params(params, url, socket) do
    tab = Map.get(params, "tab", "overview")
    period = Map.get(params, "period", "7d")
    
    # Parse the URI to get the current path
    parsed_uri = URI.parse(url)
    
    {:noreply, 
      socket
      |> assign(:tab, tab)
      |> assign(:period, period)
      |> assign(:current_path, parsed_uri.path)
      |> fetch_dashboard_data()
    }
  end
  
  @impl true
  def handle_event("change-tab", %{"tab" => tab}, socket) do
    {:noreply, 
      socket
      |> push_patch(to: ~p"/dashboard/analytics?tab=#{tab}&period=#{socket.assigns.period}")
    }
  end
  
  @impl true
  def handle_event("change-period", %{"period" => period}, socket) do
    {:noreply, 
      socket
      |> push_patch(to: ~p"/dashboard/analytics?tab=#{socket.assigns.tab}&period=#{period}")
    }
  end
  
  # The export functionality has been moved to the ReportController
  # We keep this in case any client-side JS still tries to call it
  @impl true
  def handle_event("export-data", %{"format" => _format}, socket) do
    {:noreply,
      socket
      |> put_flash(:info, "Use the export button to download reports")
    }
  end
  
  # Handle manual refresh requests from the UI
  @impl true
  def handle_event("refresh-data", _params, socket) do
    Logger.info("Manual dashboard refresh requested by user")
    {:noreply, 
      socket
      |> fetch_dashboard_data()
      |> put_flash(:info, "Dashboard data refreshed")
    }
  end
  
  @impl true
  def handle_info(:refresh_data, socket) do
    {:noreply, fetch_dashboard_data(socket)}
  end
  
  # Fetch dashboard data based on the selected tab and time period
  defp fetch_dashboard_data(socket) do
    try do
      # Get tab and period from socket assigns with fallbacks
      tab = socket.assigns[:tab] || "overview"
      period = socket.assigns[:period] || "7d"
      
      # Log data fetch attempt
      Logger.info("Fetching dashboard data", 
        metadata: %{
          tab: tab,
          period: period
        }
      )
      
      # Convert period to date range with error handling
      {since, _until} = period_to_date_range(period)
      
      # Fetch data based on tab
      data = 
        try do
          case tab do
            "overview" -> fetch_overview_data(since)
            "conversions" -> fetch_conversion_data(since)
            "traffic" -> fetch_traffic_data(since)
            "engagement" -> fetch_engagement_data(since)
            # Default to overview for unknown tabs
            unknown_tab -> 
              Logger.warning("Unknown dashboard tab requested", 
                metadata: %{tab: unknown_tab}
              )
              fetch_overview_data(since)
          end
        rescue
          e -> 
            Logger.error("Error fetching data for tab: #{tab}", 
              metadata: %{
                error: inspect(e),
                stacktrace: __STACKTRACE__
              }
            )
            # Return empty dashboard data on error
            %{error: "Data temporarily unavailable"}
        end
      
      # Get summary metrics with error handling for each metric
      total_visitors = get_metric_safely("visitors", fn -> get_unique_visitors_count(since) end)
      total_conversions = get_metric_safely("conversions", fn -> get_total_conversions(since) end)
      conversion_rate = calculate_conversion_rate(total_visitors, total_conversions)
      average_session_duration = get_metric_safely("session_duration", fn -> get_average_session_duration(since) end)
      
      # Update socket with fetched data
      socket
      |> assign(:data, data)
      |> assign(:total_visitors, total_visitors)
      |> assign(:total_conversions, total_conversions)
      |> assign(:conversion_rate, conversion_rate)
      |> assign(:average_session_duration, average_session_duration)
      |> assign(:last_updated, DateTime.utc_now())
      |> assign(:data_error, nil) # Clear any previous errors
    rescue
      e -> 
        Logger.error("Fatal error in dashboard data fetch", 
          metadata: %{
            error: inspect(e),
            stacktrace: __STACKTRACE__
          }
        )
        
        # Return socket with error information for UI
        socket
        |> assign(:data_error, "Unable to load dashboard data. Please try again later.")
        |> assign(:last_updated, DateTime.utc_now())
    end
  end
  
  # Helper function to safely get a metric with error handling
  defp get_metric_safely(metric_name, metric_fn) do
    try do
      metric_fn.()
    rescue
      e -> 
        Logger.error("Error fetching metric: #{metric_name}", 
          metadata: %{
            error: inspect(e)
          }
        )
        0 # Return safe default value on error
    end
  end
  
  # Convert period string to actual date range with error handling
  defp period_to_date_range(period) do
    try do
      today = Date.utc_today()
      
      # Validate period input and provide safe default
      safe_period = 
        if is_binary(period) do
          period
        else
          Logger.warning("Invalid period type", 
            metadata: %{
              period: inspect(period), 
              type: typeof(period)
            }
          )
          "7d" # Default to 7 days for invalid input
        end
      
      # Calculate since date with expanded options
      since = case safe_period do
        "1d" -> Date.add(today, -1)
        "7d" -> Date.add(today, -7)
        "30d" -> Date.add(today, -30)
        "90d" -> Date.add(today, -90)
        "all" -> Date.add(today, -365) # For simplicity, we'll use a year for "all"
        custom when is_binary(custom) ->
          # Try to parse custom period format like "days:30" or "weeks:4"
          case String.split(custom, ":") do
            ["days", days_str] ->
              case Integer.parse(days_str) do
                {days, _} -> Date.add(today, -days)
                _ -> Date.add(today, -7) # Default for parse error
              end
            ["weeks", weeks_str] ->
              case Integer.parse(weeks_str) do
                {weeks, _} -> Date.add(today, -weeks * 7)
                _ -> Date.add(today, -7) # Default for parse error
              end
            ["months", months_str] ->
              case Integer.parse(months_str) do
                {months, _} -> Date.add(today, -months * 30)
                _ -> Date.add(today, -7) # Default for parse error
              end
            _ -> 
              Logger.warning("Unknown period format, using default", 
                metadata: %{period: safe_period}
              )
              Date.add(today, -7) # Default for unknown format
          end
        _ -> 
          Logger.warning("Unrecognized period, using default", 
            metadata: %{period: safe_period}
          )
          Date.add(today, -7) # Default to 7 days
      end
      
      # Log the date range for debugging
      Logger.debug("Date range calculated", 
        metadata: %{
          period: safe_period,
          since: Date.to_string(since),
          until: Date.to_string(today)
        }
      )
      
      {since, today}
    rescue
      e ->
        # On any error, provide a safe default range of 7 days
        Logger.error("Error calculating date range", 
          metadata: %{
            period: inspect(period),
            error: inspect(e)
          }
        )
        today = Date.utc_today()
        {Date.add(today, -7), today}
    end
  end
  
  # Helper to get type name for logging
  defp typeof(term) do
    cond do
      is_nil(term) -> "nil"
      is_binary(term) -> "binary"
      is_boolean(term) -> "boolean"
      is_number(term) -> "number"
      is_atom(term) -> "atom"
      is_list(term) -> "list"
      is_map(term) -> "map"
      is_tuple(term) -> "tuple"
      is_function(term) -> "function"
      is_pid(term) -> "pid"
      is_reference(term) -> "reference"
      is_port(term) -> "port"
      true -> "unknown"
    end
  end
  
  # Fetch overview dashboard data
  defp fetch_overview_data(since) do
    # Get key metrics over time for the overview dashboard
    
    # Daily visitors over time
    visitors_data = case Analytics.query_data(:page_views, since: since, group_by: :timestamp) do
      {:ok, data} -> data
      _ -> %{}
    end
    
    # Daily conversions over time
    conversions_data = case Analytics.query_data(:conversions, since: since, group_by: :timestamp) do
      {:ok, data} -> data
      _ -> %{}
    end
    
    # UTM sources breakdown
    utm_data = case Analytics.query_data(:page_views, since: since, group_by: :utm_source) do
      {:ok, data} -> data
      _ -> %{}
    end
    
    # Format data for the dashboard
    utm_sources = format_utm_sources(utm_data)
    visitor_trend = format_time_series_data(visitors_data, "Visitors")
    conversion_trend = format_time_series_data(conversions_data, "Conversions")
    
    %{
      utm_sources: utm_sources,
      visitor_trend: visitor_trend,
      conversion_trend: conversion_trend
    }
  end
  
  # Fetch conversion-specific data
  defp fetch_conversion_data(since) do
    # Get conversion data
    conversions = case Analytics.query_data(:conversions, since: since) do
      {:ok, data} -> data
      _ -> []
    end
    
    # Group by conversion type
    conversion_types = Enum.group_by(conversions, & &1.conversion_type)
    
    # Group by source
    conversion_sources = Enum.group_by(conversions, & &1.utm_source)
    
    # Format for charts
    conversion_by_type = 
      conversion_types
      |> Enum.map(fn {type, entries} -> 
        {type || "direct", length(entries)}
      end)
      |> Enum.sort_by(fn {_, count} -> -count end)

    conversion_by_source = 
      conversion_sources
      |> Enum.map(fn {source, entries} -> 
        {source || "direct", length(entries)}
      end)
      |> Enum.sort_by(fn {_, count} -> -count end)
    
    %{
      conversion_by_type: conversion_by_type,
      conversion_by_source: conversion_by_source,
      recent_conversions: Enum.take(conversions, 10)
    }
  end
  
  # Fetch traffic source data
  defp fetch_traffic_data(since) do
    # Get page view data
    page_views = case Analytics.query_data(:page_views, since: since) do
      {:ok, data} -> data
      _ -> []
    end
    
    # Group by source (utm_source or referrer)
    traffic_sources = Enum.group_by(page_views, fn entry ->
      source = entry.utm_source
      if source && source != "", do: source, else: (entry.referrer || "direct")
    end)
    
    # Group by page path
    pages = Enum.group_by(page_views, & &1.page_path)
    
    # Format for charts
    traffic_by_source = 
      traffic_sources
      |> Enum.map(fn {source, entries} -> 
        {source, length(entries)}
      end)
      |> Enum.sort_by(fn {_, count} -> -count end)
      |> Enum.take(10)
    
    traffic_by_page = 
      pages
      |> Enum.map(fn {page, entries} -> 
        {page || "/", length(entries)}
      end)
      |> Enum.sort_by(fn {_, count} -> -count end)
      |> Enum.take(10)
    
    %{
      traffic_by_source: traffic_by_source,
      traffic_by_page: traffic_by_page
    }
  end
  
  # Fetch engagement data (scroll depth, section views)
  defp fetch_engagement_data(since) do
    # Get section view data
    section_views = case Analytics.query_data(:events, since: since) do
      {:ok, data} -> data
      _ -> []
    end
    
    # Filter section views and scroll depth events
    section_view_events = Enum.filter(section_views, &(&1.event == "section_view"))
    scroll_depth_events = Enum.filter(section_views, &(&1.event == "scroll_depth"))
    
    # Group by section id
    sections = Enum.group_by(section_view_events, fn entry ->
      additional_data = try_parse_additional_data(entry.additional_data)
      Map.get(additional_data, "section_id", "unknown")
    end)
    
    # Format for charts
    section_engagement = 
      sections
      |> Enum.map(fn {section, entries} -> 
        {section, length(entries)}
      end)
      |> Enum.sort_by(fn {_, count} -> -count end)
    
    # Extract scroll depths
    scroll_depths = 
      scroll_depth_events
      |> Enum.map(fn event ->
        additional_data = try_parse_additional_data(event.additional_data)
        Map.get(additional_data, "depth", 0)
      end)
      |> Enum.frequencies()
      |> Enum.map(fn {depth, count} -> {depth, count} end)
      |> Enum.sort_by(fn {depth, _} -> 
        case depth do
          depth when is_binary(depth) -> 
            case Integer.parse(depth) do
              {int, _} -> int
              _ -> 0
            end
          depth when is_integer(depth) -> depth
          _ -> 0
        end
      end)
    
    %{
      section_engagement: section_engagement,
      scroll_depths: scroll_depths
    }
  end
  
  # Helper to get unique visitor count
  defp get_unique_visitors_count(since) do
    case Analytics.query_data(:page_views, since: since) do
      {:ok, page_views} ->
        page_views
        |> Enum.map(& &1.user_id)
        |> Enum.uniq()
        |> length()
      _ -> 0
    end
  end
  
  # Helper to get total conversion count
  defp get_total_conversions(since) do
    case Analytics.query_data(:conversions, since: since) do
      {:ok, conversions} -> length(conversions)
      _ -> 0
    end
  end
  
  # Calculate conversion rate
  defp calculate_conversion_rate(visitors, conversions) do
    if visitors > 0 do
      Float.round(conversions / visitors * 100, 2)
    else
      0.0
    end
  end
  
  # Helper to get average session duration
  defp get_average_session_duration(since) do
    case Analytics.query_data(:sessions, since: since) do
      {:ok, sessions} ->
        # Extract and parse durations
        durations = 
          sessions
          |> Enum.map(fn session ->
            case session.session_duration do
              duration when is_binary(duration) ->
                case Integer.parse(duration) do
                  {value, _} -> value
                  _ -> 0
                end
              duration when is_integer(duration) -> 
                duration
              _ -> 
                0
            end
          end)
        
        # Calculate average
        total_duration = Enum.sum(durations)
        session_count = length(sessions)
        
        if session_count > 0 do
          div(total_duration, session_count)
        else
          0
        end
      
      _ -> 0
    end
  end
  
  # Format time series data for charts with improved error handling
  defp format_time_series_data(grouped_data, label) do
    try do
      # Ensure we're working with a map
      formatted_data = 
        if is_map(grouped_data) do
          grouped_data
          |> Enum.map(fn {date, entries} ->
            try do
              # Extract just the date part with comprehensive type handling
              date_part = cond do
                is_binary(date) -> 
                  # Take just the YYYY-MM-DD part, handling potential format issues
                  case String.slice(date, 0, 10) do
                    "" -> "unknown"
                    date_str -> date_str
                  end
                is_struct(date, DateTime) -> 
                  # Format DateTime as YYYY-MM-DD
                  Date.to_string(DateTime.to_date(date))
                is_struct(date, Date) -> 
                  # Format Date as YYYY-MM-DD
                  Date.to_string(date)
                is_nil(date) ->
                  "unknown"
                true -> 
                  "unknown"
              end
              
              # Handle entry count with validations
              entry_count = 
                cond do
                  is_list(entries) -> length(entries)
                  is_integer(entries) -> entries
                  true -> 0
                end
              
              %{
                date: date_part,
                count: entry_count,
                label: label
              }
            rescue
              e -> 
                Logger.warning("Error formatting time series item", 
                  metadata: %{
                    date: inspect(date),
                    error: inspect(e)
                  }
                )
                # Return a safe fallback item
                %{
                  date: "error",
                  count: 0,
                  label: label
                }
            end
          end)
          |> Enum.filter(fn item -> item.date != "error" end) # Remove error items
          |> Enum.sort_by(& &1.date)
        else
          # Return empty array for non-map data
          Logger.warning("Invalid data type for time series formatting", 
            metadata: %{type: inspect(grouped_data)}
          )
          []
        end
      
      # Return empty array if we have no items
      if Enum.empty?(formatted_data), do: [], else: formatted_data
    rescue
      e -> 
        Logger.error("Failed to format time series data", 
          metadata: %{error: inspect(e)}
        )
        [] # Return empty array on complete failure
    end
  end
  
  # Format UTM source data for charts with improved error handling
  defp format_utm_sources(utm_data) do
    try do
      # Ensure we're working with a map
      if is_map(utm_data) do
        utm_data
        |> Enum.map(fn {source, entries} ->
          try do
            # Normalize source name with expanded handling
            normalized_source = cond do
              is_nil(source) -> "direct"
              source == "" -> "direct"
              source == "null" -> "direct"
              is_binary(source) -> source
              is_atom(source) -> Atom.to_string(source)
              true -> inspect(source) # Fall back to string representation
            end
            
            # Handle entry count with validations
            entry_count = 
              cond do
                is_list(entries) -> length(entries)
                is_integer(entries) -> entries
                true -> 0
              end
            
            %{
              source: normalized_source,
              count: entry_count
            }
          rescue
            e -> 
              Logger.warning("Error formatting UTM source item", 
                metadata: %{
                  source: inspect(source),
                  error: inspect(e)
                }
              )
              # Return a safe fallback item
              %{
                source: "error",
                count: 0
              }
          end
        end)
        |> Enum.filter(fn item -> item.source != "error" end) # Remove error items
        |> Enum.sort_by(& &1.count, :desc)
        |> Enum.take(5)  # Top 5 sources
      else
        # Return empty array for non-map data
        Logger.warning("Invalid data type for UTM source formatting", 
          metadata: %{type: inspect(utm_data)}
        )
        []
      end
    rescue
      e -> 
        Logger.error("Failed to format UTM sources data", 
          metadata: %{error: inspect(e)}
        )
        [] # Return empty array on complete failure
    end
  end
  
end