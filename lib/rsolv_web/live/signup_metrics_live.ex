defmodule RsolvWeb.SignupMetricsLive do
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
    socket = assign(socket, :current_path, "/dashboard/signup-metrics")
    {:ok, fetch_signup_metrics(socket)}
  end
  
  @impl true
  def handle_params(params, url, socket) do
    period = Map.get(params, "period", "7d")
    view = Map.get(params, "view", "overview")
    
    # Parse the URI to get the current path
    parsed_uri = URI.parse(url)
    
    {:noreply, 
      socket
      |> assign(:period, period)
      |> assign(:view, view)
      |> assign(:current_path, parsed_uri.path)
      |> fetch_signup_metrics()
    }
  end
  
  @impl true
  def handle_event("change-period", %{"period" => period}, socket) do
    {:noreply, 
      socket
      |> push_patch(to: ~p"/dashboard/signup-metrics?period=#{period}&view=#{socket.assigns.view}")
    }
  end
  
  @impl true
  def handle_event("change-view", %{"view" => view}, socket) do
    {:noreply, 
      socket
      |> push_patch(to: ~p"/dashboard/signup-metrics?period=#{socket.assigns.period}&view=#{view}")
    }
  end
  
  # Handle manual refresh requests from the UI
  @impl true
  def handle_event("refresh-data", _params, socket) do
    Logger.info("Manual signup metrics refresh requested by user")
    {:noreply, 
      socket
      |> fetch_signup_metrics()
      |> put_flash(:info, "Signup metrics refreshed")
    }
  end
  
  @impl true
  def handle_info(:refresh_data, socket) do
    {:noreply, fetch_signup_metrics(socket)}
  end
  
  # Main function to fetch all signup metrics
  defp fetch_signup_metrics(socket) do
    try do
      # Get period from socket assigns with fallbacks
      period = socket.assigns[:period] || "7d"
      view = socket.assigns[:view] || "overview"
      
      # Log data fetch attempt
      Logger.info("Fetching signup metrics", 
        metadata: %{
          period: period,
          view: view
        }
      )
      
      # Convert period to date range
      {since, until} = period_to_date_range(period)
      
      # Fetch data based on view
      data = 
        try do
          case view do
            "overview" -> fetch_signup_overview(since, until)
            "sources" -> fetch_signup_sources(since, until)
            "funnel" -> fetch_signup_funnel(since, until)
            "timeline" -> fetch_signup_timeline(since, until)
            _ -> fetch_signup_overview(since, until)
          end
        rescue
          e -> 
            Logger.error("Error fetching data for view: #{view}", 
              metadata: %{
                error: inspect(e),
                stacktrace: __STACKTRACE__
              }
            )
            # Return empty dashboard data on error
            %{error: "Data temporarily unavailable"}
        end
      
      # Get summary metrics with error handling for each metric
      total_signups = get_metric_safely("total_signups", fn -> get_total_signups(since) end)
      average_daily = get_metric_safely("average_daily", fn -> get_average_daily_signups(since, until) end)
      source_breakdown = get_metric_safely("source_breakdown", fn -> get_source_breakdown(since) end)
      most_recent = get_metric_safely("most_recent", fn -> get_most_recent_signups(10) end)
      
      # Add integration status
      integration_status = %{
        convertkit: check_convertkit_integration(),
        plausible: check_plausible_integration(),
        simpleanalytics: check_simpleanalytics_integration()
      }
      
      # Update socket with fetched data
      socket
      |> assign(:data, data)
      |> assign(:total_signups, total_signups)
      |> assign(:average_daily, average_daily)
      |> assign(:source_breakdown, source_breakdown)
      |> assign(:most_recent, most_recent)
      |> assign(:integration_status, integration_status)
      |> assign(:last_updated, DateTime.utc_now())
      |> assign(:date_range, %{since: since, until: until})
      |> assign(:data_error, nil) # Clear any previous errors
    rescue
      e -> 
        Logger.error("Fatal error in signup metrics fetch", 
          metadata: %{
            error: inspect(e),
            stacktrace: __STACKTRACE__
          }
        )
        
        # Return socket with error information for UI
        socket
        |> assign(:data_error, "Unable to load signup metrics. Please try again later.")
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
        case metric_name do
          "total_signups" -> 0 # Return safe default value
          "average_daily" -> 0.0 # Return safe default value
          "source_breakdown" -> [] # Return empty list
          "most_recent" -> [] # Return empty list
          _ -> nil
        end
    end
  end
  
  # Convert period string to actual date range with error handling
  defp period_to_date_range(period) do
    try do
      today = Date.utc_today()
      
      # Calculate since date
      since = case period do
        "1d" -> Date.add(today, -1)
        "7d" -> Date.add(today, -7)
        "30d" -> Date.add(today, -30)
        "90d" -> Date.add(today, -90)
        "all" -> Date.add(today, -365) # For simplicity, we'll use a year for "all"
        _ -> Date.add(today, -7) # Default to 7 days
      end
      
      {since, today}
    rescue
      _ ->
        # On any error, provide a safe default range of 7 days
        today = Date.utc_today()
        {Date.add(today, -7), today}
    end
  end
  
  # Fetch overview data for signup metrics
  defp fetch_signup_overview(since, until) do
    # Get signup conversion data
    conversions = case Analytics.query_data(:conversions, since: since, until: until) do
      {:ok, data} -> data
      _ -> []
    end
    
    # Filter to only early access signups
    signups = Enum.filter(conversions, fn conv -> 
      conv.conversion_type == "early_access_signup" || conv.conversion_type == "signup"
    end)
    
    # Group by date
    grouped_by_date = Enum.group_by(signups, fn signup ->
      # Extract just the date part
      String.slice(signup.timestamp, 0, 10)
    end)
    
    # Create daily counts for the entire date range
    daily_counts = date_range_to_daily_counts(since, until, grouped_by_date)
    
    # Get sources breakdown
    sources_data = Enum.group_by(signups, fn signup -> 
      signup.utm_source || "direct"
    end)
    
    # Format data
    utm_sources = format_utm_sources(sources_data)
    signup_trend = format_time_series_data(grouped_by_date, "Signups")
    
    # Get completion rates if possible (form submissions vs. form success)
    form_events = case Analytics.query_data(:form_events, since: since, until: until) do
      {:ok, data} -> data
      _ -> []
    end
    
    form_submissions = Enum.filter(form_events, fn event -> 
      event.event == "form_submit" && event.form_id == "early-access"
    end)
    
    form_success = Enum.filter(form_events, fn event -> 
      event.event == "form_success" && event.form_id == "early-access"
    end)
    
    conversion_rate = 
      if length(form_submissions) > 0 do
        Float.round(length(form_success) / length(form_submissions) * 100, 2)
      else
        0.0
      end
    
    %{
      daily_counts: daily_counts,
      utm_sources: utm_sources,
      signup_trend: signup_trend,
      conversion_rate: conversion_rate,
      submissions_count: length(form_submissions),
      success_count: length(form_success)
    }
  end
  
  # Fetch source breakdown data
  defp fetch_signup_sources(since, until) do
    # Get signup conversion data
    conversions = case Analytics.query_data(:conversions, since: since, until: until) do
      {:ok, data} -> data
      _ -> []
    end
    
    # Filter to only early access signups
    signups = Enum.filter(conversions, fn conv -> 
      conv.conversion_type == "early_access_signup" || conv.conversion_type == "signup"
    end)
    
    # Group by source
    by_source = Enum.group_by(signups, fn signup -> 
      normalize_source(signup.utm_source)
    end)
    
    # Group by medium
    by_medium = Enum.group_by(signups, fn signup -> 
      get_utm_param(signup, :utm_medium) || "none"
    end)
    
    # Group by campaign
    by_campaign = Enum.group_by(signups, fn signup -> 
      get_utm_param(signup, :utm_campaign) || "none"
    end)
    
    # Format data for charts
    source_data = format_count_data(by_source)
    medium_data = format_count_data(by_medium)
    campaign_data = format_count_data(by_campaign)
    
    # Get full campaign data (source + medium + campaign)
    campaign_details = Enum.map(signups, fn signup ->
      %{
        source: normalize_source(signup.utm_source),
        medium: get_utm_param(signup, :utm_medium) || "none",
        campaign: get_utm_param(signup, :utm_campaign) || "none",
        content: get_utm_param(signup, :utm_content) || "none",
        timestamp: signup.timestamp,
        domain: signup.email_domain || "unknown"
      }
    end)
    
    %{
      by_source: source_data,
      by_medium: medium_data,
      by_campaign: campaign_data,
      campaign_details: campaign_details
    }
  end
  
  # Fetch funnel analysis data
  defp fetch_signup_funnel(since, until) do
    # Get all page views and conversion events
    page_views = case Analytics.query_data(:page_views, since: since, until: until) do
      {:ok, data} -> data
      _ -> []
    end
    
    form_events = case Analytics.query_data(:form_events, since: since, until: until) do
      {:ok, data} -> data
      _ -> []
    end
    
    conversions = case Analytics.query_data(:conversions, since: since, until: until) do
      {:ok, data} -> data
      _ -> []
    end
    
    # Count unique visitors
    unique_visitors = 
      page_views
      |> Enum.map(& &1.user_id)
      |> Enum.uniq()
      |> length()
    
    # Count form views (entries to the early access section)
    form_views = 
      page_views
      |> Enum.filter(fn view -> view.page_path =~ "#early-access" end)
      |> length()
    
    # Count form submissions
    form_submissions = 
      form_events
      |> Enum.filter(fn event -> event.event == "form_submit" && event.form_id == "early-access" end)
      |> length()
    
    # Count form success
    form_success = 
      form_events
      |> Enum.filter(fn event -> event.event == "form_success" && event.form_id == "early-access" end)
      |> length()
    
    # Count signups
    signups = 
      conversions
      |> Enum.filter(fn conv -> 
        conv.conversion_type == "early_access_signup" || conv.conversion_type == "signup"
      end)
      |> length()
    
    # Build funnel stages
    funnel_stages = [
      %{name: "Visitors", count: unique_visitors, rate: 100.0},
      %{name: "Form Views", count: form_views, rate: calculate_percentage(form_views, unique_visitors)},
      %{name: "Form Submissions", count: form_submissions, rate: calculate_percentage(form_submissions, form_views)},
      %{name: "Form Success", count: form_success, rate: calculate_percentage(form_success, form_submissions)},
      %{name: "Completed Signups", count: signups, rate: calculate_percentage(signups, form_success)}
    ]
    
    # Calculate drop-off points
    drop_offs = Enum.map(0..(length(funnel_stages) - 2), fn i ->
      current = Enum.at(funnel_stages, i)
      next = Enum.at(funnel_stages, i + 1)
      drop_count = current.count - next.count
      drop_rate = 100.0 - next.rate
      
      %{
        from: current.name,
        to: next.name,
        drop_count: drop_count,
        drop_rate: drop_rate
      }
    end)
    
    # Calculate overall conversion rate
    overall_rate = 
      if unique_visitors > 0 do
        Float.round(signups / unique_visitors * 100, 2)
      else
        0.0
      end
    
    %{
      funnel_stages: funnel_stages,
      drop_offs: drop_offs,
      overall_rate: overall_rate
    }
  end
  
  # Fetch timeline data with daily/weekly trends
  defp fetch_signup_timeline(since, until) do
    # Get signup conversions
    conversions = case Analytics.query_data(:conversions, since: since, until: until) do
      {:ok, data} -> data
      _ -> []
    end
    
    # Filter to only early access signups
    signups = Enum.filter(conversions, fn conv -> 
      conv.conversion_type == "early_access_signup" || conv.conversion_type == "signup"
    end)
    
    # Group by date
    grouped_by_date = Enum.group_by(signups, fn signup ->
      # Extract just the date part
      String.slice(signup.timestamp, 0, 10)
    end)
    
    # Create daily counts
    daily_counts = date_range_to_daily_counts(since, until, grouped_by_date)
    
    # Create weekly counts
    weekly_counts = create_weekly_counts(since, until, grouped_by_date)
    
    # Get high/low days of week
    days_of_week = count_by_day_of_week(signups)
    
    # Get high/low hours of day
    hours_of_day = count_by_hour_of_day(signups)
    
    %{
      daily_counts: daily_counts,
      weekly_counts: weekly_counts,
      days_of_week: days_of_week,
      hours_of_day: hours_of_day
    }
  end
  
  # Helper functions
  
  # Get total signup count
  defp get_total_signups(since) do
    case Analytics.query_data(:conversions, since: since) do
      {:ok, conversions} ->
        conversions
        |> Enum.filter(fn conv -> 
          conv.conversion_type == "early_access_signup" || conv.conversion_type == "signup"
        end)
        |> length()
      _ -> 0
    end
  end
  
  # Get average daily signups
  defp get_average_daily_signups(since, until) do
    total = get_total_signups(since)
    days = Date.diff(until, since)
    
    if days > 0 do
      Float.round(total / days, 1)
    else
      total * 1.0
    end
  end
  
  # Get source breakdown for signups
  defp get_source_breakdown(since) do
    case Analytics.query_data(:conversions, since: since) do
      {:ok, conversions} ->
        # Filter to only early access signups
        signups = Enum.filter(conversions, fn conv -> 
          conv.conversion_type == "early_access_signup" || conv.conversion_type == "signup"
        end)
        
        # Group by source
        by_source = Enum.group_by(signups, fn signup -> 
          normalize_source(signup.utm_source)
        end)
        
        # Format data for display
        by_source
        |> Enum.map(fn {source, entries} -> 
          %{source: source, count: length(entries)}
        end)
        |> Enum.sort_by(fn %{count: count} -> -count end)
      _ -> []
    end
  end
  
  # Get most recent signups
  defp get_most_recent_signups(limit) do
    case Analytics.query_data(:conversions) do
      {:ok, conversions} ->
        conversions
        |> Enum.filter(fn conv -> 
          conv.conversion_type == "early_access_signup" || conv.conversion_type == "signup"
        end)
        |> Enum.sort_by(fn conv -> conv.timestamp end, :desc)
        |> Enum.take(limit)
        |> Enum.map(fn signup ->
          # Enhance with additional data from the JSON field
          additional = try_parse_additional_data(signup.additional_data)
          
          %{
            timestamp: signup.timestamp,
            email_domain: signup.email_domain || "unknown",
            source: normalize_source(signup.utm_source),
            medium: get_utm_param(signup, :utm_medium) || "none",
            campaign: get_utm_param(signup, :utm_campaign) || "none",
            team_size: Map.get(additional, "team_size", "unknown")
          }
        end)
      _ -> []
    end
  end
  
  # Check integration statuses
  defp check_convertkit_integration do
    # Check config
    config = Application.get_env(:rsolv, :convertkit, [])
    api_key = Keyword.get(config, :api_key)
    api_secret = Keyword.get(config, :api_secret)
    
    %{
      configured: api_key != nil && api_secret != nil,
      status: "active" # Assuming it's active if configured
    }
  end
  
  defp check_plausible_integration do
    # Simple check if Plausible script is included in the layout
    %{
      configured: true, # We'd need to check the actual layout for this
      status: "active"
    }
  end
  
  defp check_simpleanalytics_integration do
    # Simple check if SimpleAnalytics script is included in the layout
    %{
      configured: true, # We'd need to check the actual layout for this
      status: "active"
    }
  end
  
  # Helper to normalize source names
  defp normalize_source(source) do
    cond do
      is_nil(source) -> "direct"
      source == "" -> "direct"
      true -> source
    end
  end
  
  # Helper to extract UTM parameters
  defp get_utm_param(entry, param) do
    additional_data = try_parse_additional_data(entry.additional_data)
    param_str = Atom.to_string(param)
    
    Map.get(additional_data, param_str, Map.get(entry, param))
  end
  
  # Helper to format data for counts
  defp format_count_data(grouped_data) do
    grouped_data
    |> Enum.map(fn {key, entries} -> 
      %{
        label: key, 
        count: length(entries),
        percentage: 0 # Will be calculated later
      }
    end)
    |> Enum.sort_by(fn %{count: count} -> -count end)
    |> add_percentages()
  end
  
  # Add percentage values to the data
  defp add_percentages(items) do
    total = Enum.reduce(items, 0, fn %{count: count}, acc -> acc + count end)
    
    if total > 0 do
      Enum.map(items, fn item = %{count: count} -> 
        Map.put(item, :percentage, Float.round(count / total * 100, 1))
      end)
    else
      items
    end
  end
  
  # Generate daily counts for a date range
  defp date_range_to_daily_counts(since, until, grouped_data) do
    days = Date.diff(until, since)
    
    0..days
    |> Enum.map(fn day_offset ->
      date = Date.add(since, day_offset)
      date_str = Date.to_string(date)
      
      %{
        date: date_str,
        count: length(Map.get(grouped_data, date_str, [])),
        label: "Signups"
      }
    end)
  end
  
  # Create weekly counts from daily data
  defp create_weekly_counts(since, until, grouped_data) do
    # Ensure since is the start of a week (Monday)
    days_to_monday = case Date.day_of_week(since) do
      1 -> 0  # Monday
      n -> -(n - 1)  # Otherwise, go back to previous Monday
    end
    
    start_monday = Date.add(since, days_to_monday)
    days = Date.diff(until, start_monday)
    weeks = div(days, 7) + 1
    
    0..(weeks - 1)
    |> Enum.map(fn week_offset ->
      week_start = Date.add(start_monday, week_offset * 7)
      week_end = Date.add(week_start, 6) # 7 days total
      
      # Limited by end date
      adjusted_week_end = if Date.compare(week_end, until) == :gt, do: until, else: week_end
      
      # Count signups in this week
      week_count = 
        Date.range(week_start, adjusted_week_end)
        |> Enum.reduce(0, fn date, acc ->
          date_str = Date.to_string(date)
          acc + length(Map.get(grouped_data, date_str, []))
        end)
      
      %{
        week: "Week #{week_offset + 1}",
        start_date: Date.to_string(week_start),
        end_date: Date.to_string(adjusted_week_end),
        count: week_count,
        label: "Signups"
      }
    end)
  end
  
  # Count signups by day of week
  defp count_by_day_of_week(signups) do
    day_names = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday"]
    
    # Initialize with zeros
    day_counts = Enum.reduce(1..7, %{}, fn day, acc ->
      Map.put(acc, day, 0)
    end)
    
    # Count by day
    counts = Enum.reduce(signups, day_counts, fn signup, acc ->
      case parse_date(signup.timestamp) do
        {:ok, date} ->
          day = Date.day_of_week(date)
          Map.update(acc, day, 1, &(&1 + 1))
        _ ->
          acc
      end
    end)
    
    # Format result
    1..7
    |> Enum.map(fn day ->
      %{
        day: day,
        name: Enum.at(day_names, day - 1),
        count: Map.get(counts, day, 0),
        label: "Signups"
      }
    end)
  end
  
  # Count signups by hour of day
  defp count_by_hour_of_day(signups) do
    # Initialize with zeros
    hour_counts = Enum.reduce(0..23, %{}, fn hour, acc ->
      Map.put(acc, hour, 0)
    end)
    
    # Count by hour
    counts = Enum.reduce(signups, hour_counts, fn signup, acc ->
      case parse_datetime(signup.timestamp) do
        {:ok, datetime} ->
          hour = datetime.hour
          Map.update(acc, hour, 1, &(&1 + 1))
        _ ->
          acc
      end
    end)
    
    # Format result
    0..23
    |> Enum.map(fn hour ->
      %{
        hour: hour,
        display: "#{hour}:00",
        count: Map.get(counts, hour, 0),
        label: "Signups"
      }
    end)
  end
  
  # Parse date from timestamp
  defp parse_date(timestamp) when is_binary(timestamp) do
    case String.split(timestamp, "T") do
      [date_str | _] ->
        Date.from_iso8601(date_str)
      _ ->
        {:error, :invalid_format}
    end
  end
  
  defp parse_date(_), do: {:error, :invalid_input}
  
  # Parse datetime from timestamp
  defp parse_datetime(timestamp) when is_binary(timestamp) do
    DateTime.from_iso8601(timestamp)
  end
  
  defp parse_datetime(_), do: {:error, :invalid_input}
  
  # Calculate percentage safely
  defp calculate_percentage(part, total) do
    if total > 0 do
      Float.round(part / total * 100, 1)
    else
      0.0
    end
  end
  
  # Format time series data for charts
  defp format_time_series_data(grouped_data, label) do
    try do
      # Ensure we're working with a map
      if is_map(grouped_data) do
        grouped_data
        |> Enum.map(fn {date, entries} ->
          try do
            # Extract just the date part
            date_part = cond do
              is_binary(date) -> 
                # Take just the YYYY-MM-DD part
                String.slice(date, 0, 10)
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
            
            # Handle entry count
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
            _ -> 
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
        Logger.warning("Invalid data type for time series formatting")
        []
      end
    rescue
      e -> 
        Logger.error("Failed to format time series data: #{inspect(e)}")
        [] # Return empty array on complete failure
    end
  end

  # Format UTM source data for charts
  defp format_utm_sources(utm_data) do
    try do
      # Ensure we're working with a map
      if is_map(utm_data) do
        utm_data
        |> Enum.map(fn {source, entries} ->
          try do
            # Normalize source name
            normalized_source = cond do
              is_nil(source) -> "direct"
              source == "" -> "direct"
              source == "null" -> "direct"
              is_binary(source) -> source
              is_atom(source) -> Atom.to_string(source)
              true -> inspect(source) # Fall back to string representation
            end
            
            # Handle entry count
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
            _ -> 
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
        Logger.warning("Invalid data type for UTM source formatting")
        []
      end
    rescue
      e -> 
        Logger.error("Failed to format UTM sources data: #{inspect(e)}")
        [] # Return empty array on complete failure
    end
  end
end