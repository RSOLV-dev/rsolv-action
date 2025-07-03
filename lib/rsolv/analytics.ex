defmodule Rsolv.Analytics do
  @moduledoc """
  The Analytics context for managing analytics events with optimized PostgreSQL storage.
  Uses table partitioning by month and materialized views for performance.
  """

  import Ecto.Query, warn: false
  alias Rsolv.Repo
  alias Rsolv.Analytics.Event

  @doc """
  Creates an analytics event.
  Automatically ensures the partition exists for the event's timestamp.
  """
  def create_event(attrs \\ %{}) do
    # TODO: Re-enable partition creation when function is available
    # ensure_partition_exists(attrs[:inserted_at] || DateTime.utc_now())
    
    %Event{}
    |> Event.changeset(attrs)
    |> Repo.insert()
  end

  @doc """
  Returns the list of all analytics events.
  """
  def list_events do
    Repo.all(Event)
  end

  @doc """
  Gets a single event.
  Raises `Ecto.NoResultsError` if the event does not exist.
  """
  def get_event!(id), do: Repo.get!(Event, id)

  @doc """
  Returns events of a specific type.
  """
  def list_events_by_type(event_type) do
    Event
    |> where([e], e.event_type == ^event_type)
    |> order_by([e], desc: e.inserted_at)
    |> Repo.all()
  end

  @doc """
  Returns events for a specific visitor.
  """
  def list_events_by_visitor(visitor_id) do
    Event
    |> where([e], e.visitor_id == ^visitor_id)
    |> order_by([e], desc: e.inserted_at)
    |> Repo.all()
  end

  @doc """
  Returns events within a date range.
  """
  def list_events_in_range(start_date, end_date) do
    Event
    |> where([e], e.inserted_at >= ^start_date and e.inserted_at <= ^end_date)
    |> order_by([e], desc: e.inserted_at)
    |> Repo.all()
  end

  @doc """
  Returns count of events grouped by type.
  """
  def count_events_by_type do
    Event
    |> group_by([e], e.event_type)
    |> select([e], {e.event_type, count(e.id)})
    |> Repo.all()
    |> Map.new()
  end

  @doc """
  Gets aggregated daily statistics for a specific date.
  First tries the materialized view, falls back to live query if needed.
  """
  def get_daily_stats(date) do
    # Try to get from materialized view first
    case get_daily_stats_from_view(date) do
      nil -> calculate_daily_stats_live(date)
      stats -> stats
    end
  end

  @doc """
  Refreshes the materialized view for daily stats.
  Should be called periodically (e.g., hourly via cron job).
  """
  def refresh_daily_stats do
    Repo.query!("REFRESH MATERIALIZED VIEW CONCURRENTLY analytics_daily_stats")
    :ok
  end

  @doc """
  Ensures a partition exists for the given date.
  This is called automatically when creating events.
  """
  def ensure_partition_exists(datetime) do
    date = DateTime.to_date(datetime)
    
    Repo.query!(
      "SELECT create_analytics_partition_if_not_exists($1::date)",
      [date]
    )
    
    :ok
  end

  @doc """
  Counts events by specific criteria.
  Useful for dashboard widgets.
  """
  def count_events(filters \\ []) do
    query = Event
    
    query = if filters[:event_type] do
      where(query, [e], e.event_type == ^filters[:event_type])
    else
      query
    end
    
    query = if filters[:since] do
      where(query, [e], e.inserted_at >= ^filters[:since])
    else
      query
    end
    
    Repo.aggregate(query, :count, :id)
  end

  @doc """
  Gets unique visitor count for a date range.
  """
  def count_unique_visitors(start_date, end_date) do
    Event
    |> where([e], e.inserted_at >= ^start_date and e.inserted_at <= ^end_date)
    |> where([e], not is_nil(e.visitor_id))
    |> select([e], fragment("COUNT(DISTINCT ?)", e.visitor_id))
    |> Repo.one()
  end

  # Private functions

  defp get_daily_stats_from_view(date) do
    query = """
    SELECT 
      date,
      SUM(event_count) as total_events,
      SUM(unique_visitors) as unique_visitors,
      SUM(CASE WHEN event_type = 'pageview' THEN event_count ELSE 0 END) as pageviews,
      SUM(CASE WHEN event_type = 'conversion' THEN event_count ELSE 0 END) as conversions
    FROM analytics_daily_stats
    WHERE date = $1
    GROUP BY date
    """
    
    case Repo.query(query, [date]) do
      {:ok, %{rows: [[date, total, visitors, pageviews, conversions]]}} ->
        %{
          date: date,
          total_events: total,
          unique_visitors: visitors,
          pageviews: pageviews,
          conversions: conversions
        }
      _ -> nil
    end
  end

  defp calculate_daily_stats_live(date) do
    start_time = DateTime.new!(date, ~T[00:00:00])
    end_time = DateTime.new!(date, ~T[23:59:59])
    
    events = list_events_in_range(start_time, end_time)
    
    %{
      date: date,
      total_events: length(events),
      unique_visitors: events |> Enum.map(& &1.visitor_id) |> Enum.uniq() |> length(),
      pageviews: Enum.count(events, & &1.event_type == "pageview"),
      conversions: Enum.count(events, & &1.event_type == "conversion")
    }
  end

  @doc """
  Returns events between two dates.
  """
  def events_between(start_date, end_date) do
    start_datetime = DateTime.new!(start_date, ~T[00:00:00])
    end_datetime = DateTime.new!(end_date, ~T[23:59:59])
    
    Event
    |> where([e], e.inserted_at >= ^start_datetime and e.inserted_at <= ^end_datetime)
    |> order_by([e], desc: e.inserted_at)
    |> Repo.all()
  end

  @doc """
  Counts events by type.
  """
  def count_events_by_type(event_type) do
    Event
    |> where([e], e.event_type == ^event_type)
    |> select([e], count(e.id))
    |> Repo.one() || 0
  end

  @doc """
  Query analytics data with various options.
  Used for dashboard and reporting.
  """
  def query_data(data_type, opts \\ []) do
    since = Keyword.get(opts, :since, Date.add(Date.utc_today(), -30))
    until = Keyword.get(opts, :until, Date.utc_today())
    group_by = Keyword.get(opts, :group_by)
    
    query = case data_type do
      :page_views -> 
        Event
        |> where([e], e.event_type == "page_view")
        |> where([e], fragment("?::date", e.inserted_at) >= ^since)
        |> where([e], fragment("?::date", e.inserted_at) <= ^until)
        
      :conversions ->
        Event
        |> where([e], e.event_type == "conversion")
        |> where([e], fragment("?::date", e.inserted_at) >= ^since)
        |> where([e], fragment("?::date", e.inserted_at) <= ^until)
        
      :events ->
        Event
        |> where([e], fragment("?::date", e.inserted_at) >= ^since)
        |> where([e], fragment("?::date", e.inserted_at) <= ^until)
        
      :sessions ->
        # For sessions, we'll use visitor_id as a proxy
        Event
        |> where([e], fragment("?::date", e.inserted_at) >= ^since)
        |> where([e], fragment("?::date", e.inserted_at) <= ^until)
        |> distinct([e], e.visitor_id)
    end
    
    result = case group_by do
      :timestamp ->
        query
        |> group_by([e], fragment("date(?)", e.inserted_at))
        |> select([e], %{
          date: fragment("date(?)", e.inserted_at),
          count: count(e.id),
          unique_visitors: fragment("count(distinct ?)", e.visitor_id)
        })
        |> Repo.all()
        |> Enum.map(fn row -> {row.date, row} end)
        |> Map.new()
        
      :utm_source ->
        query
        |> group_by([e], e.utm_source)
        |> select([e], %{
          source: e.utm_source,
          count: count(e.id),
          unique_visitors: fragment("count(distinct ?)", e.visitor_id)
        })
        |> Repo.all()
        |> Enum.map(fn row -> {row.source || "direct", row} end)
        |> Map.new()
        
      _ ->
        Repo.all(query)
    end
    
    {:ok, result}
  end
end