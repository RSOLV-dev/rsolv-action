defmodule Rsolv.FunnelTracking do
  @moduledoc """
  The FunnelTracking context for tracking customer conversion funnel metrics.

  This module provides functions to:
  - Track events at each stage of the conversion funnel
  - Record customer journeys through the funnel
  - Query funnel metrics and conversion rates
  - Generate dashboard analytics

  ## Funnel Stages

  1. **Website Visit** - User visits the homepage, blog, or pricing page
  2. **Signup** - User creates an account (early access or full registration)
  3. **API Key Creation** - User generates their first API key
  4. **Activation** - User makes their first successful API call
  5. **Retention** - User makes 2+ API calls

  ## Usage

  ### Track a page view:
      FunnelTracking.track_page_view(%{
        visitor_id: "uuid",
        session_id: "session_uuid",
        page_path: "/",
        utm_source: "twitter"
      })

  ### Track a signup:
      FunnelTracking.track_signup(customer, %{
        session_id: "session_uuid",
        visitor_id: "uuid",
        utm_source: "twitter"
      })

  ### Track API key creation:
      FunnelTracking.track_api_key_creation(customer)

  ### Track first API call:
      FunnelTracking.track_api_call(customer)
  """

  import Ecto.Query, warn: false
  alias Rsolv.Repo
  alias Rsolv.FunnelTracking.{FunnelEvent, CustomerJourney, FunnelMetric}
  alias Rsolv.Customers.Customer

  ## Event Tracking

  @doc """
  Tracks a page view event.

  ## Options

  - `:visitor_id` - Anonymous visitor ID (from cookie)
  - `:session_id` - Session ID
  - `:page_path` - Page path visited
  - `:utm_source`, `:utm_medium`, etc. - UTM parameters
  - `:ip_address` - Visitor IP address
  - `:user_agent` - Browser user agent
  - `:referrer` - HTTP referrer
  """
  def track_page_view(attrs \\ %{}) do
    attrs = Map.put(attrs, :event_type, "page_view")

    %FunnelEvent{}
    |> FunnelEvent.changeset(attrs)
    |> Repo.insert()
  end

  @doc """
  Tracks a signup event and updates the customer journey.

  Should be called when a customer completes registration.
  """
  def track_signup(%Customer{} = customer, attrs \\ %{}) do
    Repo.transaction(fn ->
      # Create the funnel event
      event_attrs =
        attrs
        |> Map.put(:event_type, "signup")
        |> Map.put(:customer_id, customer.id)

      {:ok, event} =
        %FunnelEvent{}
        |> FunnelEvent.changeset(event_attrs)
        |> Repo.insert()

      # Create or update customer journey
      journey = get_or_create_journey(customer.id, attrs)

      utm_params = extract_utm_params(attrs)
      signup_at = Map.get(attrs, :inserted_at, DateTime.utc_now())

      journey
      |> CustomerJourney.record_signup(signup_at, utm_params)
      |> Repo.update!()

      event
    end)
  end

  @doc """
  Tracks API key creation event.
  """
  def track_api_key_creation(%Customer{} = customer, attrs \\ %{}) do
    Repo.transaction(fn ->
      # Create the funnel event
      event_attrs =
        attrs
        |> Map.put(:event_type, "api_key_created")
        |> Map.put(:customer_id, customer.id)

      {:ok, event} =
        %FunnelEvent{}
        |> FunnelEvent.changeset(event_attrs)
        |> Repo.insert()

      # Update customer journey
      journey = get_or_create_journey(customer.id, attrs)
      created_at = Map.get(attrs, :inserted_at, DateTime.utc_now())

      journey
      |> CustomerJourney.record_api_key_creation(created_at)
      |> Repo.update!()

      event
    end)
  end

  @doc """
  Tracks an API call event.

  Automatically determines if this is the first call (activation) or
  a subsequent call (retention).
  """
  def track_api_call(%Customer{} = customer, attrs \\ %{}) do
    Repo.transaction(fn ->
      journey = get_or_create_journey(customer.id, attrs)
      called_at = Map.get(attrs, :inserted_at, DateTime.utc_now())

      # Determine if this is first or subsequent call
      event_type =
        if journey.first_api_call_at do
          "api_call"
        else
          "first_api_call"
        end

      # Create the funnel event
      event_attrs =
        attrs
        |> Map.put(:event_type, event_type)
        |> Map.put(:customer_id, customer.id)

      {:ok, event} =
        %FunnelEvent{}
        |> FunnelEvent.changeset(event_attrs)
        |> Repo.insert()

      # Update customer journey
      updated_journey =
        cond do
          # First API call (activation)
          is_nil(journey.first_api_call_at) ->
            journey
            |> CustomerJourney.record_first_api_call(called_at)
            |> Repo.update!()

          # Second API call (retention)
          is_nil(journey.second_api_call_at) ->
            journey
            |> CustomerJourney.record_second_api_call(called_at)
            |> Repo.update!()

          # Subsequent calls - no journey update needed
          true ->
            journey
        end

      {event, updated_journey}
    end)
  end

  ## Customer Journey Queries

  @doc """
  Gets a customer journey by customer ID.
  """
  def get_journey_by_customer(customer_id) do
    Repo.get_by(CustomerJourney, customer_id: customer_id)
  end

  @doc """
  Gets or creates a customer journey.
  """
  def get_or_create_journey(customer_id, attrs \\ %{}) do
    case Repo.get_by(CustomerJourney, customer_id: customer_id) do
      nil ->
        journey_attrs =
          attrs
          |> extract_utm_params()
          |> Map.put(:customer_id, customer_id)
          |> Map.put(:visitor_id, Map.get(attrs, :visitor_id))
          |> Map.put(:session_id, Map.get(attrs, :session_id))

        %CustomerJourney{}
        |> CustomerJourney.changeset(journey_attrs)
        |> Repo.insert!()

      journey ->
        journey
    end
  end

  @doc """
  Lists all customer journeys with optional filters.

  ## Options

  - `:completed_activation` - Filter by activation status (true/false)
  - `:completed_retention` - Filter by retention status (true/false)
  - `:since` - Show journeys created since this datetime
  - `:limit` - Maximum number of results
  """
  def list_journeys(opts \\ []) do
    query = CustomerJourney

    query =
      if opts[:completed_activation] != nil do
        where(query, [j], j.completed_activation == ^opts[:completed_activation])
      else
        query
      end

    query =
      if opts[:completed_retention] != nil do
        where(query, [j], j.completed_retention == ^opts[:completed_retention])
      else
        query
      end

    query =
      if opts[:since] do
        where(query, [j], j.inserted_at >= ^opts[:since])
      else
        query
      end

    query =
      if opts[:limit] do
        limit(query, ^opts[:limit])
      else
        query
      end

    query
    |> order_by([j], desc: j.inserted_at)
    |> Repo.all()
  end

  ## Funnel Metrics & Analytics

  @doc """
  Gets or calculates funnel metrics for a specific period.

  Returns a map with:
  - Stage counts (visits, signups, etc.)
  - Conversion rates between stages
  - Top UTM sources and campaigns
  """
  def get_funnel_metrics(period_start, period_end) do
    # Try to get cached metrics first
    case Repo.get_by(FunnelMetric,
           period_start: period_start,
           period_end: period_end,
           period_type: "day"
         ) do
      nil ->
        # Calculate metrics on the fly
        calculate_funnel_metrics(period_start, period_end)

      metric ->
        # Return cached metrics
        %{
          period_start: metric.period_start,
          period_end: metric.period_end,
          website_visits: metric.website_visits,
          unique_visitors: metric.unique_visitors,
          signups: metric.signups,
          api_keys_created: metric.api_keys_created,
          activated_users: metric.activated_users,
          retained_users: metric.retained_users,
          visit_to_signup_rate: metric.visit_to_signup_rate,
          signup_to_api_key_rate: metric.signup_to_api_key_rate,
          api_key_to_activation_rate: metric.api_key_to_activation_rate,
          activation_to_retention_rate: metric.activation_to_retention_rate,
          top_utm_sources: metric.top_utm_sources,
          top_utm_campaigns: metric.top_utm_campaigns
        }
    end
  end

  @doc """
  Calculates funnel metrics for a date range.
  """
  def calculate_funnel_metrics(start_date, end_date) do
    start_datetime = DateTime.new!(start_date, ~T[00:00:00])
    end_datetime = DateTime.new!(end_date, ~T[23:59:59])

    # Count events by type
    event_counts =
      FunnelEvent
      |> where([e], e.inserted_at >= ^start_datetime and e.inserted_at <= ^end_datetime)
      |> group_by([e], e.event_type)
      |> select([e], {e.event_type, count(e.id)})
      |> Repo.all()
      |> Map.new()

    # Count unique visitors
    unique_visitors =
      FunnelEvent
      |> where([e], e.inserted_at >= ^start_datetime and e.inserted_at <= ^end_datetime)
      |> where([e], e.event_type == "page_view")
      |> where([e], not is_nil(e.visitor_id))
      |> select([e], fragment("COUNT(DISTINCT ?)", e.visitor_id))
      |> Repo.one() || 0

    # Count journeys by stage
    activated_count =
      CustomerJourney
      |> where([j], j.completed_activation == true)
      |> where(
        [j],
        j.first_api_call_at >= ^start_datetime and j.first_api_call_at <= ^end_datetime
      )
      |> select([j], count(j.id))
      |> Repo.one() || 0

    retained_count =
      CustomerJourney
      |> where([j], j.completed_retention == true)
      |> where(
        [j],
        j.second_api_call_at >= ^start_datetime and j.second_api_call_at <= ^end_datetime
      )
      |> select([j], count(j.id))
      |> Repo.one() || 0

    # Get top UTM sources
    top_utm_sources =
      FunnelEvent
      |> where([e], e.inserted_at >= ^start_datetime and e.inserted_at <= ^end_datetime)
      |> where([e], not is_nil(e.utm_source))
      |> group_by([e], e.utm_source)
      |> select([e], {e.utm_source, count(e.id)})
      |> limit(10)
      |> Repo.all()
      |> Map.new()

    # Get top UTM campaigns
    top_utm_campaigns =
      FunnelEvent
      |> where([e], e.inserted_at >= ^start_datetime and e.inserted_at <= ^end_datetime)
      |> where([e], not is_nil(e.utm_campaign))
      |> group_by([e], e.utm_campaign)
      |> select([e], {e.utm_campaign, count(e.id)})
      |> limit(10)
      |> Repo.all()
      |> Map.new()

    website_visits = Map.get(event_counts, "page_view", 0)
    signups = Map.get(event_counts, "signup", 0)
    api_keys = Map.get(event_counts, "api_key_created", 0)

    %{
      period_start: start_date,
      period_end: end_date,
      website_visits: website_visits,
      unique_visitors: unique_visitors,
      signups: signups,
      api_keys_created: api_keys,
      activated_users: activated_count,
      retained_users: retained_count,
      visit_to_signup_rate: calculate_percentage(signups, website_visits),
      signup_to_api_key_rate: calculate_percentage(api_keys, signups),
      api_key_to_activation_rate: calculate_percentage(activated_count, api_keys),
      activation_to_retention_rate: calculate_percentage(retained_count, activated_count),
      top_utm_sources: top_utm_sources,
      top_utm_campaigns: top_utm_campaigns
    }
  end

  @doc """
  Aggregates and stores funnel metrics for a period.

  This should be run periodically (e.g., daily) to cache metrics.
  """
  def aggregate_metrics_for_period(period_start, period_end, period_type \\ "day") do
    metrics = calculate_funnel_metrics(period_start, period_end)

    attrs =
      metrics
      |> Map.put(:period_type, period_type)

    %FunnelMetric{}
    |> FunnelMetric.changeset(attrs)
    |> Repo.insert(
      on_conflict: {:replace_all_except, [:id, :inserted_at]},
      conflict_target: [:period_start, :period_type]
    )
  end

  @doc """
  Gets conversion funnel summary for the last N days.
  """
  def get_funnel_summary(days \\ 30) do
    end_date = Date.utc_today()
    start_date = Date.add(end_date, -days)

    calculate_funnel_metrics(start_date, end_date)
  end

  @doc """
  Gets daily funnel metrics for a date range.

  Returns a list of metrics, one per day.
  """
  def get_daily_metrics(start_date, end_date) do
    start_date
    |> Date.range(end_date)
    |> Enum.map(fn date ->
      get_funnel_metrics(date, date)
    end)
  end

  ## Helper Functions

  defp extract_utm_params(attrs) do
    Map.take(attrs, [:utm_source, :utm_medium, :utm_campaign, :utm_term, :utm_content])
  end

  defp calculate_percentage(_numerator, 0), do: Decimal.new("0.00")

  defp calculate_percentage(numerator, denominator) do
    Decimal.from_float(numerator / denominator * 100)
    |> Decimal.round(2)
  end
end
