defmodule RsolvWeb.Services.Analytics do
  @moduledoc """
  Service for tracking and analyzing user interactions.
  Handles event tracking, conversion measurement, and data persistence.

  This module provides a central location for all analytics-related functionality,
  making it easier to:
  1. Track consistent events across the application
  2. Manage privacy and data retention policies
  3. Integrate with various analytics providers (Plausible, internal DB, etc.)
  4. Generate reports and dashboards
  """
  require Logger

  # Define core events for consistency
  @events %{
    page_view: "page_view",
    form_submit: "form_submit",
    form_success: "form_success",
    form_error: "form_error",
    cta_click: "cta_click",
    section_view: "section_view",
    conversion: "conversion",
    session_start: "session_start",
    session_end: "session_end"
  }

  # Define attributes to capture for all events in the build_event_data function
  # Common attributes include timestamp, user_id, page_path, referrer, UTM parameters, device info

  @doc """
  Track a user interaction event with the system.
  Records detailed information while maintaining privacy.

  ## Examples

      track("page_view", %{page: "/", referrer: "https://google.com"})
      track("form_submit", %{form_id: "early-access", email_domain: "company.com"})
  """
  def track(event_name, attributes \\ %{}) do
    # Normalize attributes to use atom keys for internal processing
    normalized_attrs = normalize_attributes(attributes)

    # Validate and get event name
    event = validate_event_name(event_name)

    # Merge with default attributes
    event_data = build_event_data(event, normalized_attrs)

    # Log the event for debug/dev purposes
    log_event(event_data)

    # Store in persistent storage (local metrics)
    store_event(event_data)

    # Forward to external analytics if configured
    if external_analytics_enabled?() do
      forward_to_external_analytics(event_data)
    end

    # Return the event data for potential use by the caller
    {:ok, event_data}
  end

  @doc """
  Track a page view event, including referrer and path information.

  ## Examples

      track_page_view("/", "https://google.com")
  """
  def track_page_view(path, referrer \\ nil, additional_attrs \\ %{}) do
    attrs =
      Map.merge(
        %{
          page_path: path,
          referrer: referrer
        },
        additional_attrs
      )

    track(@events.page_view, attrs)
  end

  @doc """
  Track a form submission event including form details and validation status.

  ## Examples

      track_form_submission("early-access", "submit", %{email_domain: "company.com"})
      track_form_submission("early-access", "error", %{error_type: "validation"})
  """
  def track_form_submission(form_id, status, attributes \\ %{}) do
    event =
      case status do
        "success" -> @events.form_success
        "error" -> @events.form_error
        _ -> @events.form_submit
      end

    attrs =
      Map.merge(
        %{
          form_id: form_id,
          status: status
        },
        attributes
      )

    track(event, attrs)
  end

  @doc """
  Track a conversion event (such as a successful signup).

  ## Examples

      track_conversion("early-access-signup", %{source: "landing-page"})
  """
  def track_conversion(conversion_type, attributes \\ %{}) do
    attrs =
      Map.merge(
        %{
          conversion_type: conversion_type,
          timestamp: DateTime.utc_now() |> DateTime.to_string()
        },
        attributes
      )

    track(@events.conversion, attrs)
  end

  @doc """
  Track a CTA (Call to Action) click.

  ## Examples

      track_cta_click("get-early-access", "/pricing", %{section: "hero"})
  """
  def track_cta_click(cta_id, destination, attributes \\ %{}) do
    attrs =
      Map.merge(
        %{
          cta_id: cta_id,
          destination: destination
        },
        attributes
      )

    track(@events.cta_click, attrs)
  end

  @doc """
  Track when a specific section of the page comes into view.

  ## Examples

      track_section_view("pricing", 120) # viewed for 120 seconds
  """
  def track_section_view(section_id, duration_seconds \\ nil, attributes \\ %{}) do
    attrs =
      Map.merge(
        %{
          section_id: section_id,
          duration_seconds: duration_seconds
        },
        attributes
      )

    track(@events.section_view, attrs)
  end

  @doc """
  Get analytics data for the dashboard or reporting.

  ## Examples

      get_analytics_data(:conversions, since: ~D[2023-01-01], until: ~D[2023-01-31])
      get_analytics_data(:page_views, group_by: :source)
  """
  def get_analytics_data(metric, _opts \\ []) do
    # We'll use opts in the future for filtering and aggregation
    # Implementation will retrieve data from the persistent storage
    # and format it according to the requested metric and options
    # Example usage of opts that will be implemented later:
    # time_range = Keyword.get(opts, :time_range, :all)

    # For now, return a placeholder
    {:ok, %{metric: metric, sample_data: %{count: 42}}}
  end

  # Private Helpers

  # Safely convert string keys to atoms for internal use
  # Only converts known safe keys to avoid atom table exhaustion
  defp normalize_attributes(attributes) when is_map(attributes) do
    for {key, val} <- attributes, into: %{} do
      atom_key =
        cond do
          is_atom(key) -> key
          is_binary(key) -> safe_to_atom(key)
          true -> key
        end

      {atom_key, val}
    end
  end

  # Convert string to atom only if it's a known safe key
  defp safe_to_atom(string) do
    try do
      String.to_existing_atom(string)
    rescue
      ArgumentError -> String.to_atom(string)
    end
  end

  # Validate event name and log warning if undefined
  defp validate_event_name(event_name) when is_binary(event_name) do
    atom_event = safe_to_atom(event_name)

    case Map.fetch(@events, atom_event) do
      {:ok, event} ->
        event

      :error ->
        Logger.warning(
          "Tracking undefined event: #{event_name}. Consider adding to @events list."
        )

        event_name
    end
  end

  defp validate_event_name(event_name), do: event_name

  # Build complete event data structure with defaults
  defp build_event_data(event_name, attributes) do
    # Generate anonymous session ID if not exists
    session_id =
      Map.get(attributes, :user_id) ||
        Map.get(attributes, :session_id) ||
        generate_anonymous_id()

    # Build base event data
    base_data = %{
      event: event_name,
      timestamp: DateTime.utc_now() |> DateTime.to_string(),
      user_id: session_id
    }

    # Merge with provided attributes
    Map.merge(base_data, attributes)
  end

  # Log event for development and debugging
  defp log_event(event_data) do
    Logger.info("Analytics event tracked",
      event: event_data.event,
      metadata: %{
        details: Map.drop(event_data, [:event, :timestamp])
      }
    )
  end

  # Store event in persistent storage
  defp store_event(event_data) do
    # Convert to database format
    attrs = %{
      event_type: event_data.event,
      visitor_id: event_data.user_id,
      page_path: Map.get(event_data, :page_path),
      referrer: Map.get(event_data, :referrer),
      utm_source: Map.get(event_data, :utm_source),
      utm_medium: Map.get(event_data, :utm_medium),
      utm_campaign: Map.get(event_data, :utm_campaign),
      utm_content: Map.get(event_data, :utm_content),
      utm_term: Map.get(event_data, :utm_term),
      user_agent: Map.get(event_data, :user_agent),
      ip_address: Map.get(event_data, :ip_address),
      metadata: format_metadata(event_data)
    }

    # Store in database via Analytics context
    case Rsolv.Analytics.create_event(attrs) do
      {:ok, _event} ->
        :ok

      {:error, changeset} ->
        Logger.error("Failed to store analytics event",
          event: event_data.event,
          errors: changeset.errors
        )

        :error
    end
  end

  # Format additional data as JSON for metadata field
  defp format_metadata(event_data) do
    # Remove standard fields that are stored in dedicated columns
    Map.drop(
      event_data,
      [
        :event,
        :timestamp,
        :user_id,
        :page_path,
        :referrer,
        :utm_source,
        :utm_medium,
        :utm_campaign,
        :utm_content,
        :utm_term,
        :user_agent,
        :ip_address
      ]
    )
  end

  # Forward to external analytics service if configured
  defp forward_to_external_analytics(event_data) do
    # Get provider configuration
    provider = Application.get_env(:rsolv, :analytics_provider, :plausible)

    case provider do
      :plausible ->
        # Implementation for Plausible would go here
        Logger.info("Would forward to Plausible: #{inspect(event_data)}")

      :google_analytics ->
        # Implementation for Google Analytics would go here
        Logger.info("Would forward to Google Analytics: #{inspect(event_data)}")

      :custom ->
        # Implementation for custom analytics would go here
        Logger.info("Would forward to custom analytics endpoint: #{inspect(event_data)}")

      _ ->
        Logger.warning("Unknown analytics provider: #{provider}")
    end
  end

  # Check if external analytics is enabled
  defp external_analytics_enabled? do
    Application.get_env(:rsolv, :enable_external_analytics, false)
  end

  # Generate an anonymous ID for session tracking
  defp generate_anonymous_id do
    :crypto.strong_rand_bytes(16)
    |> Base.encode16(case: :lower)
  end
end
