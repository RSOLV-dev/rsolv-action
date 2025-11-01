defmodule RsolvWeb.PageController do
  use RsolvWeb, :controller
  require Logger
  alias RsolvWeb.Services.Analytics
  alias RsolvWeb.Services.Metrics
  alias RsolvWeb.Services.ConvertKit
  alias Rsolv.FeatureFlags

  # Adding a health check endpoint for Docker
  def health(conn, _params) do
    # Get clustering information
    current_node = Node.self()
    connected_nodes = Node.list()
    node_count = length(connected_nodes) + 1

    # Determine cluster health status
    cluster_status =
      cond do
        # If clustering is not enabled (non-clustered deployment)
        current_node == :nonode@nohost -> "not_configured"
        # If we have connected nodes
        length(connected_nodes) > 0 -> "healthy"
        # If we're a single node but clustering is enabled
        true -> "single_node"
      end

    # Check Mnesia status for rate limiting
    {mnesia_status, mnesia_info} = check_mnesia_health()

    # Check database health
    {db_status, db_message, db_info} = check_database_health()

    # Check analytics readiness (partition exists for current month)
    {analytics_status, analytics_message} = check_analytics_health()

    # Check Phoenix configuration (secrets, salts, etc.)
    {config_status, config_info} = check_phoenix_configuration()

    # Determine overall health status
    overall_status =
      cond do
        db_status == "error" || analytics_status == "error" || config_status == "error" ->
          "unhealthy"

        db_status == "warning" || analytics_status == "warning" || mnesia_status == "warning" ||
            config_status == "warning" ->
          "degraded"

        cluster_status == "single_node" ->
          "warning"

        true ->
          "ok"
      end

    # Build response
    health_data = %{
      status: overall_status,
      timestamp: DateTime.utc_now() |> DateTime.to_string(),
      clustering: %{
        enabled: current_node != :nonode@nohost,
        status: cluster_status,
        current_node: to_string(current_node),
        connected_nodes: Enum.map(connected_nodes, &to_string/1),
        node_count: node_count
      },
      mnesia: mnesia_info,
      database:
        Map.merge(
          %{
            status: db_status,
            message: db_message
          },
          db_info || %{}
        ),
      analytics: %{
        status: analytics_status,
        message: analytics_message
      },
      phoenix_config:
        Map.merge(
          %{
            status: config_status
          },
          config_info || %{}
        )
    }

    # Return appropriate status code based on health
    status_code =
      case overall_status do
        "unhealthy" -> 503
        # Still return 200 for degraded to avoid k8s killing the pod
        "degraded" -> 200
        _ -> 200
      end

    # Return health check response
    conn
    |> put_resp_content_type("application/json")
    |> send_resp(status_code, JSON.encode!(health_data))
  end

  # Check database connectivity
  defp check_database_health do
    try do
      # Simple query to test database connection
      Rsolv.Repo.query!("SELECT 1")

      # Get additional database metadata for troubleshooting
      db_info = get_database_info()
      {"ok", "Database connection successful", db_info}
    rescue
      error ->
        Logger.error("Health check: Database error", error: inspect(error))
        {"error", "Database connection failed: #{inspect(error)}", %{}}
    end
  end

  defp get_database_info do
    try do
      # Get current database name
      %{rows: [[database]]} = Rsolv.Repo.query!("SELECT current_database()")

      # Get database host from connection config
      config = Rsolv.Repo.config()
      hostname = config[:hostname] || "unknown"
      port = config[:port] || "unknown"
      username = config[:username] || "unknown"

      %{
        database: database,
        hostname: hostname,
        port: port,
        username: username
      }
    rescue
      error ->
        Logger.warning("Could not get database info: #{inspect(error)}")
        %{error: "Could not retrieve database metadata"}
    end
  end

  # Check Mnesia health and clustering status
  defp check_mnesia_health do
    try do
      # Check if Mnesia is running
      mnesia_running = :mnesia.system_info(:is_running) == :yes

      # Get Mnesia-specific information
      if mnesia_running do
        # Get Mnesia nodes
        running_db_nodes = :mnesia.system_info(:running_db_nodes)
        db_nodes = :mnesia.system_info(:db_nodes)

        # Check rate limiter table
        tables = :mnesia.system_info(:tables)
        rate_limiter_table = :rsolv_rate_limiter
        table_exists = rate_limiter_table in tables

        table_info =
          if table_exists do
            # Get table replicas
            ram_copies =
              try do
                :mnesia.table_info(rate_limiter_table, :ram_copies)
              rescue
                _ -> []
              end

            disc_copies =
              try do
                :mnesia.table_info(rate_limiter_table, :disc_copies)
              rescue
                _ -> []
              end

            # Get table size
            table_size =
              try do
                :mnesia.table_info(rate_limiter_table, :size)
              rescue
                _ -> 0
              end

            %{
              exists: true,
              ram_copies: Enum.map(ram_copies, &to_string/1),
              disc_copies: Enum.map(disc_copies, &to_string/1),
              size: table_size
            }
          else
            %{
              exists: false,
              message: "Rate limiter table not found"
            }
          end

        # Determine Mnesia health status
        # Each node shows itself as running_db_node, so we need to count total cluster nodes
        # Current node + connected nodes
        total_cluster_nodes = 1 + length(Node.list())
        expected_db_nodes = length(db_nodes)

        status =
          cond do
            not table_exists -> "warning"
            length(running_db_nodes) < length(db_nodes) -> "degraded"
            # Only warn if we have fewer nodes than expected in cluster
            total_cluster_nodes < expected_db_nodes -> "warning"
            true -> "ok"
          end

        {status,
         %{
           status: status,
           running: true,
           running_db_nodes: Enum.map(running_db_nodes, &to_string/1),
           configured_db_nodes: Enum.map(db_nodes, &to_string/1),
           tables: Enum.map(tables, &to_string/1),
           rate_limiter_table: table_info
         }}
      else
        {"error",
         %{
           status: "error",
           running: false,
           message: "Mnesia is not running"
         }}
      end
    rescue
      error ->
        Logger.error("Health check: Mnesia error", error: inspect(error))

        {"error",
         %{
           status: "error",
           message: "Failed to check Mnesia: #{inspect(error)}"
         }}
    end
  end

  # Check if analytics partitions are properly set up
  defp check_analytics_health do
    try do
      # Get current date for partition check
      current_date = Date.utc_today()

      partition_name =
        "analytics_events_#{current_date.year}_#{String.pad_leading(to_string(current_date.month), 2, "0")}"

      # Check if partition exists
      query = """
        SELECT EXISTS (
          SELECT 1
          FROM pg_tables
          WHERE schemaname = 'public'
            AND tablename = $1
        )
      """

      case Rsolv.Repo.query(query, [partition_name]) do
        {:ok, %{rows: [[true]]}} ->
          {"ok", "Analytics partition exists for current month"}

        {:ok, %{rows: [[false]]}} ->
          # Try to create the partition
          Logger.info("Health check: Creating missing analytics partition for #{partition_name}")
          Rsolv.Analytics.ensure_partition_exists(DateTime.utc_now())
          # Return warning instead of error to allow pod to start
          {"warning", "Analytics partition was missing but has been created"}

        {:error, error} ->
          # Return warning instead of error to allow pod to start
          Logger.warning("Health check: Failed to check analytics partition: #{inspect(error)}")
          {"warning", "Analytics partition check failed: #{inspect(error)}"}
      end
    rescue
      error ->
        Logger.warning("Health check: Analytics error: #{inspect(error)}")
        # Return warning instead of error to allow pod to start
        {"warning", "Analytics health check failed: #{inspect(error)}"}
    end
  end

  # Check critical Phoenix configuration that caused the production outages
  defp check_phoenix_configuration do
    try do
      issues = []
      warnings = []
      config_info = %{}

      # Check secret key base
      secret_key_base = Application.get_env(:rsolv, RsolvWeb.Endpoint)[:secret_key_base]

      {issues, config_info} =
        case secret_key_base do
          nil ->
            {issues ++ ["secret_key_base is not configured"],
             Map.put(config_info, :secret_key_configured, false)}

          key when byte_size(key) < 64 ->
            {issues ++ ["secret_key_base is too short (#{byte_size(key)} bytes, need 64+)"],
             Map.merge(config_info, %{
               secret_key_configured: true,
               secret_key_base_length: byte_size(key)
             })}

          key ->
            {issues,
             Map.merge(config_info, %{
               secret_key_base_length: byte_size(key),
               secret_key_configured: true
             })}
        end

      # Check LiveView signing salt
      live_view_config = Application.get_env(:rsolv, RsolvWeb.Endpoint)[:live_view] || []
      signing_salt = live_view_config[:signing_salt]

      {issues, warnings, config_info} =
        case signing_salt do
          nil ->
            {issues ++ ["live_view signing_salt is not configured"], warnings,
             Map.put(config_info, :live_view_salt_configured, false)}

          salt when byte_size(salt) < 8 ->
            {issues,
             warnings ++
               ["live_view signing_salt is short (#{byte_size(salt)} bytes, recommend 8+)"],
             Map.merge(config_info, %{
               live_view_salt_length: byte_size(salt),
               live_view_salt_configured: true
             })}

          salt ->
            {issues, warnings,
             Map.merge(config_info, %{
               live_view_salt_length: byte_size(salt),
               live_view_salt_configured: true
             })}
        end

      # Check if Phoenix can start properly (basic endpoint config)
      endpoint_configured =
        case Application.get_env(:rsolv, RsolvWeb.Endpoint) do
          nil ->
            false

          config when is_list(config) ->
            Keyword.has_key?(config, :url) and Keyword.has_key?(config, :render_errors)

          _ ->
            false
        end

      config_info = Map.put(config_info, :endpoint_configured, endpoint_configured)

      # Determine status
      status =
        cond do
          length(issues) > 0 -> "error"
          length(warnings) > 0 -> "warning"
          true -> "ok"
        end

      # Add issues and warnings to response
      final_info =
        config_info
        |> Map.put(:issues, issues)
        |> Map.put(:warnings, warnings)
        |> Map.put(
          :message,
          case status do
            "error" -> "Critical Phoenix configuration issues detected"
            "warning" -> "Phoenix configuration warnings detected"
            "ok" -> "Phoenix configuration is healthy"
          end
        )

      {status, final_info}
    rescue
      error ->
        Logger.error("Health check: Phoenix config error", error: inspect(error))
        {"error", %{message: "Phoenix configuration check failed: #{inspect(error)}"}}
    end
  end

  def home(conn, _params) do
    # Track page view with referrer information
    referrer = get_req_header(conn, "referer") |> List.first()
    Analytics.track_page_view("/", referrer, extract_tracking_data(conn))

    # The home page is often custom made,
    # so skip the default app layout.
    render(conn, :home, layout: false)
  end

  def thank_you(conn, _params) do
    # Track page view with referrer information
    referrer = get_req_header(conn, "referer") |> List.first()
    Analytics.track_page_view("/thank-you", referrer, extract_tracking_data(conn))

    # Track conversion view for funnel completion
    tracking_data = extract_tracking_data(conn)
    Analytics.track("thank_you_view", tracking_data)

    # Add success_email to assign if available in session or flash
    conn =
      cond do
        # First check session
        get_session(conn, :success_email) ->
          assign(conn, :success_email, get_session(conn, :success_email))

        # Then check flash (from LiveView redirect)
        Phoenix.Flash.get(conn.assigns.flash, :success_email) ->
          email = Phoenix.Flash.get(conn.assigns.flash, :success_email)

          conn
          |> assign(:success_email, email)
          |> put_session(:success_email, email)

        # Default case
        true ->
          conn
      end

    # Render the thank you page
    render(conn, :thank_you, layout: false)
  end

  def early_access_feedback(conn, _params) do
    # First check if the feedback feature is enabled
    if not FeatureFlags.enabled?(:feedback_form) do
      # Track attempt to access disabled feature
      Analytics.track("feature_disabled_access", %{
        feature: "feedback_form",
        path: conn.request_path,
        method: conn.method,
        remote_ip: format_ip(conn.remote_ip)
      })

      # Redirect to home page with appropriate message
      conn
      |> put_flash(:info, "Feedback submission is temporarily unavailable.")
      |> redirect(to: ~p"/")
      |> halt()
    else
      # Track page view with referrer information
      referrer = get_req_header(conn, "referer") |> List.first()
      Analytics.track_page_view("/early-access-feedback", referrer, extract_tracking_data(conn))

      # Track section view for analytics
      tracking_data = extract_tracking_data(conn)
      Analytics.track_section_view("early_access_feedback_form", nil, tracking_data)

      # Add success_email to assign if available in session
      conn =
        if get_session(conn, :success_email) do
          assign(conn, :success_email, get_session(conn, :success_email))
        else
          conn
        end

      # Render the early access feedback page
      render(conn, :early_access_feedback, layout: false)
    end
  end

  def feedback(conn, _params) do
    # First check if the feedback feature is enabled
    if not FeatureFlags.enabled?(:feedback_form) do
      # Track attempt to access disabled feature
      Analytics.track("feature_disabled_access", %{
        feature: "feedback_form",
        path: conn.request_path,
        method: conn.method,
        remote_ip: format_ip(conn.remote_ip)
      })

      # Redirect to home page with appropriate message
      conn
      |> put_flash(:info, "Feedback submission is temporarily unavailable.")
      |> redirect(to: ~p"/")
      |> halt()
    else
      # Track page view with referrer information
      referrer = get_req_header(conn, "referer") |> List.first()
      Analytics.track_page_view("/feedback", referrer, extract_tracking_data(conn))

      # Track section view for analytics
      tracking_data = extract_tracking_data(conn)
      Analytics.track_section_view("feedback_page", nil, tracking_data)

      # Use app layout instead of no layout
      render(conn, :feedback)
    end
  end

  def submit_early_access(conn, params) do
    # First check if early access signup feature is enabled
    if not FeatureFlags.enabled?(:early_access_signup) do
      # Track attempt to access disabled feature
      Analytics.track("feature_disabled_access", %{
        feature: "early_access_signup",
        path: conn.request_path,
        method: conn.method,
        remote_ip: format_ip(conn.remote_ip)
      })

      # Redirect to home page with appropriate message
      conn
      |> put_flash(
        :info,
        "Early access registrations are currently paused. Please check back later!"
      )
      |> redirect(to: ~p"/")
      |> halt()
    else
      # Feature is enabled, proceed with normal flow
      # Track form submission event
      tracking_data = extract_tracking_data(conn)
      Analytics.track_form_submission("early-access", "submit", tracking_data)

      # Log form submission for monitoring
      Logger.info("Form submission received",
        metadata: %{
          timestamp: DateTime.utc_now() |> DateTime.to_string()
        }
      )

      # Extract email from form submission - handle all possible formats
      # This now also supports the standard form approach
      email =
        cond do
          # Direct email param (standard form)
          is_binary(params["email"]) -> params["email"]
          # LiveView and older form formats
          is_map(params["signup"]) -> params["signup"]["email"]
          is_map(params["email_form"]) -> params["email_form"]["email"]
          true -> nil
        end

      # Use enhanced email validation
      alias RsolvWeb.Validators.EmailValidator
      validation_result = EmailValidator.validate_with_feedback(email)

      # Enhanced validation with helpful feedback
      case validation_result do
        {:ok, _} ->
          # Log the submission
          Logger.info("Valid email received for processing: #{email}, validation passed")

          # Extract UTM parameters for both database and ConvertKit
          utm_params = extract_utm_params_from_conn(conn)

          # Save to database first
          signup_attrs = %{
            email: email,
            name: extract_first_name_from_email(email),
            referral_source: "landing_page",
            utm_source: Map.get(utm_params, :utm_source),
            utm_medium: Map.get(utm_params, :utm_medium),
            utm_campaign: Map.get(utm_params, :utm_campaign)
          }

          case Rsolv.EarlyAccess.create_signup(signup_attrs) do
            {:ok, _signup} ->
              Logger.info("Successfully saved signup to database", email: email)

            {:error, changeset} ->
              Logger.error("Failed to save signup to database",
                email: email,
                errors: inspect(changeset.errors)
              )
          end

          # Send to ConvertKit with UTM parameters
          options =
            Map.merge(utm_params, %{
              tags: ["landing-page"],
              source: "landing-page"
            })

          ConvertKit.subscribe_to_early_access(email, options)

          # Track successful conversion with full attribution data
          email_domain = email |> String.split("@") |> List.last()

          conversion_data =
            Map.merge(tracking_data, %{
              email_domain: email_domain,
              conversion_type: "early_access_signup",
              source: "landing_page",
              form_id: "early-access",
              page_path: conn.request_path
            })

          # Track as both form success and conversion for different analytics purposes
          Analytics.track_form_submission("early-access", "success", conversion_data)
          Analytics.track_conversion("early_access_signup", conversion_data)

          # Track metrics for Prometheus
          Metrics.count_signup()
          Metrics.count_signup_by_source(Map.get(conversion_data, :utm_source, "direct"))

          # Check if welcome email sequence is enabled
          if FeatureFlags.enabled?(:welcome_email_sequence) do
            Logger.info("[PAGE CONTROLLER] Welcome email sequence is ENABLED, starting sequence",
              email: email,
              feature: "welcome_email_sequence",
              timestamp: DateTime.utc_now() |> DateTime.to_string()
            )

            # Start the early access email sequence
            # Extract first name from email (if possible)
            first_name = extract_first_name_from_email(email)

            Logger.info(
              "[PAGE CONTROLLER] About to call EmailSequence.start_early_access_onboarding_sequence",
              email: email,
              first_name: first_name,
              timestamp: DateTime.utc_now() |> DateTime.to_string()
            )

            sequence_result =
              RsolvWeb.Services.EmailSequence.start_early_access_onboarding_sequence(
                email,
                first_name
              )

            Logger.info(
              "[PAGE CONTROLLER] EmailSequence.start_early_access_onboarding_sequence returned",
              result: inspect(sequence_result),
              timestamp: DateTime.utc_now() |> DateTime.to_string()
            )
          else
            Logger.info("[PAGE CONTROLLER] Welcome email sequence is DISABLED by feature flag",
              email: email,
              feature: "welcome_email_sequence",
              timestamp: DateTime.utc_now() |> DateTime.to_string()
            )
          end

          # Send admin notification email
          send_admin_notification(email, utm_params, conn)

          # Prepare celebration data for analytics
          email_domain = email |> String.split("@") |> List.last()

          celebration_data =
            %{
              email_domain: email_domain,
              source: Map.get(utm_params, :utm_source, "direct"),
              medium: Map.get(utm_params, :utm_medium, "organic"),
              campaign: Map.get(utm_params, :utm_campaign, "none")
            }
            |> JSON.encode!()

          # Store email in session for thank you page personalization
          conn =
            conn
            |> put_session(:success_email, email)
            |> put_session(:early_access_signup_success, true)
            |> put_flash(:celebration_data, celebration_data)

          # Redirect to thank you page instead of home with flash message
          redirect(conn, to: ~p"/thank-you")

        {:error, error_message} ->
          # Track validation error with detailed information
          error_data =
            Map.merge(tracking_data, %{
              error_type: "validation",
              error_details: error_message || "Invalid email format",
              email_input: email
            })

          Analytics.track_form_submission("early-access", "error", error_data)

          # Try to suggest a correction
          suggested_correction = EmailValidator.suggest_correction(email)

          # Store the suggestion in the session so we can display it on the form
          conn =
            if suggested_correction && suggested_correction != email do
              # Track suggestion generation for analytics
              Analytics.track("suggestion_generated", %{
                original_email: email,
                suggested_email: suggested_correction
              })

              conn
              |> put_session(:suggested_email, suggested_correction)
              |> put_session(:original_email, email)
            else
              conn
            end

          # Handle invalid email - with more helpful error message
          conn
          |> put_flash(:error, error_message || "Please provide a valid email address.")
          |> redirect(to: ~p"/#early-access")
      end
    end
  end

  # Extract UTM parameters from conn params if available
  defp extract_utm_params_from_conn(conn) do
    utm_params = [
      # UTM parameters - standard
      {"utm_source", :utm_source},
      {"utm_medium", :utm_medium},
      {"utm_campaign", :utm_campaign},
      {"utm_term", :utm_term},
      {"utm_content", :utm_content},

      # Extended UTM parameters for more detailed attribution
      {"utm_source_platform", :utm_source_platform},
      {"utm_source_campaign", :utm_source_campaign},
      {"utm_source_content", :utm_source_content},

      # Hidden form fields that may be passed by our client-side JS
      {"utm_source_hidden", :utm_source},
      {"utm_medium_hidden", :utm_medium},
      {"utm_campaign_hidden", :utm_campaign},
      {"utm_term_hidden", :utm_term},
      {"utm_content_hidden", :utm_content},
      {"utm_source_platform_hidden", :utm_source_platform},
      {"utm_source_campaign_hidden", :utm_source_campaign},
      {"utm_source_content_hidden", :utm_source_content}
    ]

    # Extract UTM parameters from multiple sources with fallbacks
    # 1. URL query params (highest priority)
    # 2. Form POST params
    # 3. Referrer header
    query_params = conn.query_params
    post_params = conn.body_params

    # Start with an empty map
    initial_utm = %{}

    # Add referrer info if available
    initial_utm =
      case Plug.Conn.get_req_header(conn, "referer") do
        [referer | _] ->
          uri = URI.parse(referer)

          if uri.host && uri.host != conn.host do
            Map.put(initial_utm, :utm_source, uri.host)
          else
            initial_utm
          end

        _ ->
          initial_utm
      end

    # Build map of UTM parameters with cascade priority
    result =
      Enum.reduce(utm_params, initial_utm, fn {param_name, key}, acc ->
        cond do
          # Check query params first (highest priority)
          Map.has_key?(query_params, param_name) ->
            Map.put(acc, key, Map.get(query_params, param_name))

          # Then check POST params
          Map.has_key?(post_params, param_name) ->
            Map.put(acc, key, Map.get(post_params, param_name))

          # Otherwise, keep what we have
          true ->
            acc
        end
      end)

    # Log for debugging and monitoring
    Logger.debug("Extracted UTM parameters: #{inspect(result)}")

    result
  end

  # Extract tracking data from connection and params for analytics
  defp extract_tracking_data(conn) do
    # Generate anonymous user ID from session or create a new one
    user_id =
      get_session(conn, :tracking_id) ||
        generate_tracking_id()

    # Get UTM parameters from query params or saved in session
    utm_params = extract_utm_params_from_conn(conn)

    # Get referrer information
    referrer = List.first(get_req_header(conn, "referer") || [])

    # Get device information from user agent
    user_agent = List.first(get_req_header(conn, "user-agent") || [])
    {device_type, browser, os} = parse_user_agent(user_agent)

    # Build tracking data map
    %{
      user_id: user_id,
      timestamp: DateTime.utc_now() |> DateTime.to_string(),
      page_path: conn.request_path,
      referrer: referrer,
      utm_source: Map.get(utm_params, :utm_source),
      utm_medium: Map.get(utm_params, :utm_medium),
      utm_campaign: Map.get(utm_params, :utm_campaign),
      utm_term: Map.get(utm_params, :utm_term),
      utm_content: Map.get(utm_params, :utm_content),
      utm_source_platform: Map.get(utm_params, :utm_source_platform),
      utm_source_campaign: Map.get(utm_params, :utm_source_campaign),
      utm_source_content: Map.get(utm_params, :utm_source_content),
      device_type: device_type,
      browser: browser,
      os: os
    }
  end

  # Generate a random tracking ID for anonymous users
  defp generate_tracking_id do
    :crypto.strong_rand_bytes(16)
    |> Base.encode16(case: :lower)
  end

  # Parse user agent string for device, browser, and OS information
  defp parse_user_agent(nil), do: {"unknown", "unknown", "unknown"}

  defp parse_user_agent(user_agent) do
    # Very basic parsing - would use a proper UA parsing library in production
    device_type =
      cond do
        String.contains?(user_agent, "Mobile") -> "mobile"
        String.contains?(user_agent, "Tablet") -> "tablet"
        true -> "desktop"
      end

    browser =
      cond do
        String.contains?(user_agent, "Chrome") && !String.contains?(user_agent, "Chromium") ->
          "chrome"

        String.contains?(user_agent, "Firefox") ->
          "firefox"

        String.contains?(user_agent, "Safari") && !String.contains?(user_agent, "Chrome") ->
          "safari"

        String.contains?(user_agent, "Edge") ->
          "edge"

        String.contains?(user_agent, "Opera") || String.contains?(user_agent, "OPR") ->
          "opera"

        true ->
          "other"
      end

    os =
      cond do
        String.contains?(user_agent, "Windows") ->
          "windows"

        String.contains?(user_agent, "Mac OS X") ->
          "macos"

        String.contains?(user_agent, "Linux") && !String.contains?(user_agent, "Android") ->
          "linux"

        String.contains?(user_agent, "Android") ->
          "android"

        String.contains?(user_agent, "iOS") || String.contains?(user_agent, "iPhone") ||
            String.contains?(user_agent, "iPad") ->
          "ios"

        true ->
          "other"
      end

    {device_type, browser, os}
  end

  # Extract a likely first name from an email address
  defp extract_first_name_from_email(email) do
    case String.split(email, "@") do
      [local_part | _] ->
        # Try to extract a name from the local part
        local_part = String.downcase(local_part)
        # Remove numbers and special characters
        local_part = String.replace(local_part, ~r/[^a-z.]/, "")
        # Split by dots and take the first part
        first_part = local_part |> String.split(".") |> List.first()
        # Capitalize the first letter
        if String.length(first_part) > 1 do
          String.capitalize(first_part)
        else
          # If we couldn't get a good name, return nil
          nil
        end

      _ ->
        nil
    end
  end

  # Helper for formatting IP addresses in logs
  defp format_ip(ip) when is_tuple(ip) do
    ip
    |> Tuple.to_list()
    |> Enum.join(".")
  end

  defp format_ip(_), do: "unknown"

  # Welcome email functionality is now implemented in EmailService module

  @doc """
  Renders the unsubscribe page.
  """
  def unsubscribe(conn, params) do
    # Track page view with referrer information
    referrer = get_req_header(conn, "referer") |> List.first()
    Analytics.track_page_view("/unsubscribe", referrer, extract_tracking_data(conn))

    # Get email from params if present
    email = Map.get(params, "email")

    # Log the unsubscribe page view for analytics
    if email do
      Analytics.track("unsubscribe_page_view", %{
        email: email,
        referrer: referrer
      })
    end

    render(conn, :unsubscribe, email: email)
  end

  @doc """
  Processes an unsubscribe request.
  """
  def process_unsubscribe(conn, %{"email" => email} = _params) do
    # Track form submission
    Analytics.track_form_submission("unsubscribe", "submit", extract_tracking_data(conn))

    # Validate email
    if is_valid_email?(email) do
      # Record the unsubscribe in our database
      case Rsolv.EmailManagement.create_unsubscribe(%{
             email: String.downcase(email),
             reason: "User request via unsubscribe page"
           }) do
        {:ok, _unsubscribe} ->
          Logger.info("Successfully recorded unsubscribe for #{email}")

        {:error, _changeset} ->
          Logger.error("Failed to record unsubscribe for #{email}")
      end

      # Track this event
      Analytics.track("unsubscribe_success", %{
        email: email
      })

      # Try to unsubscribe from ConvertKit if we're using it
      attempt_convertkit_unsubscribe(email)

      render(conn, :unsubscribe_success, email: email)
    else
      # Track error
      Analytics.track_form_submission("unsubscribe", "error", %{
        error_type: "validation",
        error_details: "Invalid email format",
        email_input: email
      })

      render(conn, :unsubscribe_error, email: email)
    end
  end

  def process_unsubscribe(conn, _params) do
    # No email provided
    Analytics.track_form_submission("unsubscribe", "error", %{
      error_type: "validation",
      error_details: "No email provided"
    })

    render(conn, :unsubscribe_error, email: nil)
  end

  # Attempt to unsubscribe email from ConvertKit
  defp attempt_convertkit_unsubscribe(email) do
    # Only attempt if we have ConvertKit configured
    config = Application.get_env(:rsolv, :convertkit)
    api_key = config[:api_key]

    if api_key do
      alias RsolvWeb.Services.ConvertKit

      # Log unsubscribe attempt for record keeping
      Logger.info("Attempting to unsubscribe from ConvertKit: #{email}")

      # Call ConvertKit unsubscribe API directly
      ConvertKit.unsubscribe(email)
    end
  end

  # Basic email validation from existing code
  defp is_valid_email?(email) do
    email != nil &&
      String.contains?(email, "@") &&
      String.length(email) >= 5 &&
      String.match?(email, ~r/^[^@\s]+@[^@\s]+\.[^@\s]+$/)
  end

  # Send admin notification for new signups
  defp send_admin_notification(email, utm_params, conn) do
    signup_data = build_signup_data(email, utm_params, conn)

    case Rsolv.EmailService.send_admin_signup_notification(signup_data) do
      {:ok, result} ->
        Logger.info("Admin notification sent for new signup", email: email)
        result

      {:error, error_details} ->
        Logger.error("Failed to send admin notification",
          email: email,
          error: inspect(error_details)
        )

        nil
    end
  end

  defp build_signup_data(email, utm_params, conn) do
    %{
      email: email,
      company: get_in(conn.params, ["signup", "company"]) || conn.params["company"],
      timestamp: DateTime.utc_now() |> DateTime.to_iso8601(),
      source: "landing_page",
      utm_source: Map.get(utm_params, :utm_source),
      utm_medium: Map.get(utm_params, :utm_medium),
      utm_campaign: Map.get(utm_params, :utm_campaign),
      referrer: get_req_header(conn, "referer") |> List.first()
    }
  end

  @doc """
  Renders the terms of service page.
  """
  def terms(conn, _params) do
    # Track page view
    referrer = get_req_header(conn, "referer") |> List.first()
    Analytics.track_page_view("/docs/terms", referrer, extract_tracking_data(conn))

    render(conn, :terms)
  end

  @doc """
  Renders the privacy policy page.
  """
  def privacy(conn, _params) do
    # Track page view
    referrer = get_req_header(conn, "referer") |> List.first()
    Analytics.track_page_view("/docs/privacy", referrer, extract_tracking_data(conn))

    render(conn, :privacy)
  end
end
