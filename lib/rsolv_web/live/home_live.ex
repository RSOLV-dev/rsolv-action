defmodule RsolvWeb.HomeLive do
  use RsolvWeb, :live_view
  require Logger
  alias RsolvWeb.Services.Analytics
  alias RsolvWeb.Services.EmailSequence
  alias RsolvWeb.Services.Metrics
  alias Rsolv.FeatureFlags
  alias RsolvWeb.Validators.EmailValidator
  alias RsolvWeb.Services.ConvertKit

  @impl true
  def mount(params, session, socket) do
    # Track page view
    referrer = Map.get(socket.assigns, :referrer)
    Analytics.track_page_view("/", referrer, extract_tracking_data(socket))

    socket =
      socket
      |> assign(:email, "")
      |> assign(:company, "")
      |> assign(:platforms, "")
      |> assign(:team_size, "")
      |> assign(:security_concerns, "")
      |> assign(:errors, %{})
      |> assign(:submitting, false)
      |> assign(:mobile_menu_open, false)
      |> assign(:csrf_token, session["_csrf_token"])
      |> assign(:utm_source, params["utm_source"])
      |> assign(:utm_medium, params["utm_medium"])
      |> assign(:utm_campaign, params["utm_campaign"])
      |> assign(:utm_term, params["utm_term"])
      |> assign(:utm_content, params["utm_content"])

    {:ok, socket}
  end

  @impl true
  def handle_event("toggle_mobile_menu", _params, socket) do
    {:noreply, assign(socket, :mobile_menu_open, !socket.assigns.mobile_menu_open)}
  end

  @impl true
  def handle_event("close_mobile_menu", _params, socket) do
    {:noreply, assign(socket, :mobile_menu_open, false)}
  end

  @impl true
  def handle_event("validate", %{"signup" => params}, socket) do
    errors = validate_params(params)

    # Only update fields that are present in params, preserve existing values otherwise
    socket =
      socket
      |> assign(:email, Map.get(params, "email", socket.assigns.email))
      |> assign(:company, Map.get(params, "company", socket.assigns.company))
      |> assign(:platforms, Map.get(params, "platforms", socket.assigns.platforms))
      |> assign(:team_size, Map.get(params, "team_size", socket.assigns.team_size))
      |> assign(
        :security_concerns,
        Map.get(params, "security_concerns", socket.assigns.security_concerns)
      )
      |> assign(:errors, errors)

    {:noreply, socket}
  end

  @impl true
  def handle_event("submit", %{"signup" => params}, socket) do
    # Check if early access signup feature is enabled
    if not FeatureFlags.enabled?(:early_access_signup) do
      Analytics.track("feature_disabled_access", %{
        feature: "early_access_signup",
        method: "live_view"
      })

      socket =
        put_flash(
          socket,
          :info,
          "Early access registrations are currently paused. Please check back later!"
        )

      {:noreply, socket}
    else
      errors = validate_params(params)

      if Enum.empty?(errors) do
        socket = assign(socket, :submitting, true)

        # Process the submission with optional company
        options =
          extract_utm_params(socket)
          |> Map.put(:company, params["company"])

        case process_early_access_submission(params["email"], socket, options) do
          {:ok, signup} ->
            # Extract email domain for analytics
            email_domain =
              case String.split(signup.email, "@") do
                [_, domain] -> domain
                _ -> "unknown"
              end

            # Prepare celebration event data
            event_data = %{
              email_domain: email_domain,
              source: signup.utm_source || "direct",
              medium: signup.utm_medium || "organic",
              campaign: signup.utm_campaign || "none"
            }

            # Store celebration data in flash for the thank-you page
            socket =
              socket
              |> put_flash(:success, "Thank you for signing up!")
              |> put_flash(:celebration_data, Jason.encode!(event_data))
              |> push_navigate(to: "/thank-you")

            {:noreply, socket}

          {:error, message} ->
            socket =
              socket
              |> assign(:submitting, false)
              |> put_flash(:error, message)

            {:noreply, socket}
        end
      else
        {:noreply, assign(socket, :errors, errors)}
      end
    end
  end

  defp validate_params(params) do
    errors = %{}

    email = params["email"] || ""

    # Validate email
    case EmailValidator.validate_with_feedback(email) do
      {:ok, _} -> errors
      {:error, message} -> Map.put(errors, :email, message)
    end
  end

  defp process_early_access_submission(email, socket, options) do
    # Track form submission
    tracking_data = extract_tracking_data(socket)
    Analytics.track_form_submission("early-access", "submit", tracking_data)

    # Log for debugging
    Logger.info("LiveView form submission received",
      metadata: %{
        email: email,
        company: Map.get(options, :company),
        timestamp: DateTime.utc_now() |> DateTime.to_string()
      }
    )

    # Save to database and send to ConvertKit
    utm_options = extract_utm_params(socket)

    all_options =
      Map.merge(utm_options, %{
        tags: ["landing-page-liveview"],
        source: "landing-page-liveview",
        company: Map.get(options, :company)
      })

    # Save to database with company field
    signup_attrs = %{
      email: email,
      source: "landing_page_liveview",
      utm_source: Map.get(all_options, :utm_source),
      utm_medium: Map.get(all_options, :utm_medium),
      utm_campaign: Map.get(all_options, :utm_campaign),
      metadata: all_options
    }

    # Add company if provided
    signup_attrs =
      if company = Map.get(options, :company) do
        Map.put(signup_attrs, :company, company)
      else
        signup_attrs
      end

    # Save to database
    case Rsolv.EarlyAccess.create_signup(signup_attrs) do
      {:ok, signup} ->
        Logger.info("Successfully saved signup to database: #{email}")

        # Send to ConvertKit with all options including company
        ConvertKit.subscribe_to_early_access(email, all_options)

        # Track conversion
        email_domain = email |> String.split("@") |> List.last()

        conversion_data =
          Map.merge(tracking_data, %{
            email_domain: email_domain,
            conversion_type: "early_access_signup",
            source: "landing_page_liveview",
            form_id: "early-access"
          })

        Analytics.track_form_submission("early-access", "success", conversion_data)
        Analytics.track_conversion("early_access_signup", conversion_data)

        # Track metrics
        Metrics.count_signup()
        Metrics.count_signup_by_source(Map.get(conversion_data, :utm_source, "direct"))

        # Start email sequence if enabled
        if FeatureFlags.enabled?(:welcome_email_sequence) do
          first_name = extract_first_name_from_email(email)
          EmailSequence.start_early_access_onboarding_sequence(email, first_name)
        end

        # Send admin notification email
        Logger.info("[HOME LIVE] About to send admin notification email",
          email: email,
          timestamp: DateTime.utc_now() |> DateTime.to_string()
        )

        # Build signup data for admin notification
        signup_data = %{
          email: email,
          company: Map.get(options, :company),
          timestamp: DateTime.utc_now() |> DateTime.to_iso8601(),
          source: "landing_page_liveview",
          utm_source: Map.get(all_options, :utm_source),
          utm_medium: Map.get(all_options, :utm_medium),
          utm_campaign: Map.get(all_options, :utm_campaign),
          referrer: Map.get(tracking_data, :referrer)
        }

        case Rsolv.Emails.admin_signup_notification(signup_data) |> Rsolv.Mailer.deliver_now() do
          {:ok, result} ->
            Logger.info("[HOME LIVE] Successfully sent admin notification email",
              email: email,
              result: inspect(result),
              timestamp: DateTime.utc_now() |> DateTime.to_string()
            )

          result when is_map(result) ->
            Logger.info("[HOME LIVE] Admin notification email sent (Bamboo format)",
              email: email,
              result: inspect(result),
              timestamp: DateTime.utc_now() |> DateTime.to_string()
            )

          {:error, error} ->
            Logger.error("[HOME LIVE] Failed to send admin notification email",
              email: email,
              error: inspect(error),
              timestamp: DateTime.utc_now() |> DateTime.to_string()
            )
        end

        {:ok, signup}

      {:error, changeset} ->
        Logger.error("Failed to save signup: #{inspect(changeset.errors)}")

        # Return appropriate error message
        error_message =
          cond do
            Enum.any?(changeset.errors, fn {field, {msg, _}} ->
              field == :email and msg == "has already been taken"
            end) ->
              "This email has already signed up for early access."

            Enum.any?(changeset.errors, fn {field, _} -> field == :email end) ->
              "Please provide a valid email address."

            true ->
              "Unable to process signup. Please try again."
          end

        {:error, error_message}
    end
  end

  defp generate_tracking_id do
    :crypto.strong_rand_bytes(16)
    |> Base.encode16(case: :lower)
  end

  defp extract_tracking_data(socket) do
    %{
      user_id: generate_tracking_id(),
      timestamp: DateTime.utc_now() |> DateTime.to_string(),
      page_path: "/",
      referrer: Map.get(socket.assigns, :referrer)
    }
  end

  defp extract_utm_params(socket) do
    # In LiveView, UTM params would be passed through assigns or extracted from the URL
    %{
      utm_source: Map.get(socket.assigns, :utm_source),
      utm_medium: Map.get(socket.assigns, :utm_medium),
      utm_campaign: Map.get(socket.assigns, :utm_campaign),
      utm_term: Map.get(socket.assigns, :utm_term),
      utm_content: Map.get(socket.assigns, :utm_content)
    }
  end

  defp extract_first_name_from_email(email) do
    case String.split(email, "@") do
      [local_part | _] ->
        local_part
        |> String.downcase()
        |> String.replace(~r/[^a-z.]/, "")
        |> String.split(".")
        |> List.first()
        |> String.capitalize()

      _ ->
        nil
    end
  end

  # The render function is now handled by home_live.html.heex template
end
