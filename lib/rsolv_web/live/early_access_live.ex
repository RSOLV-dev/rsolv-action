defmodule RsolvWeb.EarlyAccessLive do
  use RsolvWeb, :live_view
  require Logger
  alias RsolvWeb.Services.Analytics
  alias RsolvWeb.Validators.EmailValidator
  alias Rsolv.EarlyAccess

  # Render function for standalone display
  def render(assigns) do
    ~H"""
    <div class="bg-white bg-opacity-10 rounded-lg p-8 backdrop-blur-sm" id="early-access-form">
      <.form for={%{}} phx-submit="submit" class="space-y-6">
        <div>
          <label for="email" class="block text-white text-left mb-2">Email Address</label>
          <div class="relative">
            <input
              type="email"
              id="email"
              name="email"
              value={@email}
              placeholder="you@company.com"
              required
              class={"email-input #{cond do
                        @error_message -> "border-red-500 focus:ring-red-500"
                        @email_valid == true -> "border-green-500 focus:ring-green-500"
                        true -> ""
                      end}"}
              phx-hook="FocusInput"
              phx-blur="validate"
            />
            <%= if @email_valid == true do %>
              <div class="absolute inset-y-0 right-0 flex items-center pr-3 pointer-events-none">
                <span class="hero-solid-check-circle w-5 h-5 text-green-500"></span>
              </div>
            <% end %>
          </div>
          <%= if @error_message do %>
            <p class="mt-1 text-red-400 text-sm">{@error_message}</p>
            <%= if @suggested_correction && @suggested_correction != @email do %>
              <p class="mt-1 text-yellow-400 text-sm">
                Did you mean <a
                  href="#"
                  phx-click="use_suggestion"
                  class="underline hover:text-yellow-300"
                ><%= @suggested_correction %></a>?
              </p>
            <% end %>
          <% end %>
        </div>

        <div>
          <button type="submit" class="w-full btn-success">
            Get Early Access
          </button>
        </div>

        <%= if @success_message do %>
          <div class="p-4 bg-green-700 bg-opacity-40 rounded-md">
            <p class="text-white">{@success_message}</p>
          </div>
        <% end %>

        <p class="text-sm text-gray-300">
          By signing up, you'll be first in line for early access. We'll never share your email with third parties.
        </p>
      </.form>
    </div>
    """
  end

  # Mount function to initialize LiveView state
  def mount(_params, session, socket) do
    # Track form view for funnel analysis
    tracking_data = extract_tracking_data(socket, session)

    # Track the form view as a section view
    Analytics.track_section_view("early-access-form", nil, tracking_data)

    {:ok,
     assign(socket,
       email: "",
       # tri-state: nil (not validated), true, false
       email_valid: nil,
       error_message: nil,
       success_message: nil,
       suggested_correction: nil,
       # Initialize current_path
       current_path: "/signup",
       # Store tracking info in socket for later events
       tracking_data: tracking_data
     )}
  end

  def handle_params(_params, uri, socket) do
    # Parse the URI to get the current path
    parsed_uri = URI.parse(uri)

    {:noreply, assign(socket, :current_path, parsed_uri.path)}
  end

  # Handle form submission
  def handle_event("submit", params, socket) do
    # Track form submission attempt
    Analytics.track_form_submission("early-access-live", "submit", socket.assigns.tracking_data)

    # Extract email from params
    email = params["email"]

    # Add extensive logging
    Logger.debug("LiveView form submission params: #{inspect(params)}")
    Logger.debug("LiveView extracted email: #{inspect(email)}")

    # Use enhanced email validation
    validation_result = EmailValidator.validate_with_feedback(email)

    case validation_result do
      {:ok, _} ->
        # Log the submission
        Logger.info("Early access signup received for email: #{email}")

        # Save to file and Kit.com
        save_email_to_file(email)

        # Track successful conversion
        email_domain = email |> String.split("@") |> List.last()

        conversion_data =
          Map.merge(socket.assigns.tracking_data, %{
            email_domain: email_domain,
            conversion_type: "early_access_signup",
            source: "liveview",
            form_id: "early-access-live"
          })

        # Track as both form success and conversion for different analytics purposes
        Analytics.track_form_submission("early-access-live", "success", conversion_data)
        Analytics.track_conversion("early_access_signup", conversion_data)

        # Use Phoenix.LiveView.push_redirect for LiveView redirects
        # We can't store session data directly from LiveView, but we can pass
        # the email as a flash message that the controller can use
        {:noreply,
         socket
         |> put_flash(:success_email, email)
         |> push_navigate(to: "/thank-you")}

      {:error, error_message} ->
        # Track validation error
        error_data =
          Map.merge(socket.assigns.tracking_data, %{
            error_type: "validation",
            error_details: error_message || "Invalid email format",
            email_input: email
          })

        Analytics.track_form_submission("early-access-live", "error", error_data)

        Logger.warning("Invalid email submitted via LiveView: #{inspect(email)}")

        # Generate suggested correction if available
        suggested_correction = EmailValidator.suggest_correction(email)

        # Return error
        {:noreply,
         assign(socket,
           email: email,
           email_valid: false,
           error_message: error_message || "Please provide a valid email address.",
           suggested_correction: suggested_correction,
           success_message: nil
         )}
    end
  end

  # Handle custom input change event from JS hook
  def handle_event("input-change", %{"value" => email}, socket) do
    # Track interaction with the form
    if String.length(email) == 1 do
      # Only track the first character typed (start of interaction)
      interaction_data = Map.put(socket.assigns.tracking_data, :interaction_type, "form_focus")
      Analytics.track("form_interaction", interaction_data)
    end

    # Use enhanced email validation
    valid = EmailValidator.is_valid?(email)

    # When typing, show validation feedback in real-time
    # But don't show errors when empty
    socket =
      if email == "" do
        assign(socket,
          email: email,
          suggested_correction: nil
        )
      else
        socket
        |> assign(:email, email)
        |> assign(:email_valid, valid)
        # Don't show errors while typing
        |> assign(:error_message, nil)
        |> assign(:suggested_correction, nil)
      end

    {:noreply, socket}
  end

  # Handle user clicking on the suggestion
  def handle_event("use_suggestion", _params, socket) do
    # Replace the email with the suggested correction
    if socket.assigns.suggested_correction do
      # Track suggestion usage for analytics
      Analytics.track("suggestion_used", %{
        original_email: socket.assigns.email,
        suggested_email: socket.assigns.suggested_correction
      })

      # Update the email field with the suggestion
      {:noreply,
       assign(socket,
         email: socket.assigns.suggested_correction,
         email_valid: true,
         error_message: nil,
         suggested_correction: nil
       )}
    else
      {:noreply, socket}
    end
  end

  # User typing in the input field - only triggered on blur now
  def handle_event("validate", %{"email" => email}, socket) do
    # Track validation event for funnel analysis
    if email != "" do
      validation_data =
        Map.merge(socket.assigns.tracking_data, %{
          email_valid: EmailValidator.is_valid?(email),
          field: "email"
        })

      Analytics.track("form_field_validation", validation_data)
    end

    # Don't re-render if the email hasn't changed
    if email == socket.assigns.email do
      {:noreply, socket}
    else
      # Get validation result with detailed feedback
      validation_result = EmailValidator.validate_with_feedback(email)

      case validation_result do
        {:ok, _} ->
          # Valid email
          {:noreply,
           socket
           |> assign(:email, email)
           |> assign(:email_valid, true)
           |> assign(:error_message, nil)
           |> assign(:suggested_correction, nil)}

        {:error, error_message} ->
          # If field is empty, don't show error yet
          if email == "" do
            {:noreply,
             socket
             |> assign(:email, email)
             |> assign(:email_valid, nil)
             |> assign(:error_message, nil)
             |> assign(:suggested_correction, nil)}
          else
            # Generate suggested correction if available
            suggested_correction = EmailValidator.suggest_correction(email)

            # Update socket with validation results
            {:noreply,
             socket
             |> assign(:email, email)
             |> assign(:email_valid, false)
             |> assign(:error_message, error_message || "Please provide a valid email address.")
             |> assign(:suggested_correction, suggested_correction)}
          end
      end
    end
  end

  # Extract tracking data from LiveView socket and session
  defp extract_tracking_data(socket, session) do
    # Generate anonymous user ID or use existing from session
    user_id = Map.get(session, "tracking_id") || generate_tracking_id()

    # Get URL and referrer information (available in LV connect params)
    connect_params = socket.private[:connect_params] || %{}
    url = Map.get(connect_params, "url", "")
    referrer = Map.get(connect_params, "referrer", "")

    # Parse URL for UTM parameters
    uri = URI.parse(url)
    query_params = URI.decode_query(uri.query || "")

    # Extract UTM parameters
    utm_source = Map.get(query_params, "utm_source")
    utm_medium = Map.get(query_params, "utm_medium")
    utm_campaign = Map.get(query_params, "utm_campaign")
    utm_term = Map.get(query_params, "utm_term")
    utm_content = Map.get(query_params, "utm_content")

    # Get user agent if available
    user_agent = Map.get(connect_params, "userAgent", "")
    {device_type, browser, os} = parse_user_agent(user_agent)

    # Parse for extended UTM parameters
    utm_source_platform = Map.get(query_params, "utm_source_platform")
    utm_source_campaign = Map.get(query_params, "utm_source_campaign")
    utm_source_content = Map.get(query_params, "utm_source_content")

    # Build tracking data map
    %{
      user_id: user_id,
      timestamp: DateTime.utc_now() |> DateTime.to_string(),
      page_path: uri.path || "/",
      referrer: referrer,
      utm_source: utm_source,
      utm_medium: utm_medium,
      utm_campaign: utm_campaign,
      utm_term: utm_term,
      utm_content: utm_content,
      utm_source_platform: utm_source_platform,
      utm_source_campaign: utm_source_campaign,
      utm_source_content: utm_source_content,
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
  defp parse_user_agent(""), do: {"unknown", "unknown", "unknown"}

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

  # Store email in database and send to Kit.com
  defp save_email_to_file(email) do
    # Store in database
    signup_attrs = %{
      email: email,
      # We don't collect name in this form
      name: nil,
      # We don't collect company in this form
      company: nil,
      referral_source: "early_access_live",
      # Could extract from tracking_data if needed
      utm_source: nil,
      utm_medium: nil,
      utm_campaign: nil
    }

    case EarlyAccess.create_signup(signup_attrs) do
      {:ok, signup} ->
        Logger.info("Successfully saved email to database: #{email}, id: #{signup.id}")

      {:error, changeset} ->
        Logger.error(
          "Failed to save email to database: #{email}, errors: #{inspect(changeset.errors)}"
        )
    end

    # Send to Kit.com API
    case send_to_kit(email) do
      {:ok, response} ->
        Logger.info(
          "Successfully sent email to Kit.com: #{email}, response: #{inspect(response)}"
        )

        # Send welcome email via Postmark
        Logger.info("[EARLY ACCESS LIVE] About to send welcome email via Postmark",
          email: email,
          timestamp: DateTime.utc_now() |> DateTime.to_string()
        )

        case Rsolv.EmailService.send_early_access_welcome_email(email) do
          {:ok, result} ->
            Logger.info("[EARLY ACCESS LIVE] Successfully sent welcome email via Postmark",
              email: email,
              result: inspect(result),
              timestamp: DateTime.utc_now() |> DateTime.to_string()
            )

          {:error, error} ->
            Logger.error("[EARLY ACCESS LIVE] Failed to send welcome email via Postmark",
              email: email,
              error: inspect(error),
              timestamp: DateTime.utc_now() |> DateTime.to_string()
            )

          {:skipped, reason} ->
            Logger.info("[EARLY ACCESS LIVE] Skipped sending welcome email",
              email: email,
              reason: inspect(reason),
              timestamp: DateTime.utc_now() |> DateTime.to_string()
            )
        end

        # Send admin notification email
        Logger.info("[EARLY ACCESS LIVE] About to send admin notification email",
          email: email,
          timestamp: DateTime.utc_now() |> DateTime.to_string()
        )

        # Build signup data for admin notification
        signup_data = %{
          email: email,
          # LiveView form doesn't collect company
          company: nil,
          timestamp: DateTime.utc_now() |> DateTime.to_iso8601(),
          source: "early_access_live",
          utm_source: nil,
          utm_medium: nil,
          utm_campaign: nil,
          referrer: nil
        }

        case Rsolv.EmailService.send_admin_signup_notification(signup_data) do
          {:ok, result} ->
            Logger.info("[EARLY ACCESS LIVE] Successfully sent admin notification email",
              email: email,
              result: inspect(result),
              timestamp: DateTime.utc_now() |> DateTime.to_string()
            )

          {:error, error} ->
            Logger.error("[EARLY ACCESS LIVE] Failed to send admin notification email",
              email: email,
              error: inspect(error),
              timestamp: DateTime.utc_now() |> DateTime.to_string()
            )
        end

        :ok

      {:error, reason} ->
        Logger.error("Failed to send email to Kit.com: #{email}, reason: #{inspect(reason)}")
        # Still return :ok since we saved locally
        :ok
    end
  end

  # Send email to Kit.com API (v4)
  defp send_to_kit(email) do
    kit_api_key = System.get_env("KIT_API_KEY")

    if is_nil(kit_api_key) do
      Logger.warning("Kit.com API key not configured")
      # Return a mock success in development
      {:ok, %{status: "mocked_success", message: "Development mode"}}
    else
      # In production, make the actual API call to Kit.com v4 API
      url = "https://api.kit.com/v4/people"

      headers = [
        {"Authorization", "Bearer #{kit_api_key}"},
        {"Content-Type", "application/json"},
        {"Accept", "application/json"}
      ]

      body =
        JSON.encode!(%{
          email: email,
          source: "rsolv_landing_page",
          custom_fields: %{
            signup_date: DateTime.utc_now() |> DateTime.to_string(),
            product: "RSOLV",
            early_access: "yes"
          }
        })

      # Make the actual API call with error handling
      case HTTPoison.post(url, body, headers, recv_timeout: 10_000) do
        {:ok, %HTTPoison.Response{status_code: status_code} = response}
        when status_code in 200..299 ->
          # Successfully added to Kit.com
          {:ok, %{status_code: status_code, body: response.body}}

        {:ok, %HTTPoison.Response{status_code: status_code} = response} ->
          # API request succeeded but Kit.com returned an error
          Logger.error(
            "Kit.com API error: Status #{status_code}, Body: #{inspect(response.body)}"
          )

          {:error, %{status_code: status_code, body: response.body}}

        {:error, %HTTPoison.Error{reason: reason}} ->
          # HTTP request failed
          Logger.error("HTTP request to Kit.com failed: #{inspect(reason)}")
          {:error, %{reason: reason}}
      end
    end
  end
end
