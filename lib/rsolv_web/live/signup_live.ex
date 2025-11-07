defmodule RsolvWeb.SignupLive do
  @moduledoc """
  Signup form for new RSOLV customers (RFC-078).

  Creates customer account, generates API key, and displays one-time key.
  Feature flag protected by :public_site flag.
  """

  use RsolvWeb, :live_view
  require Logger

  alias Rsolv.{CustomerOnboarding, Customers, FunnelTracking, RateLimiter}
  alias RsolvWeb.Services.Analytics
  alias RsolvWeb.Validators.EmailValidator

  @impl true
  def render(assigns) do
    ~H"""
    <div class="min-h-screen bg-gradient-to-br from-gray-900 via-blue-900 to-gray-900 flex items-center justify-center px-4 sm:px-6 lg:px-8">
      <div class="max-w-md w-full">
        <%= if @signup_complete do %>
          <!-- Success Screen: Show API Key -->
          <div class="bg-white dark:bg-gray-800 rounded-2xl shadow-2xl p-8 space-y-6">
            <div class="text-center">
              <div class="mx-auto flex items-center justify-center h-12 w-12 rounded-full bg-green-100 dark:bg-green-900">
                <svg
                  class="h-6 w-6 text-green-600 dark:text-green-400"
                  fill="none"
                  stroke="currentColor"
                  viewBox="0 0 24 24"
                >
                  <path
                    stroke-linecap="round"
                    stroke-linejoin="round"
                    stroke-width="2"
                    d="M5 13l4 4L19 7"
                  />
                </svg>
              </div>
              <h2 class="mt-4 text-3xl font-bold text-gray-900 dark:text-white">
                Welcome to RSOLV!
              </h2>
              <p class="mt-2 text-sm text-gray-600 dark:text-gray-300">
                Your account has been created successfully.
              </p>
            </div>

            <div class="bg-amber-50 dark:bg-amber-900/20 border-2 border-amber-400 dark:border-amber-600 rounded-lg p-4">
              <div class="flex items-start">
                <svg
                  class="h-5 w-5 text-amber-600 dark:text-amber-400 mr-2 flex-shrink-0 mt-0.5"
                  fill="currentColor"
                  viewBox="0 0 20 20"
                >
                  <path
                    fill-rule="evenodd"
                    d="M8.257 3.099c.765-1.36 2.722-1.36 3.486 0l5.58 9.92c.75 1.334-.213 2.98-1.742 2.98H4.42c-1.53 0-2.493-1.646-1.743-2.98l5.58-9.92zM11 13a1 1 0 11-2 0 1 1 0 012 0zm-1-8a1 1 0 00-1 1v3a1 1 0 002 0V6a1 1 0 00-1-1z"
                    clip-rule="evenodd"
                  />
                </svg>
                <div class="flex-1">
                  <p class="text-sm font-medium text-amber-800 dark:text-amber-200">
                    Save your API key now - it won't be shown again!
                  </p>
                </div>
              </div>
            </div>

            <div class="space-y-3">
              <div>
                <label class="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                  Your API Key
                </label>
                <div class="relative">
                  <input
                    type="text"
                    id="api-key-display"
                    readonly
                    value={@api_key}
                    class="w-full px-4 py-3 pr-12 font-mono text-sm border border-gray-300 dark:border-gray-600 rounded-lg bg-gray-50 dark:bg-gray-900 text-gray-900 dark:text-gray-100 focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                  />
                  <button
                    type="button"
                    id="copy-api-key-button"
                    phx-hook="CopyButton"
                    data-copy-target="api-key-display"
                    class="absolute inset-y-0 right-0 px-4 text-gray-600 dark:text-gray-400 hover:text-gray-900 dark:hover:text-gray-100 focus:outline-none"
                    title="Copy to clipboard"
                  >
                    <%= if @copied do %>
                      <svg
                        class="h-5 w-5 text-green-600"
                        fill="none"
                        stroke="currentColor"
                        viewBox="0 0 24 24"
                      >
                        <path
                          stroke-linecap="round"
                          stroke-linejoin="round"
                          stroke-width="2"
                          d="M5 13l4 4L19 7"
                        />
                      </svg>
                    <% else %>
                      <svg class="h-5 w-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path
                          stroke-linecap="round"
                          stroke-linejoin="round"
                          stroke-width="2"
                          d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z"
                        />
                      </svg>
                    <% end %>
                  </button>
                </div>
                <%= if @copied do %>
                  <p class="mt-1 text-sm text-green-600 dark:text-green-400">
                    ✓ Copied to clipboard!
                  </p>
                <% end %>
              </div>

              <div class="bg-blue-50 dark:bg-blue-900/20 rounded-lg p-4">
                <h3 class="text-sm font-medium text-blue-900 dark:text-blue-200 mb-2">
                  Next Steps:
                </h3>
                <ul class="text-sm text-blue-700 dark:text-blue-300 space-y-2 list-decimal list-inside">
                  <li>
                    <a
                      href="https://github.com/RSOLV-dev/RSOLV-action"
                      target="_blank"
                      rel="noopener noreferrer"
                      class="underline hover:text-blue-800 dark:hover:text-blue-200 font-medium"
                    >
                      Install the RSOLV GitHub Action
                    </a>
                    {" "}in your repository
                  </li>
                  <li>
                    Add your API key to <span class="font-mono text-xs bg-gray-100 dark:bg-gray-800 px-1 rounded">RSOLV_API_KEY</span>
                    {" "}in GitHub Secrets
                  </li>
                  <li>You have 5 free trial credits to get started</li>
                  <li>
                    Visit our{" "}
                    <a
                      href="https://docs.rsolv.dev"
                      target="_blank"
                      rel="noopener noreferrer"
                      class="underline hover:text-blue-800 dark:hover:text-blue-200"
                    >
                      documentation
                    </a>
                    {" "}to learn more
                  </li>
                  <li>
                    Check your email (<span class="font-medium">{@customer_email}</span>) for setup instructions
                  </li>
                </ul>
              </div>
            </div>

            <div class="pt-4">
              <a
                href="https://docs.rsolv.dev"
                class="block w-full text-center px-6 py-3 bg-blue-600 hover:bg-blue-700 text-white font-medium rounded-lg transition-colors duration-200 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:ring-offset-2"
              >
                View Documentation
              </a>
            </div>
          </div>
        <% else %>
          <!-- Signup Form -->
          <div class="bg-white dark:bg-gray-800 rounded-2xl shadow-2xl p-8">
            <div class="text-center mb-8">
              <h2 class="text-3xl font-bold text-gray-900 dark:text-white">
                Create Your Account
              </h2>
              <p class="mt-2 text-sm text-gray-600 dark:text-gray-400">
                Get started with 5 free trial credits
              </p>
            </div>

            <.form for={%{}} phx-submit="submit" class="space-y-6">
              <div>
                <label
                  for="email"
                  class="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2"
                >
                  Email Address
                </label>
                <div class="relative">
                  <input
                    type="email"
                    id="email"
                    name="email"
                    value={@email}
                    placeholder="you@company.com"
                    required
                    autofocus
                    class={"w-full px-4 py-3 border rounded-lg focus:ring-2 focus:outline-none transition-colors #{
                      cond do
                        @error_message -> "border-red-500 focus:ring-red-500 focus:border-red-500"
                        @email_valid == true -> "border-green-500 focus:ring-green-500 focus:border-green-500"
                        true -> "border-gray-300 dark:border-gray-600 focus:ring-blue-500 focus:border-blue-500"
                      end
                    } bg-white dark:bg-gray-900 text-gray-900 dark:text-gray-100"}
                    phx-blur="validate"
                    phx-hook="EmailInput"
                  />
                  <%= if @email_valid == true do %>
                    <div class="absolute inset-y-0 right-0 flex items-center pr-3 pointer-events-none">
                      <svg
                        class="h-5 w-5 text-green-500"
                        fill="currentColor"
                        viewBox="0 0 20 20"
                      >
                        <path
                          fill-rule="evenodd"
                          d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z"
                          clip-rule="evenodd"
                        />
                      </svg>
                    </div>
                  <% end %>
                </div>
                <%= if @error_message do %>
                  <p class="mt-2 text-sm text-red-600 dark:text-red-400">
                    {@error_message}
                  </p>
                  <%= if @suggested_correction && @suggested_correction != @email do %>
                    <p class="mt-1 text-sm text-yellow-600 dark:text-yellow-400">
                      Did you mean <a
                        href="#"
                        phx-click="use_suggestion"
                        class="underline hover:text-yellow-700 dark:hover:text-yellow-300 font-medium"
                      ><%= @suggested_correction %></a>?
                    </p>
                  <% end %>
                <% end %>
              </div>

              <div>
                <button
                  type="submit"
                  disabled={@submitting}
                  class="w-full px-6 py-3 bg-blue-600 hover:bg-blue-700 disabled:bg-gray-400 disabled:cursor-not-allowed text-white font-medium rounded-lg transition-colors duration-200 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:ring-offset-2"
                >
                  <%= if @submitting do %>
                    <span class="flex items-center justify-center">
                      <svg
                        class="animate-spin -ml-1 mr-3 h-5 w-5 text-white"
                        fill="none"
                        viewBox="0 0 24 24"
                      >
                        <circle
                          class="opacity-25"
                          cx="12"
                          cy="12"
                          r="10"
                          stroke="currentColor"
                          stroke-width="4"
                        />
                        <path
                          class="opacity-75"
                          fill="currentColor"
                          d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"
                        />
                      </svg>
                      Creating Account...
                    </span>
                  <% else %>
                    Create Account
                  <% end %>
                </button>
              </div>

              <div class="text-center">
                <p class="text-sm text-gray-600 dark:text-gray-400">
                  Already have an account?
                  <a
                    href="/signin"
                    class="text-blue-600 hover:text-blue-700 dark:text-blue-400 dark:hover:text-blue-300 font-medium"
                  >
                    Sign in
                  </a>
                </p>
              </div>

              <p class="text-xs text-gray-500 dark:text-gray-400 text-center">
                By creating an account, you agree to our
                <a href="/terms" class="underline hover:text-gray-700 dark:hover:text-gray-300">
                  Terms of Service
                </a>
                and <a href="/privacy" class="underline hover:text-gray-700 dark:hover:text-gray-300">
                  Privacy Policy
                </a>.
              </p>
            </.form>
          </div>
        <% end %>
      </div>
    </div>
    """
  end

  @impl true
  def mount(_params, session, socket) do
    # Track page view
    tracking_data = extract_tracking_data(socket, session)
    Analytics.track_section_view("signup-form", nil, tracking_data)

    # Get IP address for rate limiting (must be done during mount)
    ip_address = get_connect_info(socket, :peer_data) |> get_ip_address()

    {:ok,
     assign(socket,
       email: "",
       email_valid: nil,
       error_message: nil,
       suggested_correction: nil,
       submitting: false,
       signup_complete: false,
       api_key: nil,
       customer_email: nil,
       copied: false,
       tracking_data: tracking_data,
       current_path: "/signup",
       ip_address: ip_address
     )}
  end

  @impl true
  def handle_params(_params, uri, socket) do
    parsed_uri = URI.parse(uri)
    {:noreply, assign(socket, :current_path, parsed_uri.path)}
  end

  @impl true
  def handle_event("submit", %{"email" => email}, socket) do
    # Track submission attempt
    Analytics.track_form_submission("signup", "attempt", socket.assigns.tracking_data)

    # Get IP address from socket assigns (stored during mount)
    ip_address = socket.assigns.ip_address

    # Check rate limit (10 signups per hour per IP)
    # Note: Using customer_onboarding action which is configured for 10/minute
    # For hourly limits, we track by IP address instead of customer_id
    case RateLimiter.check_rate_limit(ip_address, :customer_onboarding) do
      {:error, :rate_limited, metadata} ->
        Logger.warning("Signup rate limit exceeded for IP: #{ip_address}")

        error_data =
          Map.merge(socket.assigns.tracking_data, %{
            error_type: "rate_limit",
            error_details: "Too many signup attempts",
            ip_address: ip_address
          })

        Analytics.track_form_submission("signup", "error", error_data)

        {:noreply,
         assign(socket,
           error_message: "Too many signup attempts. Please try again in #{div(metadata.reset - System.system_time(:second), 60)} minutes.",
           submitting: false
         )}

      {:ok, _metadata} ->
        # Validate email
        case EmailValidator.validate_with_feedback(email) do
          {:ok, _} ->
            # Set submitting state
            socket = assign(socket, submitting: true)

            # Provision customer via CustomerOnboarding
            Logger.info("Signup attempt for email: #{email}")

            # Extract name from email (before @) as a default
            # User can update this later in their profile
            default_name = email |> String.split("@") |> List.first() |> String.capitalize()

            case CustomerOnboarding.provision_customer(%{email: email, name: default_name}) do
              {:ok, %{customer: customer, api_key: raw_api_key}} ->
                Logger.info("Successfully created customer #{customer.id} with email: #{email}")

                # Track successful conversion
                email_domain = email |> String.split("@") |> List.last()

                conversion_data =
                  Map.merge(socket.assigns.tracking_data, %{
                    email_domain: email_domain,
                    conversion_type: "signup",
                    customer_id: customer.id,
                    ip_address: ip_address
                  })

                Analytics.track_form_submission("signup", "success", conversion_data)
                Analytics.track_conversion("signup", conversion_data)

                # Track funnel events (RFC-078 Part 2)
                track_funnel_signup(customer, socket.assigns.tracking_data)

                # Show success screen with API key
                {:noreply,
                 assign(socket,
                   signup_complete: true,
                   api_key: raw_api_key,
                   customer_email: customer.email,
                   customer_id: customer.id,
                   submitting: false
                 )}

              {:error, {:validation_failed, reason}} when is_binary(reason) ->
                Logger.warning("Signup validation failed: #{reason}")

                error_data =
                  Map.merge(socket.assigns.tracking_data, %{
                    error_type: "validation",
                    error_details: reason
                  })

                Analytics.track_form_submission("signup", "error", error_data)

                {:noreply,
                 assign(socket,
                   error_message: reason,
                   submitting: false
                 )}

              {:error, {:validation_failed, %Ecto.Changeset{} = changeset}} ->
                error_message = format_changeset_errors(changeset)
                Logger.warning("Signup validation failed: #{error_message}")

                error_data =
                  Map.merge(socket.assigns.tracking_data, %{
                    error_type: "validation",
                    error_details: error_message
                  })

                Analytics.track_form_submission("signup", "error", error_data)

                {:noreply,
                 assign(socket,
                   error_message: error_message,
                   submitting: false
                 )}

              {:error, reason} ->
                Logger.error("Signup failed: #{inspect(reason)}")

                error_data =
                  Map.merge(socket.assigns.tracking_data, %{
                    error_type: "system",
                    error_details: inspect(reason)
                  })

                Analytics.track_form_submission("signup", "error", error_data)

                {:noreply,
                 assign(socket,
                   error_message: "An error occurred. Please try again or contact support.",
                   submitting: false
                 )}
            end

          {:error, error_message} ->
            Logger.warning("Invalid email submitted: #{inspect(email)}")

            suggested_correction = EmailValidator.suggest_correction(email)

            error_data =
              Map.merge(socket.assigns.tracking_data, %{
                error_type: "validation",
                error_details: error_message || "Invalid email format"
              })

            Analytics.track_form_submission("signup", "error", error_data)

            {:noreply,
             assign(socket,
               email: email,
               email_valid: false,
               error_message: error_message || "Please provide a valid email address.",
               suggested_correction: suggested_correction,
               submitting: false
             )}
        end
    end
  end

  @impl true
  def handle_event("validate", %{"email" => email}, socket) do
    # Don't re-render if email hasn't changed
    if email == socket.assigns.email do
      {:noreply, socket}
    else
      # Validate email
      case EmailValidator.validate_with_feedback(email) do
        {:ok, _} ->
          {:noreply,
           assign(socket,
             email: email,
             email_valid: true,
             error_message: nil,
             suggested_correction: nil
           )}

        {:error, error_message} ->
          # Don't show error if field is empty
          if email == "" do
            {:noreply,
             assign(socket,
               email: email,
               email_valid: nil,
               error_message: nil,
               suggested_correction: nil
             )}
          else
            suggested_correction = EmailValidator.suggest_correction(email)

            {:noreply,
             assign(socket,
               email: email,
               email_valid: false,
               error_message: error_message,
               suggested_correction: suggested_correction
             )}
          end
      end
    end
  end

  @impl true
  def handle_event("use_suggestion", _params, socket) do
    if socket.assigns.suggested_correction do
      Analytics.track("suggestion_used", %{
        original_email: socket.assigns.email,
        suggested_email: socket.assigns.suggested_correction
      })

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

  @impl true
  def handle_event("copy_api_key", _params, socket) do
    # Track copy event (analytics)
    Analytics.track("api_key_copied", %{customer_email: socket.assigns.customer_email})

    # Track API key copied in funnel (RFC-078 Part 2)
    if socket.assigns[:customer_id] do
      customer = Rsolv.Customers.get_customer!(socket.assigns.customer_id)
      track_funnel_api_key_copied(customer, socket.assigns.tracking_data)
    end

    # Set copied state (will reset after 2 seconds)
    Process.send_after(self(), :reset_copied, 2000)

    {:noreply, assign(socket, copied: true)}
  end

  @impl true
  def handle_info(:reset_copied, socket) do
    {:noreply, assign(socket, copied: false)}
  end

  # Catch-all for messages we don't need to handle (e.g., Bamboo's :delivered_email)
  @impl true
  def handle_info(_msg, socket) do
    {:noreply, socket}
  end

  # Format Ecto changeset errors into user-friendly message
  defp format_changeset_errors(%Ecto.Changeset{errors: errors}) do
    errors
    |> Enum.map(fn {field, {message, _}} ->
      "#{humanize_field(field)} #{message}"
    end)
    |> Enum.join(", ")
  end

  defp humanize_field(:email), do: "Email"
  defp humanize_field(field), do: field |> to_string() |> String.capitalize()

  # Extract tracking data from LiveView socket and session
  defp extract_tracking_data(socket, session) do
    user_id = Map.get(session, "tracking_id") || generate_tracking_id()
    connect_params = socket.private[:connect_params] || %{}
    url = Map.get(connect_params, "url", "")
    referrer = Map.get(connect_params, "referrer", "")

    uri = URI.parse(url)
    query_params = URI.decode_query(uri.query || "")

    %{
      user_id: user_id,
      timestamp: DateTime.utc_now() |> DateTime.to_string(),
      page_path: uri.path || "/signup",
      referrer: referrer,
      utm_source: Map.get(query_params, "utm_source"),
      utm_medium: Map.get(query_params, "utm_medium"),
      utm_campaign: Map.get(query_params, "utm_campaign")
    }
  end

  defp generate_tracking_id do
    :crypto.strong_rand_bytes(16)
    |> Base.encode16(case: :lower)
  end

  # Get IP address from peer_data for rate limiting
  defp get_ip_address(%{address: {a, b, c, d}}), do: "#{a}.#{b}.#{c}.#{d}"
  defp get_ip_address(%{address: ip}) when is_tuple(ip), do: :inet.ntoa(ip) |> to_string()
  defp get_ip_address(_), do: "unknown"

  # RFC-078 Part 2: Track funnel events for signup completion
  defp track_funnel_signup(customer, tracking_data) do
    attrs =
      tracking_data
      |> Map.take([:visitor_id, :session_id, :utm_source, :utm_medium, :utm_campaign])
      |> Map.put(:inserted_at, DateTime.utc_now())

    case FunnelTracking.track_signup(customer, attrs) do
      {:ok, _event} ->
        Logger.info("Tracked signup funnel event for customer #{customer.id}")

      {:error, reason} ->
        Logger.error("Failed to track signup funnel event: #{inspect(reason)}")
    end
  end

  # RFC-078 Part 2: Track API key copy event in funnel
  # This indicates the customer successfully saved their API key
  defp track_funnel_api_key_copied(customer, tracking_data) do
    # For now, we use the existing API key creation tracking
    # The customer gets an API key on signup, so we track that they copied it
    attrs =
      tracking_data
      |> Map.take([:visitor_id, :session_id])
      |> Map.put(:inserted_at, DateTime.utc_now())

    case FunnelTracking.track_api_key_creation(customer, attrs) do
      {:ok, _event} ->
        Logger.info("Tracked API key copied event for customer #{customer.id}")

      {:error, reason} ->
        Logger.error("Failed to track API key copied event: #{inspect(reason)}")
    end
  end
end
