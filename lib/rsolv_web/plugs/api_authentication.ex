defmodule RsolvWeb.Plugs.ApiAuthentication do
  @moduledoc """
  Centralized API authentication plug for consistent authentication across all API endpoints.

  This plug provides a uniform authentication mechanism that:
  1. Checks x-api-key header for authentication
  2. Validates the API key against the database
  3. Assigns the authenticated customer to the connection

  ## Usage

  In controllers, use this plug to ensure authentication:

      plug RsolvWeb.Plugs.ApiAuthentication when action in [:index, :create]

  Or with optional authentication:

      plug RsolvWeb.Plugs.ApiAuthentication, optional: true

  The authenticated customer will be available in `conn.assigns.customer`
  """

  import Plug.Conn
  alias Rsolv.Accounts
  alias Rsolv.FunnelTracking
  alias RsolvWeb.ApiErrorCodes
  require Logger

  @doc """
  Initialize the plug with options.

  Options:
  - :optional - if true, authentication is optional (no error on missing/invalid key)
  """
  def init(opts) do
    Keyword.get(opts, :optional, false)
  end

  @doc """
  Execute the authentication plug.

  Returns:
  - Connection with assigned customer on successful authentication
  - Connection with error response on failed authentication (unless optional)
  - Connection unchanged if optional and no valid authentication
  """
  def call(conn, optional?) do
    case extract_api_key(conn) do
      {:ok, api_key} ->
        authenticate_with_key(conn, api_key, optional?)

      :no_key ->
        handle_no_key(conn, optional?)
    end
  end

  # Extract API key from x-api-key header only
  defp extract_api_key(conn) do
    case get_req_header(conn, "x-api-key") do
      [api_key | _] when is_binary(api_key) and api_key != "" ->
        Logger.info("[ApiAuthentication] Found API key: #{String.slice(api_key, 0..15)}...")
        {:ok, api_key}

      _ ->
        Logger.info("[ApiAuthentication] No API key found in x-api-key header")
        :no_key
    end
  end

  # Authenticate with the provided API key
  defp authenticate_with_key(conn, api_key, optional?) do
    Logger.info("[ApiAuthentication] Validating API key: #{String.slice(api_key, 0..15)}...")

    case Accounts.get_customer_by_api_key(api_key) do
      nil ->
        Logger.warning("[ApiAuthentication] Invalid API key: #{String.slice(api_key, 0..15)}...")
        handle_invalid_key(conn, optional?)

      customer ->
        Logger.info(
          "[ApiAuthentication] ✅ Authenticated customer: #{customer.name} (ID: #{customer.id})"
        )

        # Check rate limit and get metadata
        # Use :api_request action for general API endpoints (500/hour as per test)
        rate_limit_result = Rsolv.RateLimiter.check_rate_limit(customer.id, :api_request)

        # Also get the full API key record for phase storage access control
        api_key_record = Rsolv.Customers.get_api_key_by_key(api_key)

        case rate_limit_result do
          {:ok, metadata} ->
            # Track API call in funnel (best-effort, non-blocking)
            Task.start(fn ->
              try do
                FunnelTracking.track_api_call(customer)
              rescue
                e ->
                  Logger.warning(
                    "[ApiAuthentication] Funnel tracking failed (non-critical): #{inspect(e)}"
                  )
              end
            end)

            conn
            |> assign(:customer, customer)
            |> assign(:api_key, api_key_record)
            |> assign(:raw_api_key, api_key)
            |> assign(:rate_limit_metadata, metadata)

          {:error, :rate_limited, metadata} ->
            # Store metadata even when rate limited so headers can be added
            conn
            |> assign(:rate_limit_metadata, metadata)
            |> handle_rate_limited(customer)
        end
    end
  end

  # Handle rate limit exceeded
  defp handle_rate_limited(conn, customer) do
    request_id = conn.assigns[:request_id] || Logger.metadata()[:request_id] || "unknown"

    Logger.warning(
      "[ApiAuthentication] Rate limit exceeded for customer #{customer.id} (#{customer.name})"
    )

    conn
    |> put_status(429)
    |> Phoenix.Controller.put_view(json: RsolvWeb.ErrorJSON)
    |> Phoenix.Controller.render("429.json", %{
      error_code: ApiErrorCodes.rate_limit_exceeded(),
      message: "Rate limit exceeded. Please retry after the reset time.",
      request_id: request_id
    })
    |> halt()
  end

  # Handle missing API key
  defp handle_no_key(conn, true = _optional?) do
    # Optional authentication - just continue without customer
    conn
  end

  defp handle_no_key(conn, false = _optional?) do
    request_id = conn.assigns[:request_id] || Logger.metadata()[:request_id] || "unknown"

    conn
    |> put_status(401)
    |> Phoenix.Controller.put_view(json: RsolvWeb.ErrorJSON)
    |> Phoenix.Controller.render("401.json", %{
      error_code: ApiErrorCodes.auth_required(),
      message: "API key must be provided in x-api-key header",
      request_id: request_id
    })
    |> halt()
  end

  # Handle invalid API key
  defp handle_invalid_key(conn, true = _optional?) do
    # For optional authentication with invalid key, we still reject
    # This prevents using invalid keys accidentally
    request_id = conn.assigns[:request_id] || Logger.metadata()[:request_id] || "unknown"

    conn
    |> put_status(401)
    |> Phoenix.Controller.put_view(json: RsolvWeb.ErrorJSON)
    |> Phoenix.Controller.render("401.json", %{
      error_code: ApiErrorCodes.invalid_api_key(),
      message: "Invalid or expired API key",
      request_id: request_id
    })
    |> halt()
  end

  defp handle_invalid_key(conn, false = _optional?) do
    request_id = conn.assigns[:request_id] || Logger.metadata()[:request_id] || "unknown"

    conn
    |> put_status(401)
    |> Phoenix.Controller.put_view(json: RsolvWeb.ErrorJSON)
    |> Phoenix.Controller.render("401.json", %{
      error_code: ApiErrorCodes.invalid_api_key(),
      message: "Invalid or expired API key",
      request_id: request_id
    })
    |> halt()
  end
end
