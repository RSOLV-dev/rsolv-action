defmodule RsolvWeb.Plugs.ApiAuthentication do
  @moduledoc """
  Centralized API authentication plug for consistent authentication across all API endpoints.

  This plug provides a uniform authentication mechanism that:
  1. Checks x-api-key header first (preferred)
  2. Falls back to Authorization: Bearer token for backward compatibility
  3. Validates the API key against the database
  4. Assigns the authenticated customer to the connection

  ## Usage

  In controllers, use this plug to ensure authentication:

      plug RsolvWeb.Plugs.ApiAuthentication when action in [:index, :create]

  Or with optional authentication:

      plug RsolvWeb.Plugs.ApiAuthentication, optional: true

  The authenticated customer will be available in `conn.assigns.customer`
  """

  import Plug.Conn
  alias Rsolv.Accounts
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
        Logger.info("[ApiAuthentication] ✅ Authenticated customer: #{customer.name} (ID: #{customer.id})")
        # Also get the full API key record for phase storage access control
        api_key_record = Rsolv.Customers.get_api_key_by_key(api_key)
        conn
        |> assign(:customer, customer)
        |> assign(:api_key, api_key_record)
    end
  end

  # Handle missing API key
  defp handle_no_key(conn, true = _optional?) do
    # Optional authentication - just continue without customer
    conn
  end

  defp handle_no_key(conn, false = _optional?) do
    conn
    |> put_status(401)
    |> Phoenix.Controller.put_view(json: RsolvWeb.ErrorJSON)
    |> Phoenix.Controller.render("401.json", %{
      error: "Authentication required",
      message: "API key must be provided in x-api-key header"
    })
    |> halt()
  end

  # Handle invalid API key
  defp handle_invalid_key(conn, true = _optional?) do
    # For optional authentication with invalid key, we still reject
    # This prevents using invalid keys accidentally
    conn
    |> put_status(401)
    |> Phoenix.Controller.put_view(json: RsolvWeb.ErrorJSON)
    |> Phoenix.Controller.render("401.json", %{
      error: "Invalid API key",
      message: "The provided API key is invalid or expired"
    })
    |> halt()
  end

  defp handle_invalid_key(conn, false = _optional?) do
    conn
    |> put_status(401)
    |> Phoenix.Controller.put_view(json: RsolvWeb.ErrorJSON)
    |> Phoenix.Controller.render("401.json", %{
      error: "Invalid API key",
      message: "The provided API key is invalid or expired"
    })
    |> halt()
  end
end