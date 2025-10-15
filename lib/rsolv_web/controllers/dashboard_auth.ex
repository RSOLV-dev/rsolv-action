defmodule RsolvWeb.DashboardAuth do
  @moduledoc """
  Authentication plug for the analytics dashboard.
  Provides basic authentication mechanisms for dashboard access.
  """
  import Plug.Conn

  @doc """
  Initialize the plug with options.
  """
  def init(opts), do: opts

  @doc """
  Call function that implements authentication logic.
  """
  def call(conn, _opts) do
    # Check environment
    env = Application.get_env(:rsolv, :env, :prod)

    case env do
      :dev ->
        # In dev, accept the admin key as a query parameter
        admin_key = Application.get_env(:rsolv, :admin_key, "rsolv_admin_access")

        if Map.get(conn.query_params, "key") == admin_key do
          conn
        else
          deny_access(conn)
        end

      :test ->
        # In test, always allow access
        conn

      :prod ->
        # In production, check for authentication cookie
        auth_cookie = conn.cookies["rsolv_dashboard_auth"]

        if auth_cookie && verify_auth_token(auth_cookie) do
          conn
        else
          # Check for basic auth header as fallback
          authenticate_with_basic_auth(conn)
        end
    end
  end

  # Deny access and redirect to home
  defp deny_access(conn) do
    conn
    |> Phoenix.Controller.put_flash(:error, "Access denied. Please log in as an administrator.")
    |> Phoenix.Controller.redirect(to: "/")
    |> halt()
  end

  # Verify the authentication token from cookie
  defp verify_auth_token(token) do
    # In a real implementation, this would validate a signed token
    # For now, we'll check if it matches a static token pattern
    admin_secret = Application.get_env(:rsolv, :admin_secret, "")
    admin_token = create_admin_token(admin_secret)

    # Secure comparison to prevent timing attacks
    secure_compare(token, admin_token)
  end

  # Create a token from secret (in real app, use proper signing)
  defp create_admin_token(secret) do
    # Simple hash-based token for demo purposes
    :crypto.hash(:sha256, secret <> "RSOLV_ANALYTICS_SALT")
    |> Base.encode16(case: :lower)
  end

  # Authenticate with basic auth header
  defp authenticate_with_basic_auth(conn) do
    case get_req_header(conn, "authorization") do
      ["Basic " <> encoded] ->
        case Base.decode64(encoded) do
          {:ok, credentials} ->
            check_credentials(conn, credentials)

          :error ->
            request_basic_auth(conn)
        end

      _ ->
        request_basic_auth(conn)
    end
  end

  # Check basic auth credentials
  defp check_credentials(conn, credentials) do
    # Expected format: "username:password"
    case String.split(credentials, ":", parts: 2) do
      [username, password] ->
        if verify_credentials(username, password) do
          # Add auth cookie for future requests
          conn
          |> put_resp_cookie(
            "rsolv_dashboard_auth",
            create_admin_token(Application.get_env(:rsolv, :admin_secret, "")),
            # 1 day
            max_age: 86_400,
            http_only: true,
            secure: true
          )
        else
          request_basic_auth(conn)
        end

      _ ->
        request_basic_auth(conn)
    end
  end

  # Verify credentials against config
  defp verify_credentials(username, password) do
    admin_username = Application.get_env(:rsolv, :admin_username, "admin")
    admin_password = Application.get_env(:rsolv, :admin_password, "")

    # Secure comparison to prevent timing attacks
    secure_compare(username, admin_username) && secure_compare(password, admin_password)
  end

  # Request basic auth by sending the appropriate header
  defp request_basic_auth(conn) do
    conn
    |> put_resp_header("www-authenticate", ~s(Basic realm="RSOLV Analytics Dashboard"))
    |> send_resp(401, "Unauthorized")
    |> halt()
  end

  # Constant-time comparison to prevent timing attacks
  defp secure_compare(a, b) when byte_size(a) == byte_size(b) do
    :crypto.hash_equals(a, b)
  end

  defp secure_compare(_a, _b), do: false
end
