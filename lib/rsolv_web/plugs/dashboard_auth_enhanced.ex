defmodule RsolvWeb.Plugs.DashboardAuthEnhanced do
  @moduledoc """
  Enhanced dashboard authentication that checks auth BEFORE feature flags.

  This solves the chicken-and-egg problem where feature flags were checked
  before authentication, preventing admins from accessing the admin UI
  even with valid credentials.
  """

  import Plug.Conn
  import Phoenix.Controller
  alias Rsolv.FeatureFlags

  def init(opts), do: opts

  def call(conn, opts) do
    feature = Keyword.get(opts, :require_feature)

    # First, check authentication
    case authenticate(conn) do
      {:ok, user_email} ->
        # Authentication successful, now check feature flag if required
        if feature && !FeatureFlags.enabled?(feature, email: user_email) do
          conn
          |> put_flash(:error, "This feature is not available for your account.")
          |> redirect(to: "/")
          |> halt()
        else
          # Both auth and feature flag check passed
          conn
          |> assign(:current_user_email, user_email)
        end

      {:error, _reason} ->
        # Authentication failed
        conn
        |> put_resp_header("www-authenticate", ~s(Basic realm="Admin Dashboard"))
        |> send_resp(401, "Unauthorized")
        |> halt()
    end
  end

  defp authenticate(conn) do
    username = Application.get_env(:rsolv, :admin_username, "admin")
    password = Application.get_env(:rsolv, :admin_password)
    admin_emails = Application.get_env(:rsolv, :admin_emails, ["admin@rsolv.dev"])

    with ["Basic " <> encoded] <- get_req_header(conn, "authorization"),
         {:ok, decoded} <- Base.decode64(encoded),
         [provided_username, provided_password] <- String.split(decoded, ":", parts: 2),
         true <- provided_username == username,
         true <- provided_password == password do
      # Return the first admin email as the authenticated user
      {:ok, List.first(admin_emails, "admin@rsolv.dev")}
    else
      _ -> {:error, :invalid_credentials}
    end
  end
end
