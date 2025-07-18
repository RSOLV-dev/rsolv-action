defmodule RsolvWeb.Plugs.DashboardAuth do
  @moduledoc """
  Dashboard authentication plug that verifies HTTP Basic Auth credentials.
  
  This plug only handles authentication. Feature flag checking is done
  separately by FeatureFlagPlug in the router pipeline, ensuring proper
  separation of concerns.
  """
  
  import Plug.Conn
  import Phoenix.Controller
  
  def init(opts), do: opts
  
  def call(conn, _opts) do
    # Only check authentication - feature flags are handled by FeatureFlagPlug in the pipeline
    case authenticate(conn) do
      {:ok, user_email} ->
        # Authentication successful
        conn
        |> assign(:current_user_email, user_email)
        
      {:error, _reason} ->
        # Authentication failed
        conn
        |> put_resp_header("www-authenticate", ~s(Basic realm="Admin Dashboard"))
        |> put_resp_content_type("text/html")
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