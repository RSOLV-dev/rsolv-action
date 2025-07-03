defmodule RsolvWeb.DashboardController do
  use RsolvWeb, :controller
  
  @doc """
  Redirect to the LiveView dashboard for analytics
  """
  def index(conn, _params) do
    # For now, we're implementing a very simple auth check
    # In production, this should be replaced with proper authentication
    case verify_admin_access(conn) do
      true ->
        # Redirect to LiveView dashboard
        redirect(conn, to: ~p"/dashboard/analytics")
      false ->
        conn
        |> put_flash(:error, "Access denied. Please log in as an administrator.")
        |> redirect(to: ~p"/")
    end
  end
  
  # Simple auth check based on a query parameter for now
  # This is only for development and should be replaced with proper auth
  defp verify_admin_access(conn) do
    # In development, allow access with a special key
    # In production, this should check for a proper authenticated session
    if Application.get_env(:rsolv, :env) == :dev do
      # Accept admin key for dev purposes only
      admin_key = Application.get_env(:rsolv, :admin_key, "rsolv_admin_access")
      Map.get(conn.query_params, "key") == admin_key
    else
      # In production, we would check for authenticated admin session
      false
    end
  end
end