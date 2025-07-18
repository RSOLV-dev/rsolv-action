defmodule RsolvWeb.DashboardController do
  use RsolvWeb, :controller
  
  @doc """
  Redirect to the LiveView dashboard for analytics
  """
  def index(conn, _params) do
    # Check if user is authenticated via DashboardAuth plug
    # The DashboardAuth plug sets :current_user_email when auth succeeds
    if conn.assigns[:current_user_email] do
      # User is authenticated, redirect to LiveView dashboard
      redirect(conn, to: ~p"/dashboard/analytics")
    else
      # This shouldn't happen as DashboardAuth should have already blocked access
      # But just in case, redirect to home with error
      conn
      |> put_flash(:error, "Access denied. Please log in as an administrator.")
      |> redirect(to: ~p"/")
    end
  end
end