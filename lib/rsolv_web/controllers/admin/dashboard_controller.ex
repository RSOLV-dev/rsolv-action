defmodule RsolvWeb.Admin.DashboardController do
  use RsolvWeb, :controller
  
  alias RsolvWeb.CustomerAuth
  
  def index(conn, _params) do
    render(conn, :index, customer: conn.assigns.current_customer)
  end
  
  def logout(conn, _params) do
    CustomerAuth.log_out_customer(conn)
  end
end