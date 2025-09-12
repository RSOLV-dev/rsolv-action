defmodule RsolvWeb.Admin.AuthController do
  use RsolvWeb, :controller
  require Logger
  
  alias Rsolv.Customers
  alias RsolvWeb.CustomerAuth
  
  def authenticate(conn, %{"token" => token}) do
    Logger.info("[Admin AuthController] Processing authentication token")
    
    # Validate the token and get the customer
    case Customers.get_customer_by_session_token(token) do
      nil ->
        Logger.warning("[Admin AuthController] Invalid or expired token")
        conn
        |> put_flash(:error, "Invalid or expired authentication token")
        |> redirect(to: ~p"/admin/login")
      
      customer ->
        if customer.is_staff do
          Logger.info("[Admin AuthController] Valid staff token for customer #{customer.id}")
          
          conn
          |> CustomerAuth.log_in_customer(customer, %{"remember_me" => "true"})
        else
          Logger.warning("[Admin AuthController] Non-staff customer attempted admin access: #{customer.id}")
          conn
          |> put_flash(:error, "You are not authorized to access the admin area.")
          |> redirect(to: ~p"/admin/login")
        end
    end
  end
end