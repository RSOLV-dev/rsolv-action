defmodule RsolvWeb.Admin.SessionController do
  use RsolvWeb, :controller
  
  alias Rsolv.Customers
  alias RsolvWeb.CustomerAuth

  def new(conn, _params) do
    render(conn, :new, error_message: nil)
  end
  
  def create(conn, %{"session" => %{"email" => email, "password" => password}}) do
    case Customers.authenticate_customer_by_email_and_password(email, password) do
      {:ok, customer} ->
        if customer.is_staff do
          CustomerAuth.log_in_customer(conn, customer, %{"remember_me" => "true"})
        else
          render(conn, :new, error_message: "You are not authorized to access the admin area.")
        end
      
      {:error, :invalid_credentials} ->
        render(conn, :new, error_message: "Invalid email or password")
      
      {:error, :too_many_attempts} ->
        render(conn, :new, error_message: "Too many login attempts. Please try again later.")
    end
  end
end