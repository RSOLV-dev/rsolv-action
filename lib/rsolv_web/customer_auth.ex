defmodule RsolvWeb.CustomerAuth do
  @moduledoc """
  The authentication module for customer sessions.
  
  This module handles customer login, logout, and session management
  for both regular customers and staff members.
  """
  
  import Plug.Conn
  import Phoenix.Controller
  
  alias Rsolv.Customers
  
  # Token name stored in the session
  @session_token_key :customer_token
  
  # Plug callbacks
  def init(opts), do: opts
  
  def call(conn, opts) do
    apply(__MODULE__, opts, [conn, []])
  end
  
  @doc """
  Logs the customer in.
  
  It creates a new session token and stores it in the session.
  For staff members, it redirects to the admin dashboard.
  For regular customers, it redirects to the homepage.
  """
  def log_in_customer(conn, customer, _params \\ %{}) do
    token = Customers.generate_customer_session_token(customer)
    
    conn
    |> put_session(@session_token_key, token)
    |> put_session(:live_socket_id, "customers_sessions:#{Base.url_encode64(token)}")
    |> configure_session(renew: true)
    |> redirect_after_login(customer)
  end
  
  defp redirect_after_login(conn, customer) do
    if customer.is_staff do
      redirect(conn, to: "/admin/dashboard")
    else
      redirect(conn, to: "/")
    end
  end
  
  @doc """
  Logs the customer out.
  
  It clears all session data and redirects to the homepage.
  """
  def log_out_customer(conn) do
    if token = get_session(conn, @session_token_key) do
      Customers.delete_session_token(token)
    end
    
    conn
    |> configure_session(drop: true)
    |> redirect(to: "/")
  end
  
  @doc """
  Authenticates the customer by looking into the session.
  """
  def fetch_current_customer(conn, _opts) do
    token = get_session(conn, @session_token_key)
    customer = token && Customers.get_customer_by_session_token(token)
    assign(conn, :current_customer, customer)
  end
  
  @doc """
  Used for routes that require the user to be authenticated.
  
  If you need to check if they're staff, use `require_staff_customer/2` instead.
  """
  def require_authenticated_customer(conn, _opts) do
    if conn.assigns[:current_customer] do
      conn
    else
      conn
      |> put_flash(:error, "You must log in to access this page.")
      |> redirect(to: "/admin/login")
      |> halt()
    end
  end
  
  @doc """
  Used for routes that require the user to be a staff member.
  """
  def require_staff_customer(conn, _opts) do
    customer = conn.assigns[:current_customer]
    
    cond do
      # No customer logged in - redirect to admin login
      is_nil(customer) ->
        conn
        |> put_flash(:error, "You must be logged in to access this page.")
        |> redirect(to: "/admin/login")
        |> halt()
      
      # Customer logged in but not staff - redirect to home
      not customer.is_staff ->
        conn
        |> put_flash(:error, "You are not authorized to access this page.")
        |> redirect(to: "/")
        |> halt()
      
      # Staff customer - allow access
      true ->
        conn
    end
  end
end