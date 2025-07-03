defmodule RsolvWeb.PageController do
  use RsolvWeb, :controller
  require Logger

  def home(conn, _params) do
    # For now, render a simple HTML response
    html(conn, """
    <!DOCTYPE html>
    <html>
      <head>
        <title>RSOLV - AI-Powered Security</title>
      </head>
      <body>
        <h1>RSOLV Platform</h1>
        <p>Unified security platform</p>
      </body>
    </html>
    """)
  end

  def blog(conn, _params) do
    # Placeholder for blog
    html(conn, """
    <!DOCTYPE html>
    <html>
      <head>
        <title>RSOLV Blog</title>
      </head>
      <body>
        <h1>RSOLV Blog</h1>
        <p>Coming soon...</p>
      </body>
    </html>
    """)
  end

  @doc """
  Renders the thank you page after successful signup
  """
  def thank_you(conn, _params) do
    # Add success_email to assign if available in session or flash
    conn = 
      cond do
        # First check session
        get_session(conn, :success_email) ->
          assign(conn, :success_email, get_session(conn, :success_email))
        
        # Then check flash (from LiveView redirect)
        Phoenix.Flash.get(conn.assigns.flash, :success_email) ->
          email = Phoenix.Flash.get(conn.assigns.flash, :success_email)
          conn 
          |> assign(:success_email, email)
          |> put_session(:success_email, email)
        
        # Also check regular flash (for tests)
        get_flash(conn, :success_email) ->
          email = get_flash(conn, :success_email)
          conn
          |> assign(:success_email, email)
        
        # Default case
        true -> conn
      end
    
    # Render the thank you page
    render(conn, :thank_you, layout: false)
  end

  @doc """
  Renders the privacy policy page
  """
  def privacy(conn, _params) do
    render(conn, :privacy)
  end

  @doc """
  Renders the terms of service page
  """
  def terms(conn, _params) do
    render(conn, :terms)
  end

  @doc """
  Renders the unsubscribe page
  """
  def unsubscribe(conn, params) do
    # Get email from params if present
    email = Map.get(params, "email")
    render(conn, :unsubscribe, email: email)
  end

  @doc """
  Processes an unsubscribe request
  """
  def process_unsubscribe(conn, %{"email" => email} = _params) do
    # Validate email
    if is_valid_email?(email) do
      # For now, just log the unsubscribe request
      # In production, this would record the unsubscribe in the database
      Logger.info("Unsubscribe request for: #{email}")
      
      render(conn, :unsubscribe_success, email: email)
    else
      render(conn, :unsubscribe_error, email: email)
    end
  end

  def process_unsubscribe(conn, _params) do
    # No email provided
    render(conn, :unsubscribe_error, email: nil)
  end

  # Basic email validation
  defp is_valid_email?(email) when is_binary(email) do
    email != "" &&
    String.contains?(email, "@") &&
    String.length(email) >= 5 &&
    String.match?(email, ~r/^[^@\s]+@[^@\s]+\.[^@\s]+$/)
  end
  
  defp is_valid_email?(_), do: false
end