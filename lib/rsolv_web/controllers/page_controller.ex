defmodule RsolvWeb.PageController do
  use RsolvWeb, :controller

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
end