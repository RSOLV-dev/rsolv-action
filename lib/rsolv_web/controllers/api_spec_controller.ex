defmodule RsolvWeb.ApiSpecController do
  @moduledoc """
  Controller for serving OpenAPI specification documents.
  """

  use RsolvWeb, :controller

  alias OpenApiSpex.OpenApi
  alias Plug.Conn

  @doc """
  Serves the OpenAPI specification as JSON.
  """
  def spec(conn, _params) do
    spec = RsolvWeb.ApiSpec.spec()

    conn
    |> put_resp_content_type("application/json")
    |> json(spec)
  end

  @doc """
  Serves the Swagger UI for interactive API documentation.
  """
  def swaggerui(conn, _params) do
    conn
    |> put_resp_content_type("text/html")
    |> send_resp(200, swagger_ui_html())
  end

  defp swagger_ui_html do
    """
    <!DOCTYPE html>
    <html lang="en">
    <head>
      <meta charset="UTF-8">
      <title>RSOLV API Documentation</title>
      <link rel="stylesheet" type="text/css" href="https://cdn.jsdelivr.net/npm/swagger-ui-dist@5/swagger-ui.css" />
      <style>
        html { box-sizing: border-box; overflow: -moz-scrollbars-vertical; overflow-y: scroll; }
        *, *:before, *:after { box-sizing: inherit; }
        body { margin: 0; padding: 0; }
      </style>
    </head>
    <body>
      <div id="swagger-ui"></div>
      <script src="https://cdn.jsdelivr.net/npm/swagger-ui-dist@5/swagger-ui-bundle.js" charset="UTF-8"></script>
      <script src="https://cdn.jsdelivr.net/npm/swagger-ui-dist@5/swagger-ui-standalone-preset.js" charset="UTF-8"></script>
      <script>
        window.onload = function() {
          window.ui = SwaggerUIBundle({
            url: "/api/openapi",
            dom_id: '#swagger-ui',
            deepLinking: true,
            presets: [
              SwaggerUIBundle.presets.apis,
              SwaggerUIStandalonePreset
            ],
            plugins: [
              SwaggerUIBundle.plugins.DownloadUrl
            ],
            layout: "StandaloneLayout"
          });
        };
      </script>
    </body>
    </html>
    """
  end
end
