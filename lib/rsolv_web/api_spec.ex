defmodule RsolvWeb.ApiSpec do
  @moduledoc """
  OpenAPI specification for the RSOLV API.

  This module defines the overall structure, metadata, and configuration
  for the API documentation using OpenAPI 3.0 specification via open_api_spex.
  """

  alias OpenApiSpex.{Info, OpenApi, Paths, Server, Components, SecurityScheme}
  alias RsolvWeb.{Endpoint, Router}

  @behaviour OpenApi

  @impl OpenApi
  def spec do
    # Try to get server from endpoint, but fall back to static config if endpoint not started
    servers =
      try do
        [Server.from_endpoint(Endpoint)]
      rescue
        RuntimeError ->
          # Endpoint not started (e.g., during compilation), use static config
          [
            %Server{
              url: "https://api.rsolv.dev",
              description: "Production API server"
            },
            %Server{
              url: "https://staging-api.rsolv.dev",
              description: "Staging API server"
            },
            %Server{
              url: "http://localhost:4000",
              description: "Local development server"
            }
          ]
      end

    %OpenApi{
      servers: servers,
      info: %Info{
        title: "RSOLV API",
        version: "1.0.0",
        description: """
        The RSOLV API provides comprehensive security vulnerability detection, AST analysis,
        and automated fix generation capabilities.

        ## Features

        - **Pattern-based Detection**: Access to 400+ security vulnerability patterns
        - **AST Analysis**: Advanced Abstract Syntax Tree analysis for accurate detection
        - **Vulnerability Validation**: AI-powered validation to reduce false positives
        - **Credential Management**: Secure credential exchange for GitHub Actions
        - **Test Integration**: AST-based test generation for security fixes
        - **Framework Detection**: Automatic detection of web frameworks and libraries

        ## Authentication

        Most endpoints require authentication via API key. Include your API key in the
        `Authorization` header as a Bearer token:

        ```
        Authorization: Bearer rsolv_your_api_key_here
        ```

        Some endpoints (like pattern demo access and health checks) are available without authentication.

        ## Rate Limiting

        API requests are rate-limited based on your subscription tier:
        - Free tier: 100 requests per hour
        - Pro tier: 1000 requests per hour
        - Enterprise: Custom limits

        Rate limit information is included in response headers:
        - `X-RateLimit-Limit`: Maximum requests per hour
        - `X-RateLimit-Remaining`: Remaining requests
        - `X-RateLimit-Reset`: Unix timestamp when limit resets
        """,
        contact: %{
          name: "RSOLV API Support",
          email: "api-support@rsolv.dev",
          url: "https://docs.rsolv.dev"
        },
        license: %{
          name: "Proprietary",
          url: "https://rsolv.dev/docs/terms"
        }
      },
      paths: Paths.from_router(Router),
      components: %Components{
        securitySchemes: %{
          "ApiKeyAuth" => %SecurityScheme{
            type: "http",
            scheme: "bearer",
            bearerFormat: "API Key",
            description: """
            API key authentication. Obtain your API key from the RSOLV dashboard
            and include it as a Bearer token in the Authorization header.
            """
          }
        }
      },
      tags: [
        %{name: "Patterns", description: "Security vulnerability pattern endpoints"},
        %{name: "AST", description: "Abstract Syntax Tree analysis endpoints"},
        %{name: "Vulnerabilities", description: "Vulnerability validation endpoints"},
        %{name: "Credentials", description: "Credential exchange for GitHub Actions"},
        %{name: "Test Integration", description: "AST-based test generation endpoints"},
        %{name: "Framework", description: "Framework and library detection"},
        %{name: "Phases", description: "Phase data storage for multi-phase operations"},
        %{name: "Health", description: "API health and status endpoints"},
        %{name: "Feedback", description: "User feedback endpoints"},
        %{name: "Education", description: "Educational resources"},
        %{name: "Audit", description: "Audit log endpoints"}
      ]
    }
    |> OpenApiSpex.resolve_schema_modules()
  end
end
