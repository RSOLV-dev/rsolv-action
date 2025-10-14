defmodule RsolvWeb.Schemas.Health do
  @moduledoc """
  OpenAPI schemas for health check endpoints.
  """

  alias OpenApiSpex.Schema

  defmodule HealthResponse do
    @moduledoc "Health check response schema"
    require OpenApiSpex

    OpenApiSpex.schema(%{
      title: "HealthResponse",
      type: :object,
      description: "System health status including service availability and clustering info",
      properties: %{
        status: %Schema{
          type: :string,
          enum: ["healthy", "degraded"],
          description: "Overall system health status"
        },
        service: %Schema{type: :string, description: "Service name", example: "rsolv-api"},
        version: %Schema{type: :string, description: "API version", example: "0.1.0"},
        timestamp: %Schema{
          type: :string,
          format: :"date-time",
          description: "Current server timestamp"
        },
        node: %Schema{
          type: :string,
          description: "Current BEAM node identifier",
          example: "nonode@nohost"
        },
        services: %Schema{
          type: :object,
          description: "Status of dependent services",
          properties: %{
            database: %Schema{
              type: :string,
              enum: ["healthy", "unhealthy"],
              description: "PostgreSQL database connection status"
            },
            ai_providers: %Schema{
              type: :object,
              description: "Status of AI provider connections",
              properties: %{
                anthropic: %Schema{type: :string, enum: ["healthy", "unhealthy"]},
                openai: %Schema{type: :string, enum: ["healthy", "unhealthy"]},
                openrouter: %Schema{type: :string, enum: ["healthy", "unhealthy"]}
              }
            }
          }
        },
        clustering: %Schema{
          type: :object,
          description: "BEAM clustering information",
          properties: %{
            enabled: %Schema{type: :boolean, description: "Whether clustering is enabled"},
            current_node: %Schema{
              type: :string,
              description: "Current node name",
              nullable: true
            },
            connected_nodes: %Schema{
              type: :array,
              items: %Schema{type: :string},
              description: "List of connected nodes",
              nullable: true
            },
            node_count: %Schema{
              type: :integer,
              description: "Total number of nodes in cluster",
              nullable: true
            }
          }
        }
      },
      required: [:status, :service, :version, :timestamp, :services],
      example: %{
        "status" => "healthy",
        "service" => "rsolv-api",
        "version" => "0.1.0",
        "timestamp" => "2025-10-14T15:30:00Z",
        "node" => "nonode@nohost",
        "services" => %{
          "database" => "healthy",
          "ai_providers" => %{
            "anthropic" => "healthy",
            "openai" => "healthy",
            "openrouter" => "healthy"
          }
        },
        "clustering" => %{
          "enabled" => false
        }
      }
    })
  end
end
