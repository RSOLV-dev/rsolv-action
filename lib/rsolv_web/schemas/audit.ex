defmodule RsolvWeb.Schemas.Audit do
  @moduledoc """
  OpenAPI schemas for audit log endpoints.
  """

  alias OpenApiSpex.Schema

  defmodule AuditEvent do
    @moduledoc "Single audit event schema"
    require OpenApiSpex

    OpenApiSpex.schema(%{
      title: "AuditEvent",
      type: :object,
      description: "Security audit event record",
      properties: %{
        id: %Schema{type: :string, format: :uuid, description: "Event unique identifier"},
        event_type: %Schema{
          type: :string,
          description: "Type of security event",
          example: "api_access"
        },
        severity: %Schema{
          type: :string,
          enum: ["info", "warning", "error", "critical"],
          description: "Event severity level"
        },
        timestamp: %Schema{
          type: :string,
          format: :"date-time",
          description: "When the event occurred"
        },
        correlation_id: %Schema{
          type: :string,
          description: "Correlation ID for tracking related events",
          nullable: true
        },
        metadata: %Schema{
          type: :object,
          description: "Additional event-specific data",
          additionalProperties: true
        }
      },
      required: [:id, :event_type, :severity, :timestamp],
      example: %{
        "id" => "550e8400-e29b-41d4-a716-446655440000",
        "event_type" => "api_access",
        "severity" => "info",
        "timestamp" => "2025-10-14T15:30:00Z",
        "correlation_id" => "req-abc123",
        "metadata" => %{
          "endpoint" => "/api/v1/patterns",
          "ip_address" => "192.168.1.1",
          "user_agent" => "RSOLV-action/3.7.46"
        }
      }
    })
  end

  defmodule AuditLogResponse do
    @moduledoc "Audit log query response"
    require OpenApiSpex

    OpenApiSpex.schema(%{
      title: "AuditLogResponse",
      type: :object,
      description: "Paginated list of audit events",
      properties: %{
        events: %Schema{
          type: :array,
          items: AuditEvent,
          description: "List of audit events matching query"
        },
        total: %Schema{
          type: :integer,
          description: "Total number of events returned",
          example: 42
        }
      },
      required: [:events, :total],
      example: %{
        "events" => [
          %{
            "id" => "550e8400-e29b-41d4-a716-446655440000",
            "event_type" => "api_access",
            "severity" => "info",
            "timestamp" => "2025-10-14T15:30:00Z"
          }
        ],
        "total" => 1
      }
    })
  end
end
