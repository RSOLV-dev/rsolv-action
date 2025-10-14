defmodule RsolvWeb.Api.V1.AuditLogController do
  use RsolvWeb, :controller
  use OpenApiSpex.ControllerSpecs

  alias Rsolv.AST.AuditLogger
  alias RsolvWeb.Schemas.Audit.AuditLogResponse
  alias RsolvWeb.Schemas.Error.ErrorResponse

  tags ["Audit"]

  operation(:index,
    summary: "Query audit logs",
    description: """
    Retrieve security audit events with optional filtering.

    **Authentication Required** - Enterprise tier only.

    **Query Filters:**
    - Filter by event type, severity, time range, or correlation ID
    - Results are returned in reverse chronological order (newest first)
    - Maximum 1000 events per query

    **Common Event Types:**
    - `api_access`: API endpoint access
    - `auth_failure`: Authentication failures
    - `rate_limit_exceeded`: Rate limit violations
    - `credential_exchange`: API key usage
    - `vulnerability_scan`: Security scan operations

    **Severity Levels:**
    - `info`: Normal operational events
    - `warning`: Noteworthy but non-critical events
    - `error`: Error conditions
    - `critical`: Security incidents requiring immediate attention

    **Compliance:**
    This endpoint supports SOC 2, ISO 27001, and GDPR compliance requirements
    by providing comprehensive audit trails of all security-relevant events.
    """,
    parameters: [
      event_type: [
        in: :query,
        description: "Filter by event type (e.g., api_access, auth_failure)",
        type: :string,
        required: false
      ],
      severity: [
        in: :query,
        description: "Filter by severity level (info, warning, error, critical)",
        type: :string,
        required: false
      ],
      since: [
        in: :query,
        description: "Start time (ISO8601 format)",
        type: :string,
        required: false,
        example: "2025-10-14T00:00:00Z"
      ],
      until: [
        in: :query,
        description: "End time (ISO8601 format)",
        type: :string,
        required: false,
        example: "2025-10-14T23:59:59Z"
      ],
      correlation_id: [
        in: :query,
        description: "Filter by correlation ID to track related events",
        type: :string,
        required: false
      ]
    ],
    responses: [
      ok: {"Audit events retrieved successfully", "application/json", AuditLogResponse},
      unauthorized: {"Invalid or missing API key", "application/json", ErrorResponse},
      forbidden: {
        "Insufficient permissions (Enterprise tier required)",
        "application/json",
        ErrorResponse
      }
    ],
    security: [%{"ApiKeyAuth" => []}]
  )

  def index(conn, params) do
    criteria = build_query_criteria(params)
    
    events = AuditLogger.query_events(criteria)
    
    json(conn, %{
      events: events,
      total: length(events)
    })
  end
  
  @doc """
  Get aggregated security metrics.
  """
  def metrics(conn, _params) do
    metrics = AuditLogger.get_security_metrics()
    
    json(conn, %{
      metrics: metrics
    })
  end
  
  @doc """
  Export audit logs in specified format.
  """
  def export(conn, params) do
    format = String.to_atom(params["format"] || "csv")
    criteria = build_query_criteria(params)
    
    case AuditLogger.export_events(format, criteria) do
      {:ok, data} ->
        conn
        |> put_resp_content_type("text/csv")
        |> put_resp_header("content-disposition", "attachment; filename=\"audit_logs.csv\"")
        |> send_resp(200, data)
        
      {:error, reason} ->
        conn
        |> put_status(:bad_request)
        |> json(%{error: reason})
    end
  end
  
  # Private functions
  
  defp build_query_criteria(params) do
    criteria = %{}
    
    criteria = if params["event_type"] do
      Map.put(criteria, :event_type, String.to_atom(params["event_type"]))
    else
      criteria
    end
    
    criteria = if params["severity"] do
      Map.put(criteria, :severity, String.to_atom(params["severity"]))
    else
      criteria
    end
    
    criteria = if params["since"] do
      case DateTime.from_iso8601(params["since"]) do
        {:ok, datetime, _} -> Map.put(criteria, :since, datetime)
        _ -> criteria
      end
    else
      criteria
    end
    
    criteria = if params["until"] do
      case DateTime.from_iso8601(params["until"]) do
        {:ok, datetime, _} -> Map.put(criteria, :until, datetime)
        _ -> criteria
      end
    else
      criteria
    end
    
    criteria = if params["correlation_id"] do
      Map.put(criteria, :correlation_id, params["correlation_id"])
    else
      criteria
    end
    
    criteria
  end
end