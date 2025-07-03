defmodule RsolvWeb.Api.V1.AuditLogController do
  use RsolvWeb, :controller
  
  alias Rsolv.AST.AuditLogger
  
  @doc """
  Query audit logs with filters.
  
  Query parameters:
  - event_type: Filter by event type
  - severity: Filter by severity (info, warning, error, critical)
  - since: ISO8601 timestamp for start time
  - until: ISO8601 timestamp for end time
  - correlation_id: Filter by correlation ID
  """
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