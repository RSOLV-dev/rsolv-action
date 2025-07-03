defmodule RsolvWeb.MetricsController do
  use RsolvWeb, :controller
  require Logger
  alias RsolvWeb.Services.PrometheusHelper

  def index(conn, _params) do
    if Application.get_env(:rsolv, :monitoring, []) |> Keyword.get(:enabled, false) do
      export_metrics(conn)
    else
      conn
      |> put_resp_content_type("text/plain")
      |> send_resp(200, "# Metrics collection is disabled in this environment")
    end
  end
  
  defp export_metrics(conn) do
    result = PrometheusHelper.export_metrics(conn)
    
    case result do
      %Plug.Conn{} = updated_conn -> updated_conn
      :error ->
        conn
        |> put_resp_content_type("text/plain")
        |> send_resp(500, "Error exporting metrics: Prometheus exporter unavailable")
      _ ->
        conn
        |> put_resp_content_type("text/plain")
        |> send_resp(200, "# Metrics collection is disabled in this environment")
    end
  end
end