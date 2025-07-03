defmodule RsolvWeb.Plugs.PrometheusExPlug do
  @moduledoc """
  Plug for serving Prometheus metrics at /metrics endpoint.
  Also sets up metric collectors and telemetry handlers.
  This plug is conditionally enabled based on application configuration.
  """
  
  require Logger
  alias RsolvWeb.Services.PrometheusHelper
  alias RsolvWeb.Services.Metrics
  
  @doc """
  Initialize Prometheus metrics collection.
  Should be called from Application.start/2.
  """
  def setup do
    if PrometheusHelper.monitoring_enabled?() do
      Logger.info("Setting up Prometheus metrics collection")
      
      # Initialize metric collectors
      if Code.ensure_loaded?(Metrics) do
        Metrics.setup()
      end
      
      # Initialize process collector
      PrometheusHelper.setup_process_collector()
      
      # Create a metrics exporter
      PrometheusHelper.setup_plug_exporter()
      
      :ok
    else
      Logger.info("Prometheus metrics collection disabled")
      :ok
    end
  end
  
  @doc """
  Phoenix plug for handling the /metrics endpoint.
  """
  def init(opts), do: opts
  
  def call(conn, _opts) do
    if PrometheusHelper.monitoring_enabled?() do
      # Set up request timing
      start = System.monotonic_time()
      
      # Continue processing the request
      conn = Plug.Conn.put_private(conn, :prometheus_metrics_start, start)
      
      # Register a callback to track request duration after the response is sent
      Plug.Conn.register_before_send(conn, &before_send_callback/1)
    else
      conn
    end
  end
  
  defp before_send_callback(conn) do
    if PrometheusHelper.monitoring_enabled?() and Code.ensure_loaded?(Metrics) do
      # Calculate request duration
      start = conn.private[:prometheus_metrics_start]
      
      if start do
        duration_ms = System.convert_time_unit(System.monotonic_time() - start, :native, :millisecond)
        
        # Record HTTP metrics
        Metrics.count_http_request(
          conn.method,
          conn.request_path,
          conn.status |> Integer.to_string()
        )
        
        Metrics.observe_http_request_duration(
          conn.method,
          conn.request_path,
          duration_ms
        )
      end
    end
    
    conn
  end
end