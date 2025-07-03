defmodule RsolvWeb.Services.PrometheusHelper do
  @moduledoc """
  Helper module for standardizing Prometheus interactions across the application.
  Centralizes conditional dependency loading and error handling for monitoring.
  """
  
  require Logger
  
  def monitoring_enabled? do
    Application.get_env(:rsolv, :monitoring, [])
    |> Keyword.get(:enabled, false)
  end
  
  def metrics_available? do
    monitoring_enabled?() && 
    Code.ensure_loaded?(Prometheus.Metric) && 
    Code.ensure_loaded?(Prometheus.Metric.Counter) &&
    Code.ensure_loaded?(Prometheus.Metric.Histogram)
  end
  
  def exporter_available? do
    monitoring_enabled?() && Code.ensure_loaded?(Prometheus.PlugExporter)
  end
  
  def safe_prometheus_call(module, function, args, error_msg \\ nil) do
    if monitoring_enabled?() && Code.ensure_loaded?(module) do
      try do
        apply(module, function, args)
      rescue
        e ->
          log_msg = if error_msg, do: "#{error_msg}: #{inspect(e)}", 
                                  else: "Error in Prometheus call to #{module}.#{function}: #{inspect(e)}"
          Logger.warning(log_msg)
          :error
      end
    else
      :not_available
    end
  end
  
  def declare_counter(opts) do
    safe_prometheus_call(Prometheus.Metric.Counter, :declare, [opts], 
                         "Failed to declare Prometheus counter: #{opts[:name]}")
  end
  
  def declare_gauge(opts) do
    safe_prometheus_call(Prometheus.Metric.Gauge, :declare, [opts], 
                         "Failed to declare Prometheus gauge: #{opts[:name]}")
  end
  
  def declare_histogram(opts) do
    safe_prometheus_call(Prometheus.Metric.Histogram, :declare, [opts], 
                         "Failed to declare Prometheus histogram: #{opts[:name]}")
  end
  
  def increment_counter(opts) do
    safe_prometheus_call(Prometheus.Metric.Counter, :inc, [opts], 
                         "Failed to increment Prometheus counter")
  end
  
  def observe_histogram(opts) do
    safe_prometheus_call(Prometheus.Metric.Histogram, :observe, [opts], 
                         "Failed to observe Prometheus histogram")
  end
  
  def set_gauge(opts) do
    safe_prometheus_call(Prometheus.Metric.Gauge, :set, [opts], 
                         "Failed to set Prometheus gauge")
  end
  
  def export_metrics(conn) do
    if exporter_available?() do
      safe_prometheus_call(Prometheus.PlugExporter, :export, [conn, []], 
                          "Failed to export Prometheus metrics")
    else
      conn
      |> Plug.Conn.put_resp_content_type("text/plain")
      |> Plug.Conn.send_resp(200, "# Metrics collection is disabled in this environment")
    end
  end
  
  def setup_process_collector do
    if monitoring_enabled?() && Code.ensure_loaded?(:prometheus_process_collector) do
      safe_prometheus_call(Prometheus.Registry, :register_collector, [:prometheus_process_collector], 
                          "Failed to set up Prometheus process collector")
    end
  end
  
  def setup_plug_exporter do
    if exporter_available?() do
      safe_prometheus_call(Prometheus.PlugExporter, :setup, [], 
                          "Failed to set up Prometheus plug exporter")
    end
  end
end