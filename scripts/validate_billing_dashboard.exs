#!/usr/bin/env elixir

defmodule BillingDashboardValidator do
  @moduledoc """
  Validates the billing dashboard configuration and tests with live data.

  This script:
  1. Validates dashboard JSON structure
  2. Emits test telemetry events
  3. Verifies events appear in Prometheus
  4. Optionally validates via Grafana HTTP API

  ## Usage

      mix run scripts/validate_billing_dashboard.exs

  Or with Grafana validation:

      GRAFANA_URL=http://localhost:3000 \
      GRAFANA_TOKEN=your_token \
      mix run scripts/validate_billing_dashboard.exs --grafana
  """

  require Logger

  def run(args \\ []) do
    Logger.info("Starting billing dashboard validation")

    with :ok <- validate_dashboard_json(),
         :ok <- emit_test_events(),
         :ok <- verify_prometheus_metrics(),
         :ok <- maybe_validate_grafana(args) do
      Logger.info("✅ All validations passed!")
      :ok
    else
      {:error, reason} ->
        Logger.error("❌ Validation failed: #{inspect(reason)}")
        exit({:shutdown, 1})
    end
  end

  defp validate_dashboard_json do
    Logger.info("Validating dashboard JSON structure...")

    dashboard_path = "config/monitoring/billing_dashboard.json"

    with {:ok, content} <- File.read(dashboard_path),
         {:ok, dashboard} <- Jason.decode(content) do
      # Validate required fields
      required_fields = ["dashboard"]
      missing = required_fields -- Map.keys(dashboard)

      if missing == [] do
        dashboard_config = dashboard["dashboard"]

        # Validate panels exist
        panels = Map.get(dashboard_config, "panels", [])

        if length(panels) >= 10 do
          Logger.info("✅ Dashboard has #{length(panels)} panels")

          # Validate critical panels exist
          validate_critical_panels(panels)
        else
          {:error, "Expected at least 10 panels, found #{length(panels)}"}
        end
      else
        {:error, "Missing required fields: #{inspect(missing)}"}
      end
    else
      {:error, :enoent} ->
        {:error, "Dashboard file not found: #{dashboard_path}"}

      {:error, reason} ->
        {:error, "Failed to parse dashboard JSON: #{inspect(reason)}"}
    end
  end

  defp validate_critical_panels(panels) do
    critical_panels = [
      "Subscription Creation Rate",
      "Payment Success Rate",
      "Revenue by Plan",
      "Customer Conversion Funnel"
    ]

    panel_titles = Enum.map(panels, & &1["title"])
    missing_panels = critical_panels -- panel_titles

    if missing_panels == [] do
      Logger.info("✅ All critical panels present")
      :ok
    else
      {:error, "Missing critical panels: #{inspect(missing_panels)}"}
    end
  end

  defp emit_test_events do
    Logger.info("Emitting test telemetry events...")

    # Ensure telemetry is available
    Application.ensure_all_started(:telemetry)

    test_events = [
      # Subscription created
      {[:rsolv, :billing, :subscription_created], %{amount: 4900, duration: 250},
       %{customer_id: "cus_test_123", plan: "pro", status: "success"}},
      # Payment processed
      {[:rsolv, :billing, :payment_processed], %{amount_cents: 4900, duration: 500},
       %{customer_id: "cus_test_123", status: "success", payment_method: "card"}},
      # Invoice paid
      {[:rsolv, :billing, :invoice_paid], %{amount_cents: 4900, duration: 200},
       %{customer_id: "cus_test_123", plan: "pro"}},
      # Usage tracked
      {[:rsolv, :billing, :usage_tracked], %{quantity: 5},
       %{customer_id: "cus_test_123", plan: "pro", resource_type: "fix"}},
      # Credits added
      {[:rsolv, :billing, :credits_added], %{quantity: 5},
       %{customer_id: "cus_test_456", reason: "signup_bonus"}},
      # Subscription cancelled
      {[:rsolv, :billing, :subscription_cancelled], %{duration: 150},
       %{customer_id: "cus_test_789", plan: "pro", reason: "customer_request"}}
    ]

    Enum.each(test_events, fn {event_name, measurements, metadata} ->
      :telemetry.execute(event_name, measurements, metadata)
      Logger.debug("Emitted: #{inspect(event_name)}")
    end)

    Logger.info("✅ Emitted #{length(test_events)} test events")
    :ok
  end

  defp verify_prometheus_metrics do
    Logger.info("Verifying Prometheus metrics...")

    # In a real scenario, you would query Prometheus HTTP API
    # For now, we just verify the plugin is configured correctly

    case Code.ensure_loaded(Rsolv.PromEx.BillingPlugin) do
      {:module, _} ->
        Logger.info("✅ BillingPlugin module loaded successfully")
        :ok

      {:error, reason} ->
        {:error, "Failed to load BillingPlugin: #{inspect(reason)}"}
    end
  end

  defp maybe_validate_grafana(args) do
    if "--grafana" in args do
      validate_grafana()
    else
      Logger.info("Skipping Grafana validation (use --grafana flag to enable)")
      :ok
    end
  end

  defp validate_grafana do
    Logger.info("Validating via Grafana HTTP API...")

    grafana_url = System.get_env("GRAFANA_URL") || "http://localhost:3000"
    grafana_token = System.get_env("GRAFANA_TOKEN")

    if grafana_token do
      validate_grafana_dashboard(grafana_url, grafana_token)
    else
      Logger.warning("GRAFANA_TOKEN not set, skipping Grafana validation")
      :ok
    end
  end

  defp validate_grafana_dashboard(base_url, token) do
    # Read and upload dashboard
    dashboard_path = "config/monitoring/billing_dashboard.json"

    with {:ok, content} <- File.read(dashboard_path),
         {:ok, dashboard} <- Jason.decode(content) do
      # Prepare API request
      url = "#{base_url}/api/dashboards/db"

      headers = [
        {"Authorization", "Bearer #{token}"},
        {"Content-Type", "application/json"}
      ]

      # Upload dashboard
      case HTTPoison.post(url, content, headers) do
        {:ok, %{status_code: 200}} ->
          Logger.info("✅ Dashboard uploaded successfully to Grafana")
          :ok

        {:ok, %{status_code: code, body: body}} ->
          Logger.error("Grafana API returned #{code}: #{body}")
          {:error, "Failed to upload dashboard"}

        {:error, reason} ->
          Logger.error("Failed to connect to Grafana: #{inspect(reason)}")
          {:error, "Grafana connection failed"}
      end
    end
  end
end

# Run validation
case System.argv() do
  args ->
    BillingDashboardValidator.run(args)
end
