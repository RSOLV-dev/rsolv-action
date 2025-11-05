# RSOLV Monitoring & Observability - Quick Reference Guide

## For Developers: Adding New Metrics

### 1. Creating Custom Telemetry Events

#### Option A: Simple Counter/Gauge

```elixir
# In your code, emit a telemetry event
:telemetry.execute(
  [:rsolv, :my_feature, :event_name],
  %{count: 1, duration: 125},  # measurements
  %{customer_id: "cus_123", status: "success"}  # metadata
)
```

#### Option B: Create a PromEx Plugin

```elixir
# lib/rsolv/prom_ex/my_feature_plugin.ex
defmodule Rsolv.PromEx.MyFeaturePlugin do
  use PromEx.Plugin

  @impl true
  def event_metrics(_opts) do
    Event.build(
      :my_feature_metrics,
      [
        counter(
          [:rsolv, :my_feature, :events, :total],
          event_name: [:rsolv, :my_feature, :event_name],
          description: "Total events from my feature",
          tags: [:customer_id, :status],
          tag_values: &extract_tags/1
        ),
        distribution(
          [:rsolv, :my_feature, :duration, :milliseconds],
          event_name: [:rsolv, :my_feature, :event_name],
          measurement: :duration,
          description: "My feature duration",
          tags: [:customer_id],
          tag_values: &extract_tags_success/1,
          unit: {:native, :millisecond},
          reporter_options: [buckets: [100, 500, 1000, 5000]]
        )
      ]
    )
  end

  @impl true
  def polling_metrics(_opts), do: []

  @impl true
  def manual_metrics(_opts), do: []

  defp extract_tags(metadata) do
    %{
      customer_id: Map.get(metadata, :customer_id, "unknown"),
      status: Map.get(metadata, :status, "unknown")
    }
  end

  defp extract_tags_success(metadata) do
    if Map.get(metadata, :status) == "success" do
      %{customer_id: Map.get(metadata, :customer_id, "unknown")}
    else
      :skip
    end
  end
end
```

Then register it in `/lib/rsolv/prom_ex.ex`:

```elixir
def plugins do
  [
    # ... other plugins
    Rsolv.PromEx.MyFeaturePlugin  # Add this
  ]
end
```

### 2. Accessing Metrics

#### View Prometheus Metrics
```
curl http://localhost:4021/metrics | grep rsolv_my_feature
```

#### Check in Grafana
1. Navigate to `https://grafana.rsolv.dev`
2. Create dashboard or use Explore
3. Query: `rsolv_my_feature_events_total{customer_id="cus_123"}`

#### Check Logs
```bash
# Look for metrics reported every 60s by ValidationReporter
docker logs -f <container> | grep "Validation Metrics"
```

### 3. Tag Cardinality (Important!)

Use `Rsolv.PromEx.Helpers` for safe tag extraction:

```elixir
defp extract_tags(metadata) do
  %{
    # Good - Limited cardinality
    status: Rsolv.PromEx.Helpers.extract_tag(metadata, :status, "unknown"),

    # Good - Categorized
    error_category: Rsolv.PromEx.Helpers.categorize_error(metadata.error_msg),

    # BAD - Would explode cardinality
    # full_error_message: metadata.error_msg  # Don't do this!
  }
end
```

---

## Existing Metrics Quick Lookup

### Business Metrics
| Feature | Metric | Granularity | Location |
|---------|--------|-------------|----------|
| Validation | test_integration_analyze, test_integration_generate | language, framework, customer | `/lib/rsolv/prom_ex/validation_plugin.ex` |
| Billing | subscription_created, payment_processed, invoice_paid | plan, customer, payment_method | `/lib/rsolv/prom_ex/billing_plugin.ex` |
| Onboarding | customer_onboarding_complete | source, customer | `/lib/rsolv/prom_ex/customer_onboarding_plugin.ex` |
| Signups | signups_total, signups_by_source, signups_by_domain | source, domain | `/lib/rsolv_web/services/metrics.ex` |
| Rate Limiting | rate_limiter_* | action, customer | DISABLED - needs fix |

### Infrastructure Metrics
| System | Metric | Source |
|--------|--------|--------|
| HTTP Endpoints | endpoint.start, endpoint.stop | Phoenix built-in |
| Database | query.start, query.stop | Ecto built-in |
| VM Memory | vm.memory.total | BEAM built-in |
| Cluster | node up/down events | ClusterMonitor |
| Uptime | http_probe | Blackbox exporter |

---

## Configuration Reference

### Environment Variables
```bash
# Enable/disable metrics
ENABLE_PROMETHEUS_METRICS=true|false  # Default: true

# Grafana integration
GRAFANA_HOST=http://localhost:3000
GRAFANA_AUTH_TOKEN=<token>

# Error tracking (optional)
SENTRY_DSN=https://key@sentry.io/project
SENTRY_ENV=production|staging|development
```

### Feature Flags
```bash
# In database via FunWithFlags:
:metrics_dashboard       # View signup metrics (admin)
:admin_dashboard         # Access /dashboard (admin)
```

Enable via Rails console:
```ruby
FunWithFlags.enable(:metrics_dashboard)
```

### Metrics Port
- **Local:** `http://localhost:4021/metrics`
- **Docker:** Must expose port 4021
- **Kubernetes:** ServiceMonitor configured for scraping

---

## Dashboards Available

### Auto-Uploaded to Grafana
- RFC-060 Validation Metrics (production & staging)
- RFC-068 Billing System Metrics
- Beam VM Metrics
- Phoenix HTTP Metrics
- Ecto Database Metrics
- Phoenix LiveView Metrics

### Custom Dashboards
- Signup Analytics (`/dashboard/signup-metrics`) - requires `:metrics_dashboard` flag
- Admin Dashboard (`/dashboard`) - requires `:admin_dashboard` flag

---

## Common Tasks

### Enable Metrics Collection
```bash
# Local development
export ENABLE_PROMETHEUS_METRICS=true
mix phx.server
curl http://localhost:4021/metrics
```

### Query a Metric in Grafana
1. Go to Explore
2. Paste query: `rate(rsolv_billing_subscription_created_total[5m])`
3. Add filters: `{plan="pro"}`
4. Aggregate: `sum by (plan)`

### Check if Metric is Being Collected
```bash
# Wait 60s after event, then check
curl http://localhost:4021/metrics | grep "my_metric_name"

# Should show:
# rsolv_my_metric_name_total{tag="value"} 1.0
```

### Debug Metric Tags
Check `extract_tags/1` function output:
```elixir
iex> metadata = %{customer_id: 123, status: :success}
iex> extract_tags(metadata)
%{customer_id: "123", status: "success"}  # Should be strings!
```

---

## Troubleshooting

### Metrics not appearing in Grafana
1. Check metrics endpoint is working: `curl http://localhost:4021/metrics`
2. Verify Prometheus is scraping (check Prometheus UI)
3. Check query uses correct metric name (case-sensitive)
4. Wait 60+ seconds for metrics to accumulate

### "Cannot connect to Grafana"
- Check `GRAFANA_HOST` env var
- Check `GRAFANA_AUTH_TOKEN` is valid
- Dashboards may still exist even if upload fails

### High cardinality warning
- Check you're using `extract_tag()` helper
- Categorize errors with `categorize_error()`
- Avoid using user IDs or other high-variance fields as tags
- Use only: status, plan, language, framework, method, etc.

### Rate limiter metrics disabled
- Reason: Metric name format incompatibility
- Fix needed in `/lib/rsolv/prom_ex/rate_limiter_plugin.ex`
- Impact: No rate limiting visibility currently

---

## Best Practices

1. **Always use string values for tags** (not atoms or integers)
   - Use `to_string_safe()` helper

2. **Keep tag cardinality low**
   - Max 10-15 unique tag combinations per metric
   - Never use: full error messages, timestamps, user emails

3. **Use appropriate distribution buckets**
   - Duration: [100, 250, 500, 1000, 2000, 5000] ms
   - Amounts: [100, 500, 1500, 4900, 10000] cents
   - Counts: [1, 5, 10, 20, 50, 100, 200]

4. **Document your metrics**
   - Add description field
   - Document what tags mean
   - Include units (milliseconds, cents, percentage)

5. **Test metrics locally**
   - Run `mix phx.server`
   - Emit test events
   - Verify in `curl http://localhost:4021/metrics`
   - Check Grafana dashboard updates

---

## Files to Know

| Path | Purpose |
|------|---------|
| `/lib/rsolv/prom_ex.ex` | Plugin registry & config |
| `/lib/rsolv/prom_ex/*.ex` | Custom metric plugins |
| `/lib/rsolv/telemetry/validation_reporter.ex` | 60s aggregator |
| `/lib/rsolv_web/services/metrics.ex` | Business metric helpers |
| `/lib/rsolv_web/services/prometheus_helper.ex` | Safe dependency loading |
| `/lib/rsolv_web/controllers/metrics_controller.ex` | `/metrics` endpoint |
| `/config/config.exs` | PromEx configuration |
| `/config/runtime.exs` | Environment variable setup |
| `/priv/grafana_dashboards/` | Dashboard JSON files |
| `/monitoring/` | Kubernetes monitoring setup |

---

## Quick Start: Add a New Business Metric

### 1. Emit Event from Your Code
```elixir
# When something happens
:telemetry.execute(
  [:rsolv, :my_feature, :action],
  %{duration: duration_ms},
  %{customer_id: customer_id, status: "success"}
)
```

### 2. Create PromEx Plugin
Copy from `/lib/rsolv/prom_ex/billing_plugin.ex` as template

### 3. Register Plugin
Add to `/lib/rsolv/prom_ex.ex` plugins list

### 4. Verify Metrics
```bash
curl http://localhost:4021/metrics | grep my_feature
```

### 5. Create Grafana Dashboard
Use UI or JSON with PromQL queries

Done! Metrics will auto-upload on restart.
