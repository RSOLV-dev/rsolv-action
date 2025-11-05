# RSOLV Platform Monitoring and Observability Setup - Comprehensive Summary

## Executive Summary

The RSOLV platform has a **sophisticated, multi-layered monitoring and observability infrastructure** with Prometheus/Grafana as the primary stack, complemented by Phoenix telemetry, custom PromEx plugins, and error tracking. The system is production-ready with comprehensive metrics collection across application, infrastructure, and business domains.

---

## 1. Core Monitoring Tools Currently in Use

### 1.1 Primary Monitoring Stack
| Tool | Version | Purpose | Status |
|------|---------|---------|--------|
| **PromEx** | ~1.9 | Prometheus metrics exporter | Active |
| **Prometheus** | (via Kubernetes) | Metrics collection & storage | Active |
| **Grafana** | (via Kubernetes) | Visualization & dashboards | Active |
| **Telemetry** | ~0.6 | Event-based metrics collection | Active |
| **Telemetry Poller** | ~1.0 | Periodic measurement collection | Active |
| **Sentry** | (Optional) | Error tracking & APM | Configured |

### 1.2 Key Infrastructure Components
- **Phoenix LiveDashboard** (~0.8): Built-in Phoenix monitoring (inactive in tests)
- **Kubernetes DNS Clustering**: Service discovery and node monitoring
- **Custom Telemetry Reporters**: Validation metrics, billing metrics
- **Cluster Monitor**: Node up/down event tracking

---

## 2. Metrics Collection Architecture

### 2.1 PromEx Plugins (Custom Metrics)
The system uses PromEx with five custom plugins:

#### **ValidationPlugin** (RFC-060)
**Location:** `/lib/rsolv/prom_ex/validation_plugin.ex`

Tracks:
- Test Integration API metrics
  - `rsolv.test_integration.analyze.total` - Analysis request counters
  - `rsolv.test_integration.generate.total` - Generation request counters
  - `rsolv.test_integration.analyze.duration.milliseconds` - Duration distributions
  - `rsolv.test_integration.generate.duration.milliseconds` - Duration distributions
  - `rsolv.test_integration.generate.lines.integrated` - Code integration metrics
- Legacy validation metrics (future frontend implementation)
  - `rsolv.validation.executions.total`
  - `rsolv.validation.test_generated.total`
  - `rsolv.validation.duration.milliseconds`
- Mitigation metrics (future frontend implementation)
  - `rsolv.mitigation.executions.total`
  - `rsolv.mitigation.trust_score.value`

**Tags:** customer_id, language, framework, status, method
**Buckets:** 10-300,000ms (distributions)

#### **BillingPlugin** (RFC-068)
**Location:** `/lib/rsolv/prom_ex/billing_plugin.ex`

Comprehensive billing system metrics:

Subscription Lifecycle:
- `rsolv.billing.subscription_created.total` - New subscriptions
- `rsolv.billing.subscription_renewed.total` - Renewals
- `rsolv.billing.subscription_cancelled.total` - Cancellations

Payment Processing:
- `rsolv.billing.payment_processed.total` - Payment processing counters
- `rsolv.billing.payment_processed.amount.cents` - Payment amounts (buckets: 100-50,000 cents)
- `rsolv.billing.payment_processed.duration.milliseconds` - Duration (100-10,000ms)
- `rsolv.billing.invoice_paid.total` - Successful invoices
- `rsolv.billing.invoice_paid.amount.cents` - Invoice amounts
- `rsolv.billing.invoice_failed.total` - Failed invoices

Stripe Integration:
- `rsolv.billing.stripe_webhook_received.total` - Webhook reception
- `rsolv.billing.stripe_webhook_received.duration.milliseconds` - Processing time
- `rsolv.billing.stripe_webhook_failed.total` - Failed webhooks

Usage & Credits:
- `rsolv.billing.usage_tracked.total` - Usage events
- `rsolv.billing.usage_tracked.quantity` - Usage quantities (buckets: 1-100)
- `rsolv.billing.credits_added.total` - Credit additions
- `rsolv.billing.credits_added.quantity` - Quantities (buckets: 5-120)
- `rsolv.billing.credits_consumed.total` - Credit consumption

**Tags:** customer_id, plan, status, payment_method, event_type, failure_code, reason
**Buckets:** Granular for financial tracking

#### **CustomerOnboardingPlugin** (RFC-065)
**Location:** `/lib/rsolv/prom_ex/customer_onboarding_plugin.ex`

Tracks customer onboarding flow:
- `rsolv.customer_onboarding.complete.total` - Successful onboardings
- `rsolv.customer_onboarding.failed.total` - Failed attempts
- `rsolv.customer_onboarding.duration.milliseconds` - Duration tracking (100-10,000ms)

**Tags:** status, source, reason
**Purpose:** Monitor signup funnel effectiveness

#### **RateLimiterPlugin** (Commented Out - Has Issues)
**Location:** `/lib/rsolv/prom_ex/rate_limiter_plugin.ex`

**Status:** Disabled due to metric name format issues (referenced in code TODO)

Intended metrics:
- `rsolv.rate_limiter.limit_exceeded.total` - Limit violations
- `rsolv.rate_limiter.requests_allowed.total` - Allowed requests
- `rsolv.rate_limiter.current_count` - Current window usage

### 2.2 Built-in PromEx Plugins
The system also includes standard PromEx plugins for:
- **Application metrics** (general app health)
- **BEAM metrics** (VM performance: memory, run queues)
- **Phoenix metrics** (HTTP endpoint, router dispatch, WebSocket events, LiveView)
- **Ecto metrics** (database query performance, connection pooling)
- **Phoenix LiveView metrics** (LV event timing)

### 2.3 Phoenix Telemetry Infrastructure
**Location:** `/lib/rsolv_web/telemetry.ex`

Measures:
- Phoenix endpoint timing (system_time, duration)
- Router dispatch metrics (start_time, exception duration, stop duration)
- WebSocket/Channel metrics (connection duration, event handling)
- VM metrics (memory usage, run queue lengths)

**Polling Period:** 10 seconds

---

## 3. Grafana Dashboards

### 3.1 Active Dashboards

**Location:** `/priv/grafana_dashboards/`

#### **Validation Metrics Dashboard** (RFC-060)
- File: `rfc-060-validation-metrics.json` (784 lines)
- UID: `fp-cache-production` (production), `fp-cache-staging` (staging)
- Tracks:
  - Cache hit rate (%) - percentage of requests served from cache
  - Response times (P95 latency)
  - Total cached entries count
  - Cache memory usage (MB)
  - Cache invalidations per hour
  - False positive rates
  - Pattern rejection frequency

#### **Billing Dashboard** (RFC-068)
- File: `billing_dashboard.json` (346 lines)
- Tracks:
  - Subscription creation rate (subscriptions/sec by plan)
  - Payment success rate (gauge, 0-100%)
  - Revenue tracking (by plan)
  - Failed invoice trends
  - Webhook processing metrics
  - Credit utilization

#### **Rate Limiter Dashboard**
- File: `rate_limiter.json` (disabled but available)
- Would track rate limit violations and request throughput

#### **Built-in Dashboards**
PromEx provides standard dashboards:
- `application.json` - App-level metrics
- `beam.json` - VM/BEAM metrics
- `phoenix.json` - HTTP/endpoint metrics
- `ecto.json` - Database performance
- `phoenix_live_view.json` - LiveView event metrics

### 3.2 Uptime Monitoring Dashboard
- File: `/monitoring/rsolv-uptime-dashboard.json`
- Kubernetes-based uptime monitoring
- Blackbox exporter probes for:
  - Main site: https://rsolv.dev (2-min alert threshold)
  - Blog: https://rsolv.dev/blog (5-min threshold)
  - Feedback: https://rsolv.dev/feedback (5-min threshold)
- Response time alerts (>3 seconds)
- SSL certificate expiry alerts (7 days before)

**Access:**
- URL: `https://grafana.rsolv.dev/`
- Dashboards auto-uploaded to Grafana on PromEx startup

---

## 4. Telemetry Event System

### 4.1 Validation Metrics Reporter
**Location:** `/lib/rsolv/telemetry/validation_reporter.ex`

GenServer that:
- Subscribes to validation events every 60 seconds
- Collects:
  - Request counts (success/error)
  - Response time percentiles (p50, p95, p99)
  - False positive rates (%)
  - Cache hit rates (%)
  - Pattern rejection tracking
- Logs aggregated metrics to application logs
- Reports to Prometheus via telemetry.execute

**Events Tracked:**
- `[:rsolv, :validation, :request]` - Request metrics
- `[:rsolv, :validation, :false_positive]` - FP detection
- `[:rsolv, :validation, :cache_hit]` - Cache hits
- `[:rsolv, :validation, :cache_miss]` - Cache misses

### 4.2 Pattern Telemetry
**Location:** `/lib/rsolv/security/pattern_telemetry.ex`

Tracks security pattern detection metrics

### 4.3 Custom Metrics Services
**Metrics Service** (`/lib/rsolv_web/services/metrics.ex`)
- HTTP request counting and duration tracking
- Signup tracking (total and by source)
- Feedback submission tracking
- Conversion tracking
- Signup milestone gauges
- Signup domain tracking

**Funnel Metrics** (`/lib/rsolv_web/services/funnel_metrics.ex`)
- Customer journey funnel analysis

---

## 5. Configuration & Setup

### 5.1 Environment Configuration
**Location:** `/config/config.exs`

PromEx Configuration:
```elixir
config :rsolv, Rsolv.PromEx,
  disabled: false,
  manual_metrics_start_delay: :no_delay,
  drop_metrics_groups: [],
  grafana: [
    host: System.get_env("GRAFANA_HOST", "http://localhost:3000"),
    auth_token: System.get_env("GRAFANA_AUTH_TOKEN", ""),
    upload_dashboards_on_start: true,
    folder_name: "Rsolv API Dashboards",
    annotate_app_lifecycle: true
  ],
  metrics_server: [
    port: 4021,
    path: "/metrics",
    protocol: :http,
    pool_size: 5,
    cowboy_opts: [],
    auth_strategy: :none
  ]
```

**Key Settings:**
- Metrics endpoint: `:4021/metrics` (separate from main app)
- Grafana dashboard auto-upload: enabled
- Automatic app lifecycle annotation: enabled
- Folder: "Rsolv API Dashboards"

### 5.2 Runtime Configuration
**Location:** `/config/runtime.exs` (line 192)

```elixir
config :rsolv, :monitoring,
  enabled: System.get_env("ENABLE_PROMETHEUS_METRICS", "true") == "true"
```

**Feature Flag:** `ENABLE_PROMETHEUS_METRICS` (default: enabled)

### 5.3 Test Environment
**Location:** `/config/test.exs`

```elixir
# Disable PromEx in test environment to avoid port conflicts
config :rsolv, Rsolv.PromEx, disabled: true
```

Reason: Port 4021 would conflict in test environments

### 5.4 Sentry Error Tracking
**Location:** `/config/runtime.exs` (lines 179-188)

```elixir
if System.get_env("SENTRY_DSN") do
  config :sentry,
    dsn: System.get_env("SENTRY_DSN"),
    environment_name: System.get_env("SENTRY_ENV") || "production",
    enable_source_code_context: true,
    root_source_code_path: File.cwd!(),
    tags: %{env: System.get_env("SENTRY_ENV") || "production"}
end
```

**Optional:** Only configured if SENTRY_DSN env var is present
**Features:** Source code context, environment tagging

---

## 6. Metrics Endpoints & APIs

### 6.1 Prometheus Metrics Endpoint
- **Port:** 4021 (separate from app port 4000)
- **Path:** `/metrics`
- **Format:** Prometheus text format
- **Exposed By:** `MetricsController` with `PromEx.Plug`
- **Security:** No authentication required in current config

### 6.2 Internal Metrics Endpoints
**Location:** `/lib/rsolv_web/router.ex`

- **GET `/metrics`** - PromEx metrics (via MetricsController)
- **Live Dashboard** - Phoenix LiveDashboard (when enabled, requires auth)
- **Admin Dashboard** (`/dashboard`) - Custom admin dashboard with metrics feature flag

### 6.3 Monitoring Feature Flags
Located in database (`features` table):
- `:metrics_dashboard` - Analytics dashboard availability
- `:admin_dashboard` - Admin dashboard access
- `:feedback_dashboard` - Feedback dashboard access

---

## 7. Infrastructure Monitoring

### 7.1 Kubernetes Monitoring Setup
**Location:** `/monitoring/` directory

**Components:**

1. **Blackbox Exporter** (`blackbox-exporter.yaml`)
   - HTTP endpoint probing
   - Monitors external site availability

2. **Prometheus Configuration** (`prometheus-config-update.yaml`)
   - Scrape configuration for RSOLV endpoints
   - Pod discovery via Kubernetes labels

3. **Alert Rules** (`rsolv-uptime-alerts.yaml`)
   - Downtime alerts (critical sites: 2 min, others: 5 min)
   - Response time alerts (>3s)
   - SSL certificate expiry (7 days before)

4. **Alertmanager Configuration** (`alertmanager-config-webhook.yaml`)
   - Email notification receivers
   - Webhook receiver for recovery alerts
   - Alert throttling to prevent flooding:
     - Critical: 1 on fire, 1/day if down, 1 on recovery
     - Others: Every 4-12 hours
   - 5-minute recovery deduplication window

5. **Custom Webhook Receiver** (`webhook-receiver-deployment.yaml`)
   - Kubernetes deployment
   - Ensures recovery emails are sent (without re-triggering alerts)

### 7.2 Cluster Monitoring
**Location:** `/lib/rsolv/cluster_monitor.ex`

GenServer that:
- Monitors Erlang cluster node up/down events
- Logs cluster topology changes
- Triggers cache invalidation on cluster topology changes
- Supports Kubernetes DNS service discovery

---

## 8. Dependency Stack

### 8.1 Key Dependencies
```
{:phoenix_live_dashboard, "~> 0.8"}     # Built-in monitoring UI
{:telemetry_metrics, "~> 0.6"}          # Metric definitions
{:telemetry_poller, "~> 1.0"}           # Periodic measurements
{:prom_ex, "~> 1.9"}                    # Prometheus exporter
{:sentry, optional}                     # Error tracking (if DSN provided)
{:libcluster, "~> 3.3"}                 # Kubernetes clustering
```

No direct Prometheus, Grafana, or other APM dependencies (they're in infrastructure)

---

## 9. Metrics Being Tracked (By Category)

### 9.1 Application-Level Metrics
| Category | Metric | Tags | Status |
|----------|--------|------|--------|
| HTTP Endpoints | duration, status codes | method, path | Active |
| Router Dispatch | dispatch time, exceptions | route | Active |
| WebSockets | connection duration | - | Active |
| LiveView | event duration, component renders | event | Active |
| Ecto/DB | query duration, pool usage | repo, table | Active |
| VM/BEAM | memory, run queues, GC | - | Active |

### 9.2 Business Metrics
| Category | Metric | Status |
|----------|--------|--------|
| Signups | Total, by source, by domain, milestones | Active |
| Feedback | Submissions by type | Active |
| Conversions | By type tracking | Active |
| Validation/Cache | Hit rate, response times, false positives | Active |
| Billing | Subscriptions, payments, revenue, credits | Active |
| Onboarding | Success rate, duration, failure reasons | Active |
| Rate Limiting | Limit exceeded, request allowed (disabled) | Partial |

### 9.3 Infrastructure Metrics
| Category | Metric | Status |
|----------|--------|--------|
| Uptime | Site availability | Active |
| Response Time | P95 latency tracking | Active |
| SSL Certs | Expiry monitoring | Active |
| Node Health | Cluster topology, node up/down events | Active |

---

## 10. Known Gaps & Limitations

### 10.1 Disabled Components
1. **Rate Limiter Plugin** - Disabled due to metric name format issues
   - File: `/lib/rsolv/prom_ex/rate_limiter_plugin.ex`
   - Issue: Referenced in TODO comment in application.ex
   - Impact: No visibility into rate limiting performance
   - Dashboard: Available but unused

2. **Future Frontend Metrics** - Not yet implemented
   - Validation test generation workflow (frontend)
   - Mitigation workflow (frontend)
   - Trust score metrics
   - Metric definitions exist but no data flow

### 10.2 Missing Integrations
- **No APM**: New Relic, DataDog, Honeycomb, Splunk, etc.
- **No Custom Alerting**: Only Kubernetes uptime monitoring
- **No Application Performance Monitoring**: Beyond PromEx metrics
- **No Distributed Tracing**: No OpenTelemetry integration
- **No Real User Monitoring**: No browser performance metrics

### 10.3 Configuration Gaps
- **Grafana Auth Token**: Currently required but may be empty
- **Metrics Endpoint Security**: No authentication on `/metrics` endpoint
- **Dashboard Persistence**: Depends on ConfigMap (could be lost)
- **Metrics Retention**: Not configured (depends on Prometheus storage)

### 10.4 Feature Flags Requiring Dashboard Setup
- `:metrics_dashboard` - Must be enabled in features table to view
- `:admin_dashboard` - Required for admin access
- Authentication pipeline required for all dashboards

---

## 11. Deployment & Infrastructure Context

### 11.1 Kubernetes Deployment
- Pod labels for Prometheus scraping
- Headless service for DNS clustering
- Pod name injection via environment variables
- Service discovery via Kubernetes DNS

### 11.2 Configuration Management
- Environment variables for Grafana connection
- SENTRY_DSN optional for error tracking
- ENABLE_PROMETHEUS_METRICS feature flag
- Rate limit configuration
- AI provider credentials

### 11.3 Application Startup
1. Ensure Hackney is started (HTTP client)
2. Create required directories (database-backed now)
3. Set up Prometheus metrics collection (`PrometheusExPlug.setup()`)
4. Start supervision tree including:
   - Ecto repository
   - Telemetry supervisor
   - PromEx (metrics)
   - Oban (background jobs)
   - Cluster manager
   - Security services
   - Custom services (rate limiter, AST, etc.)

---

## 12. Recommendations for New Metrics

### 12.1 Quick Wins
1. **Fix & Enable Rate Limiter Plugin**
   - Resolve metric name format issues
   - Would provide immediate rate limiting visibility

2. **Implement Frontend Metrics**
   - Add telemetry events in validation/mitigation workflows
   - Wire up JavaScript SDK for browser metrics
   - Track user interaction timing

3. **Add Distributed Tracing**
   - OpenTelemetry integration for request tracing
   - Would show end-to-end latency paths
   - Help identify bottlenecks

### 12.2 Medium-term Enhancements
1. **Custom Alerting**
   - Beyond uptime monitoring
   - Business metric alerts (low conversion rate, high failures)
   - Performance degradation detection

2. **APM Integration**
   - New Relic, DataDog, or AppSignal
   - Would add rich context to metrics
   - Error correlation with performance

3. **Retention Policies**
   - Configure Prometheus retention
   - Archive historical data to long-term storage
   - Set up metrics downsampling

### 12.3 Advanced Observability
1. **Real User Monitoring**
   - Frontend SDK for browser metrics
   - User session correlation
   - Custom event tracking

2. **Advanced Analytics**
   - Behavioral cohort analysis
   - Retention/churn tracking
   - Customer value metrics

3. **Logs Integration**
   - Centralized log aggregation
   - Structured logging format
   - Log-to-metrics correlation

---

## 13. Key Files Reference

| Component | Location | Purpose |
|-----------|----------|---------|
| PromEx Config | `/lib/rsolv/prom_ex.ex` | Plugin registry & dashboard mappings |
| Validation Plugin | `/lib/rsolv/prom_ex/validation_plugin.ex` | RFC-060 metrics |
| Billing Plugin | `/lib/rsolv/prom_ex/billing_plugin.ex` | RFC-068 metrics |
| Onboarding Plugin | `/lib/rsolv/prom_ex/customer_onboarding_plugin.ex` | RFC-065 metrics |
| Rate Limiter Plugin | `/lib/rsolv/prom_ex/rate_limiter_plugin.ex` | Disabled, needs fix |
| Helpers | `/lib/rsolv/prom_ex/helpers.ex` | Tag extraction utilities |
| Validation Reporter | `/lib/rsolv/telemetry/validation_reporter.ex` | 60s metrics reporting |
| Metrics Service | `/lib/rsolv_web/services/metrics.ex` | HTTP/business metrics |
| PrometheusHelper | `/lib/rsolv_web/services/prometheus_helper.ex` | Conditional dependency loading |
| MetricsController | `/lib/rsolv_web/controllers/metrics_controller.ex` | `/metrics` endpoint |
| Telemetry | `/lib/rsolv_web/telemetry.ex` | Phoenix telemetry setup |
| App Config | `/lib/rsolv/application.ex` | Startup & supervision tree |
| Runtime Config | `/config/runtime.exs` | Environment variables |
| Test Config | `/config/test.exs` | PromEx disabled in tests |
| K8s Monitoring | `/monitoring/` | Prometheus, alerts, dashboards |
| Grafana Dashboards | `/priv/grafana_dashboards/` | Dashboard JSON definitions |

---

## Summary Statistics

| Metric | Count | Status |
|--------|-------|--------|
| **PromEx Plugins** | 5 | 3 active, 1 disabled, 1 future |
| **Built-in PromEx Plugins** | 5 | All active |
| **Grafana Dashboards** | 5+ | All uploaded automatically |
| **Telemetry Event Types** | 10+ | Actively tracked |
| **Custom Metrics** | 50+ | Across validation, billing, onboarding |
| **Kubernetes Alert Rules** | 10+ | Uptime, response time, SSL |
| **Feature Flags** | 3 | Dashboard access controls |
| **Monitoring Dependencies** | 4 | PromEx, Telemetry, LiveDashboard, Sentry |
| **Grafana Dashboards (UI)** | 2 | Admin dashboard + signup metrics |
| **Metrics Endpoints** | 2 | `:4021/metrics` + internal dashboards |

---

## Conclusion

The RSOLV platform has a **mature, production-ready monitoring infrastructure** built on industry-standard tools (Prometheus, Grafana). The system provides:

✅ **Comprehensive metrics collection** across application, infrastructure, and business domains
✅ **Multiple data visualization layers** (Grafana dashboards, admin UI, logs)
✅ **Automated deployment** with Kubernetes integration
✅ **Feature flag controls** for dashboard access
✅ **Error tracking** via Sentry (optional)
✅ **Cluster monitoring** for distributed deployments
✅ **Business metrics** deeply integrated (billing, onboarding, validation)

The main **opportunities for enhancement** are:
- Fix and enable the rate limiter plugin (quick win)
- Implement frontend metrics collection
- Add distributed tracing (OpenTelemetry)
- Integrate APM for deeper insights
- Set up custom business alerts beyond uptime

This provides a solid foundation for the next phase of observability work.
