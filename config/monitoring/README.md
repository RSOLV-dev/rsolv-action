# Test Monitoring Dashboard Configuration

Configuration for monitoring CI/CD test execution, coverage, and quality metrics.

## Overview

This directory contains dashboard configurations for monitoring:
- Test execution results (pass/fail)
- Test coverage percentages
- Test execution duration
- Flaky test detection
- Migration integrity
- Code quality metrics
- Security test status
- Load test results

## Dashboards

### CI Dashboard (`ci_dashboard.json`)

Primary dashboard for CI/CD monitoring. Tracks:

**Test Results:**
- Overall pass/fail status
- Test count trends (total, passed, failed, skipped)
- Flaky test detection (zero tolerance)

**Performance:**
- Test suite duration (target: < 5 minutes)
- Parallel execution balance across partitions
- Load test results (k6 metrics)

**Quality:**
- Test coverage percentage (80% minimum, 95% aspirational)
- Credo warnings count
- Migration integrity

**Security:**
- Security test status
- PCI compliance test results
- Webhook signature validation tests

## Metrics Sources

### Prometheus Pushgateway

CI/CD metrics are exported to Prometheus via Pushgateway. This allows GitHub Actions workflows to push metrics to Prometheus even though they run externally.

**URLs:**
- **Production:** `https://pushgateway.rsolv.dev` (also available at `https://pushgateway.rsolv.ai`)
- **Staging:** `https://pushgateway.rsolv-staging.com`
- **Local/Docker Compose:** `http://pushgateway:9091`

**Authentication:** All endpoints require HTTP Basic Authentication. Credentials are stored in:
- Kubernetes: `pushgateway-auth` secret in each namespace
- GitHub: `PUSHGATEWAY_USERNAME` and `PUSHGATEWAY_PASSWORD` repository secrets

**Configuration:**
The workflow defaults to the production URL (`https://pushgateway.rsolv.dev`). To override:
```bash
gh secret set PUSHGATEWAY_URL --body "https://pushgateway.rsolv-staging.com"
```

**Deployment Status:**
- ✅ Production: Deployed to `rsolv-monitoring` namespace (2025-10-30)
- ✅ Staging: Deployed to `rsolv-monitoring-staging` namespace (2025-10-29)

See `docs/PUSHGATEWAY-DEPLOYMENT.md` for deployment instructions and `docs/PUSHGATEWAY-SECURITY.md` for security configuration.

### GitHub Actions Metrics

Exported via GitHub Actions workflow runs to Pushgateway:

```yaml
- name: Export metrics
  run: |
    cat <<EOF | curl --data-binary @- ${PUSHGATEWAY_URL}/metrics/job/ci/workflow/${GITHUB_WORKFLOW}
    github_actions_workflow_run_duration_seconds{workflow="${GITHUB_WORKFLOW}"} ${{ job.duration }}
    github_actions_workflow_run_conclusion{workflow="${GITHUB_WORKFLOW}"} ${{ job.conclusion == 'success' && '0' || '1' }}
    EOF
```

### ExUnit Metrics

Exported from test suite via custom formatter:

```elixir
# config/test.exs
config :rsolv, :test_metrics, enabled: true

# In test helper:
ExUnit.configure(formatters: [ExUnit.CLIFormatter, Rsolv.TestMetricsFormatter])
```

### Coverage Metrics

From ExCoveralls:

```bash
mix coveralls.json
# Exports coverage_percentage metric
```

### k6 Load Test Metrics

k6 exports metrics in various formats:

```bash
# JSON output
k6 run --out json=load_tests/results/signup_test.json load_tests/signup_test.js

# InfluxDB (for Grafana)
k6 run --out influxdb=http://localhost:8086/k6 load_tests/signup_test.js

# Prometheus
k6 run --out experimental-prometheus-rw load_tests/signup_test.js
```

## Alerts

### Critical Alerts

- **CI Pipeline Failure** - Immediate notification
- **Flaky Tests Detected** - Zero tolerance policy
- **Security Test Failure** - Immediate security team notification
- **Migration Failure** - Database integrity risk

### Warning Alerts

- **Coverage Below Threshold** - Quality degradation
- **Test Suite Too Slow** - Performance degradation

## Setup

### 1. Install Monitoring Stack

#### Kubernetes (Production/Staging)

The monitoring stack (Prometheus, Grafana, Pushgateway) is deployed to Kubernetes. See the main infrastructure documentation at `~/dev/rsolv/RSOLV-infrastructure/` for deployment details.

To deploy Pushgateway:

```bash
# Deploy to staging
kubectl apply -f config/monitoring/pushgateway.yaml --namespace monitoring --context staging

# Deploy to production
kubectl apply -f config/monitoring/pushgateway.yaml --namespace monitoring --context production

# Verify deployment
kubectl get pods -n monitoring -l app=pushgateway
kubectl get service -n monitoring pushgateway
```

#### Local Development

For local development with Docker Compose:

```bash
# Prometheus
docker run -p 9090:9090 -v ./config/monitoring/prometheus.yml:/etc/prometheus/prometheus.yml prom/prometheus

# Grafana
docker run -p 3000:3000 grafana/grafana-oss

# Pushgateway
docker run -p 9091:9091 prom/pushgateway:v1.9.0
```

### 2. Configure Data Sources

In Grafana:
1. Add Prometheus data source: http://localhost:9090
2. Add GitHub Actions integration
3. Configure Coveralls webhook

### 3. Import Dashboard

```bash
# Via Grafana UI
Dashboard → Import → Upload config/monitoring/ci_dashboard.json

# Via API
curl -X POST http://admin:admin@localhost:3000/api/dashboards/db \
  -H "Content-Type: application/json" \
  -d @config/monitoring/ci_dashboard.json
```

### 4. Configure Alerts

Update notification channels in `ci_dashboard.json`:

```json
{
  "alerts": [
    {
      "name": "CI Pipeline Failure",
      "notify": ["slack:#alerts-ci", "email:team@example.com"]
    }
  ]
}
```

## Customization

### Adding New Panels

1. Edit `ci_dashboard.json`
2. Add panel configuration:

```json
{
  "id": "custom-panel",
  "title": "Custom Metric",
  "type": "graph",
  "targets": [
    {
      "metric": "custom_metric_name",
      "labels": {}
    }
  ]
}
```

3. Reload dashboard in Grafana

### Adding New Alerts

1. Define alert condition in `ci_dashboard.json`
2. Configure notification channels
3. Test alert by triggering condition

## Integration with CI

### GitHub Actions

Export metrics from workflow to Pushgateway:

```yaml
- name: Report metrics
  if: always()
  env:
    PUSHGATEWAY_URL: ${{ secrets.PUSHGATEWAY_URL || 'https://pushgateway.rsolv.dev' }}
  run: |
    # Export to Prometheus pushgateway
    cat <<EOF | curl --data-binary @- ${PUSHGATEWAY_URL}/metrics/job/ci/workflow/${GITHUB_WORKFLOW}
    test_duration_seconds{workflow="${GITHUB_WORKFLOW}"} $(date +%s)
    EOF
```

**Note:** The `test-monitoring.yml` workflow automatically exports metrics after the main CI workflow completes. See `.github/workflows/test-monitoring.yml` for the full implementation.

### Coveralls

Automatic via GitHub Action:

```yaml
- name: Upload coverage to Coveralls
  uses: coverallsapp/github-action@v2
  with:
    github-token: ${{ secrets.GITHUB_TOKEN }}
```

### k6 Load Tests

Run in CI and export metrics:

```yaml
- name: Run load tests
  run: |
    k6 run --out json=load_tests/results/results.json \
           --out influxdb=http://influxdb:8086/k6 \
           load_tests/signup_test.js
```

## Accessing Dashboards

- **Grafana**: http://localhost:3000 (local) or https://grafana.rsolv.dev (staging)
- **Prometheus**: http://localhost:9090
- **Default credentials**: admin / admin (change on first login)

## Success Metrics

Track these KPIs in the dashboard:

- **CI Speed**: < 5 minutes (target)
- **Test Coverage**: 80% minimum, 95% aspirational
- **Flaky Tests**: 0 (zero tolerance)
- **Security Tests**: 100% passing
- **Load Test P95**: < 500ms (signup), < 200ms (webhooks)

## Maintenance

- Review dashboard weekly for trends
- Update thresholds as system evolves
- Add new panels for new test categories
- Archive outdated metrics

## See Also

- [RFC-068: Billing Testing Infrastructure](../../RFCs/RFC-068-BILLING-TESTING-INFRASTRUCTURE.md)
- [Security Testing Checklist](../../test/security/SECURITY_TESTING_CHECKLIST.md)
- [Load Testing README](../../load_tests/README.md)
