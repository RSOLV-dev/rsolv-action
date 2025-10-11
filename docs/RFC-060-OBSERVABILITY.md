# RFC-060 Observability Implementation

**Status:** Implemented
**Created:** 2025-10-11
**Component:** Phase 5.2 - Backend Observability
**Related:** RFC-060 Phase 5.2 (#10 of 11)

## Overview

This document describes the observability implementation for RFC-060's validation and mitigation phases in the RSOLV platform backend (Elixir). This complements the frontend observability in RSOLV-action (Phase 5.1).

## Architecture

### Components

1. **PromEx ValidationPlugin** (`lib/rsolv/prom_ex/validation_plugin.ex`)
   - Custom PromEx plugin for validation/mitigation metrics
   - Integrates with Prometheus for metric collection
   - Exposes metrics via `/metrics` endpoint

2. **Telemetry Events** (`lib/rsolv/phases.ex`)
   - Emits telemetry events when validation/mitigation data is stored
   - Captures duration, success rates, and metadata
   - Provides granular test-level metrics when available

3. **Grafana Dashboard** (`priv/grafana_dashboards/rfc-060-validation-metrics.json`)
   - 10+ visualization panels
   - Real-time monitoring of validation/mitigation health
   - Supports filtering by language and repository

4. **Prometheus Alerts** (`config/prometheus/rfc-060-alerts.yml`)
   - 9 alert rules for proactive monitoring
   - Tiered severity (info, warning, critical)
   - Actionable runbook links

## Metrics

### Validation Metrics

#### Counters
- `rsolv.validation.executions.total` - Total validation executions
  - Tags: `repo`, `language`, `framework`, `status`
- `rsolv.validation.test_generated.total` - Total tests generated
  - Tags: `repo`, `language`, `framework`, `test_type`
- `rsolv.validation.test_executed.total` - Total tests executed
  - Tags: `repo`, `language`, `framework`, `result`

#### Histograms/Distributions
- `rsolv.validation.test_generation.duration.milliseconds` - Test generation duration
  - Buckets: 10ms - 30s
- `rsolv.validation.test_execution.duration.milliseconds` - Test execution duration
  - Buckets: 100ms - 60s
- `rsolv.validation.total.duration.milliseconds` - Total validation phase duration
  - Buckets: 1s - 5min

#### Gauges
- `rsolv.validation.success_rate.percent` - Validation success rate (0-100)
- `rsolv.validation.tests_generated.count` - Number of tests generated
- `rsolv.validation.tests_passed.count` - Number of tests passed
- `rsolv.validation.tests_failed.count` - Number of tests failed

### Mitigation Metrics

#### Counters
- `rsolv.mitigation.executions.total` - Total mitigation executions
  - Tags: `repo`, `language`, `framework`, `status`
- `rsolv.mitigation.pr_created.total` - Total PRs created
  - Tags: `repo`, `language`, `framework`

#### Histograms/Distributions
- `rsolv.mitigation.total.duration.milliseconds` - Total mitigation duration
  - Buckets: 1s - 10min
- `rsolv.mitigation.trust_score.value` - Trust score distribution
  - Buckets: 0, 25, 50, 60, 70, 80, 90, 95, 100

#### Gauges
- `rsolv.mitigation.trust_score.latest` - Latest trust score (0-100)

## Telemetry Events

### Event Structure

All telemetry events follow the pattern: `[:rsolv, :phase, :event]`

#### Validation Events

**`[:rsolv, :validation, :complete]`**
- **When**: After validation execution is stored
- **Measurements**:
  - `duration` - Total duration in milliseconds
  - `tests_generated` - Number of tests generated
  - `tests_passed` - Number of tests passed
  - `tests_failed` - Number of tests failed
  - `success_rate` - Success rate percentage
- **Metadata**:
  - `repo` - Repository identifier
  - `language` - Programming language
  - `framework` - Test framework
  - `status` - Execution status (`:completed`, `:failed`)
  - `validated` - Whether validation passed (boolean)

**`[:rsolv, :validation, :test_generated]`**
- **When**: For each test in `test_details` array (if provided)
- **Measurements**:
  - `duration` - Test generation duration in milliseconds
- **Metadata**:
  - `repo`, `language`, `framework`
  - `test_type` - Type of test (e.g., "unit", "integration")

**`[:rsolv, :validation, :test_executed]`**
- **When**: For each test execution in `test_details` array (if provided)
- **Measurements**:
  - `duration` - Test execution duration in milliseconds
- **Metadata**:
  - `repo`, `language`, `framework`
  - `result` - Test result (e.g., "passed", "failed")

#### Mitigation Events

**`[:rsolv, :mitigation, :complete]`**
- **When**: After mitigation execution is stored
- **Measurements**:
  - `duration` - Total duration in milliseconds
- **Metadata**:
  - `repo`, `language`, `framework`
  - `status` - Execution status
  - `pr_created` - Whether a PR was created (boolean)

**`[:rsolv, :mitigation, :pr_created]`**
- **When**: When a mitigation PR is created
- **Measurements**:
  - `count` - Always 1
- **Metadata**:
  - `repo`, `language`, `framework`

**`[:rsolv, :mitigation, :trust_score]`**
- **When**: When trust score is available in mitigation data
- **Measurements**:
  - `trust_score` - Trust score value (0-100)
- **Metadata**:
  - `repo`, `language`, `framework`

## Data Format

### Expected Data Structure

When storing validation/mitigation data via the Phases API, include the following fields for observability:

#### Validation Data (`POST /api/v1/phases/validation`)

```json
{
  "repo": "owner/repo",
  "issue_number": 123,
  "commit_sha": "abc123...",
  "data": {
    "language": "javascript",
    "framework": "jest",
    "tests_generated": 3,
    "tests_passed": 2,
    "tests_failed": 1,
    "validated": true,
    "test_details": [
      {
        "type": "unit",
        "generation_duration": 2500,
        "execution_duration": 1200,
        "result": "passed"
      },
      {
        "type": "integration",
        "generation_duration": 3200,
        "execution_duration": 4500,
        "result": "failed"
      }
    ]
  }
}
```

#### Mitigation Data (`POST /api/v1/phases/mitigation`)

```json
{
  "repo": "owner/repo",
  "issue_number": 123,
  "commit_sha": "def456...",
  "data": {
    "language": "javascript",
    "framework": "jest",
    "pr_url": "https://github.com/owner/repo/pull/456",
    "pr_number": 456,
    "files_changed": 3,
    "trust_score": 85
  }
}
```

## Alerts

### Alert Levels

1. **Critical** - Requires immediate action, may indicate system failure
2. **Warning** - Requires attention within hours, indicates degraded performance
3. **Info** - Informational, no immediate action required

### Alert Rules

| Alert | Severity | Condition | Duration | Action |
|-------|----------|-----------|----------|--------|
| ValidationSuccessRateCritical | Critical | Success rate < 25% | 10 min | Check logs, verify dependencies, consider rollback |
| ValidationSuccessRateLow | Warning | Success rate < 50% | 15 min | Review logs, check for failure patterns |
| MitigationTrustScoreLow | Warning | Avg trust score < 60 | 24 hours | Review PR quality, check AI provider |
| ValidationExecutionsStalled | Info | No executions in 1h | 1 hour | Verify expected, check workflow triggers |
| TestGenerationDurationHigh | Warning | p95 > 30s | 20 min | Check AI provider latency |
| TestExecutionDurationHigh | Warning | p95 > 60s | 20 min | Check test runner resources |
| HighValidationFailureRateByRepo | Warning | Per-repo failure > 50% | 30 min | Review repo-specific issues |
| MitigationDurationHigh | Warning | p95 > 5min | 30 min | Check AI provider, GitHub API |
| NoPRsCreated | Warning | 0 PRs in 24h with activity | 30 min | Check mitigation phase, verify auth |

### Alert Routing (Example)

Configure in `alertmanager.yml`:

```yaml
route:
  group_by: ['rfc', 'component']
  receiver: 'rfc-060-team'
  routes:
    - match:
        severity: critical
      receiver: 'rfc-060-oncall-pagerduty'
    - match:
        severity: warning
      receiver: 'rfc-060-team-slack'
    - match:
        severity: info
      receiver: 'rfc-060-team-email'
```

## Grafana Dashboard

### Panels

The dashboard includes 10 visualization panels:

1. **Validation Success Rate** (Stat) - Overall health indicator
2. **Validation Executions (Total)** (Stat) - Activity level
3. **Average Trust Score** (Gauge) - Mitigation quality
4. **Mitigation PRs Created (24h)** (Stat) - Output metric
5. **Validation Success Rate Over Time** (Graph) - Trend by language
6. **Test Generation Duration** (Heatmap) - Performance distribution
7. **Test Execution Duration** (Heatmap) - Performance distribution
8. **Trust Score Distribution** (Graph) - Quality percentiles
9. **Validation Executions by Language** (Pie Chart) - Language breakdown
10. **Failed Validations** (Table) - Top failures for investigation
11. **Total Validation Duration** (Graph) - p50/p95/p99 latency
12. **Mitigation Duration** (Graph) - p50/p95/p99 latency

### Access

- **URL**: `https://grafana.rsolv.dev/d/rfc-060-validation`
- **Refresh**: 30 seconds
- **Time Range**: Last 6 hours (default)
- **Variables**:
  - `language` - Filter by programming language
  - `repo` - Filter by repository

## Deployment

### Local Testing

1. **Start the application**:
   ```bash
   cd ~/dev/rsolv
   mix phx.server
   ```

2. **Trigger a validation/mitigation** (via RSOLV-action or API)

3. **Check metrics endpoint**:
   ```bash
   curl http://localhost:4000/metrics | grep rsolv_validation
   ```

4. **Verify telemetry events** (check logs):
   ```
   [info] Telemetry event: [:rsolv, :validation, :complete]
   ```

### Staging Deployment

1. **Deploy to staging**:
   ```bash
   # From rsolv-infrastructure repo
   cd ~/dev/rsolv-infrastructure
   ./deploy.sh staging
   ```

2. **Verify metrics are collecting**:
   ```bash
   curl https://api-staging.rsolv.dev/metrics | grep rsolv_validation
   ```

3. **Check Grafana dashboard**:
   - Navigate to staging Grafana instance
   - Select "RFC-060 Validation & Mitigation Metrics" dashboard
   - Verify panels are populating with data

4. **Test alerts** (optional):
   ```bash
   # Trigger a test alert by simulating low success rate
   # This requires access to Prometheus/Alertmanager
   ```

### Production Deployment

Follow the standard deployment process documented in `rsolv-infrastructure/DEPLOYMENT.md`:

1. Test on staging first (required)
2. Deploy to production during maintenance window
3. Monitor metrics and alerts for 24 hours
4. Verify dashboard is accessible to the team

## Monitoring Best Practices

### What to Monitor

1. **Success Rate** - Primary health indicator
   - Target: > 75%
   - Warning: < 50%
   - Critical: < 25%

2. **Trust Score** - Fix quality indicator
   - Target: > 80
   - Warning: < 60 for 24h

3. **Duration** - Performance indicator
   - Validation p95: < 30s generation, < 60s execution
   - Mitigation p95: < 5 minutes

4. **Volume** - Activity indicator
   - Normal: Varies by customer usage
   - Concern: 0 executions for > 1 hour during expected activity

### Response Procedures

1. **Critical Alert Received**
   - Acknowledge alert immediately
   - Check dashboard for context
   - Review recent deployments/changes
   - Check error logs in platform and action
   - Escalate if issue persists > 30 minutes

2. **Warning Alert Received**
   - Review within 1 hour
   - Investigate root cause
   - Document findings
   - Create ticket if ongoing issue

3. **Info Alert Received**
   - Review within 24 hours
   - Verify if expected behavior
   - Update alert thresholds if needed

## Integration with RSOLV-action

This backend observability complements the frontend observability in RSOLV-action (Phase 5.1):

- **RSOLV-action**: Tracks test generation, execution, and fix application at the GitHub Action level
- **RSOLV-platform**: Tracks data storage, API calls, and aggregate metrics at the platform level

Both systems emit metrics that can be correlated for end-to-end observability.

## Files Created

- `lib/rsolv/prom_ex/validation_plugin.ex` - PromEx plugin for metrics
- `priv/grafana_dashboards/rfc-060-validation-metrics.json` - Grafana dashboard
- `config/prometheus/rfc-060-alerts.yml` - Prometheus alert rules
- `docs/RFC-060-OBSERVABILITY.md` - This documentation

## Files Modified

- `lib/rsolv/phases.ex` - Added telemetry emission
- `lib/rsolv/prom_ex.ex` - Enabled ValidationPlugin and dashboard

## Success Criteria

- [x] PromEx ValidationPlugin created with validation metrics
- [x] Telemetry events emitting from Phases context
- [x] Grafana dashboard with 10+ panels
- [x] 9+ Prometheus alerts configured with runbooks
- [ ] Metrics visible in staging environment
- [ ] Dashboard accessible and showing data
- [ ] Alerts firing correctly (test with simulated failures)
- [ ] Documentation complete

## Next Steps

1. Deploy to staging and verify metrics collection
2. Test alert rules with simulated failures
3. Review dashboard with team for usability feedback
4. Iterate on panel layouts and alert thresholds based on real data
5. Deploy to production as part of RFC-060 Phase 5.3

## References

- [RFC-060: Executable Validation Test Integration](../RFCs/RFC-060-ENHANCED-VALIDATION-TEST-PERSISTENCE.md)
- [PromEx Documentation](https://hexdocs.pm/prom_ex/)
- [Telemetry Documentation](https://hexdocs.pm/telemetry/)
- [Grafana Documentation](https://grafana.com/docs/)
- [Prometheus Alerting](https://prometheus.io/docs/prometheus/latest/configuration/alerting_rules/)
