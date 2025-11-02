# RFC-079: Alert Configuration Review and Optimization

**RFC Number**: 079
**Title**: Alert Configuration Review and Optimization
**Author**: RSOLV Team
**Status**: Draft
**Created**: 2025-11-01
**Priority**: Medium
**Dependencies**: RFC-077 (Tailwind Syntax Template Adoption)

## Summary

Following an alert email flood incident on 2025-11-01, this RFC proposes a comprehensive review and optimization of the RSOLV monitoring and alerting infrastructure. The immediate incident has been resolved through emergency changes, but a systematic review is needed to prevent future issues and improve alert quality.

## Context

### Incident Overview (2025-11-01)

After charging the Postmark account, the platform began sending excessive alert emails to `alerts@rsolv.dev`. Investigation revealed:

1. **Root Cause**: `RSOLVBlogDown` alert firing continuously due to blog returning HTTP 404
2. **Contributing Factors**:
   - 3 AlertManager instances running (monitoring, rsolv-monitoring-staging, rsolv-monitoring)
   - Alert fired 1,440 times in 12 hours
   - Estimated 72-144 emails/day
3. **Secondary Issues**:
   - `ValidationExecutionsStalled` alert too noisy during normal low-activity periods
   - Multiple alert rules with overly sensitive thresholds
   - Duplicate monitoring infrastructure

### Emergency Changes Applied

1. Disabled all AlertManager instances temporarily
2. Fixed blog 404 issue (feature flag not enabled)
3. Restored missing fonts causing styling issues
4. Updated AlertManager configuration:
   - Increased `group_wait` to 1m
   - Increased `group_interval` to 15m
   - Increased `repeat_interval` to 4h (warnings)
   - Disabled `send_resolved` to reduce volume
   - Email to `alerts@rsolv.dev`
5. Disabled `ValidationExecutionsStalled` alert (too noisy)
6. Re-enabled production AlertManager only

### Documentation Created

- `ALERT-FLOOD-ANALYSIS-2025-11-01.md` - Comprehensive configuration analysis
- `ALERT-FIRE-HISTORY-2025-11-01.md` - What actually fired during incident

## Motivation

1. **Prevent Alert Fatigue**: Current configuration can flood inboxes during incidents
2. **Improve Signal-to-Noise**: Many alerts fire during normal operation
3. **Reduce Operational Costs**: Excessive email volume impacts Postmark budget
4. **Infrastructure Consolidation**: Remove duplicate monitoring stacks
5. **Better Alert Routing**: Different severities should go to different channels

## Proposed Solution

### Phase 1: Infrastructure Consolidation

**Namespaces to Keep**:
- `monitoring` - Production alerts
- `rsolv-monitoring-staging` - Staging alerts

**Namespaces to Remove**:
- `rsolv-monitoring` - Duplicate production stack (already scaled to 0)
- `default` (alert configs) - Orphaned signup celebration alerts

**Actions**:
1. Verify no dependencies on `rsolv-monitoring` namespace
2. Delete namespace: `kubectl delete namespace rsolv-monitoring`
3. Remove unused ConfigMaps in `default` namespace:
   - `prometheus-signup-rules`
   - `alertmanager-signup-config`

### Phase 2: Alert Rule Review

Review all alert rules across categories:

#### RFC-060 Validation Alerts (9 rules)

**Critical Priority** (keep as-is):
- `ValidationSuccessRateCritical` - <25% for 10m
- Severity: critical, Threshold: Appropriate

**Medium Priority** (adjust thresholds):
- `ValidationSuccessRateLow` - <50% for 15m → **Recommend**: <30% for 2h
- `TestGenerationDurationHigh` - >30s for 20m → **Recommend**: >60s for 1h
- `TestExecutionDurationHigh` - >60s for 20m → **Recommend**: >120s for 1h
- `MitigationDurationHigh` - >5m for 30m → **Recommend**: >10m for 1h

**Low Priority** (consider disabling):
- `MitigationTrustScoreLow` - <60 for 24h (very rare to fire)
- `NoPRsCreated` - 0 for 24h (weekends/holidays normal)
- `HighValidationFailureRateByRepo` - May be repository-specific issue

**Already Disabled**:
- ✅ `ValidationExecutionsStalled` - Disabled 2025-11-01 (too noisy)

#### AST Validation Alerts (7 rules)

From `prometheus-rules-ast-validation` ConfigMap - needs review for similar threshold issues.

#### Uptime Alerts (5 rules)

**Keep**:
- `RSOLVMainSiteDown` - Critical, 2m threshold (appropriate)
- `RSOLVBlogDown` - Warning, 5m threshold (may increase to 15m)
- `RSOLVHighResponseTime` - >3s for 5m (reasonable)
- `RSOLVSSLCertificateExpiringSoon` - <7 days (appropriate)

**Review**:
- `TestResolveAlert` - No 'for' duration, fires immediately (test only - disable in prod)

#### System & Application Alerts

- `HighCPUUsage` - >80% for 5m (reasonable)
- `HighErrorRate` - >5% for 5m (reasonable)
- `SignupDropOff` - >50% decrease for 6h (low priority)

### Phase 3: Alert Routing Strategy

Implement severity-based routing:

```yaml
route:
  group_by: ['alertname', 'severity', 'instance']
  group_wait: 1m
  group_interval: 15m
  repeat_interval: 4h
  receiver: 'default-email'

  routes:
    # Critical: Email immediately
    - match:
        severity: critical
      receiver: 'critical-email'
      group_wait: 30s
      repeat_interval: 1h

    # Warning: Email with longer intervals
    - match:
        severity: warning
      receiver: 'warning-email'
      group_wait: 1m
      repeat_interval: 4h

    # Info: Consider Slack or daily digest
    - match:
        severity: info
      receiver: 'info-slack'  # Future: Implement Slack integration
      repeat_interval: 24h

receivers:
  - name: 'critical-email'
    email_configs:
      - to: 'alerts@rsolv.dev'
        send_resolved: true  # Important to know when resolved

  - name: 'warning-email'
    email_configs:
      - to: 'alerts@rsolv.dev'
        send_resolved: false  # Reduce volume

  - name: 'default-email'
    email_configs:
      - to: 'alerts@rsolv.dev'
        send_resolved: false
```

### Phase 4: Improved Alert Content

Update alert annotations to include:

1. **Clear Impact**: What does this mean for users/business?
2. **Actionable Steps**: Specific commands to run, dashboards to check
3. **Runbook Links**: Link to detailed troubleshooting guides
4. **Context**: What's normal vs abnormal for this metric

**Example**:
```yaml
- alert: ValidationSuccessRateLow
  annotations:
    summary: "Validation success rate below 30%"
    description: |
      **Current State**:
      - Success rate: {{ $value | humanizePercentage }}
      - Threshold: 30%
      - Duration: Last 2 hours

      **Impact**: Validation phase not functioning well, fewer fixes generated

      **Next Steps**:
      1. Check Grafana: https://grafana.rsolv.dev/d/rfc-060-validation
      2. Review recent deployments: `kubectl logs -n rsolv-production deployment/rsolv-platform`
      3. Check external dependencies (AI provider, test runners)

      **Runbook**: https://docs.rsolv.dev/runbooks/validation-success-rate-low
```

### Phase 5: Slack Integration (Optional)

Consider routing non-critical alerts to Slack:

1. Create `#rsolv-alerts` channel
2. Configure Slack webhook in AlertManager
3. Route `info` and some `warning` alerts to Slack
4. Keep `critical` for email

**Benefits**:
- Reduce email volume by ~70%
- Better for team collaboration on alerts
- Easier to mute during known maintenance

**Drawbacks**:
- Requires Slack workspace setup
- Another service dependency
- May miss alerts if Slack is down

## Implementation Plan

### Immediate (Post RFC-077)

1. **Week 1**: Infrastructure consolidation
   - Remove duplicate `rsolv-monitoring` namespace
   - Clean up unused ConfigMaps in `default`
   - Verify monitoring still works correctly

2. **Week 2**: Alert rule threshold adjustments
   - Update RFC-060 validation alert thresholds
   - Review and adjust AST validation alerts
   - Test alert changes in staging first

3. **Week 3**: Alert routing implementation
   - Update AlertManager configuration with severity-based routing
   - Test routing with manual alert triggers
   - Deploy to production

### Near-term (1-2 months)

4. **Week 4-5**: Alert content improvements
   - Write runbooks for all critical alerts
   - Update alert annotations with better context
   - Add links to Grafana dashboards

5. **Week 6-8**: Monitoring validation
   - Monitor alert volume for 2 weeks
   - Gather feedback on alert quality
   - Iterate on thresholds as needed

### Future (Optional)

6. **Slack Integration** (if needed)
   - Evaluate if email volume still too high
   - Set up Slack workspace and webhooks
   - Migrate info/warning alerts to Slack
   - Keep critical alerts on email

## Expected Outcomes

### Alert Volume Reduction

**Before** (estimated pre-incident normal state):
- 10-20 emails/day
- Mixture of critical and info alerts
- Potential for floods during incidents

**After Phase 3** (conservative estimate):
- Critical: 1-2 emails/day (only real issues)
- Warning: 2-4 emails/day (batched)
- Info: 0 emails (disabled or moved to Slack)
- **Total**: 3-6 emails/day (-70% reduction)

**After Slack Integration** (if implemented):
- Critical: 1-2 emails/day
- Warning: 0-1 emails/day (only severe)
- Info: Slack only
- **Total**: 1-3 emails/day (-85% reduction)

### Cost Impact

**Postmark Email Usage**:
- Current (post-fix): ~6 emails/day = 180/month (well within free tier)
- After optimization: ~3 emails/day = 90/month (excellent margin)
- No cost concern even with 10x growth

### Operational Impact

1. **Reduced Alert Fatigue**: Fewer, more meaningful alerts
2. **Faster Response**: Critical alerts stand out
3. **Better Context**: Improved alert content speeds diagnosis
4. **Lower Maintenance**: Consolidated infrastructure easier to manage

## Alternatives Considered

### 1. Keep Current Configuration

**Pros**:
- No work required
- Already applied emergency fixes

**Cons**:
- Still too noisy for some alerts
- Missed opportunity to improve
- Duplicate infrastructure waste

**Decision**: Rejected - systematic improvements needed

### 2. Disable Most Alerts

**Pros**:
- Eliminates alert fatigue
- No email costs

**Cons**:
- No visibility into production issues
- Incidents go unnoticed

**Decision**: Rejected - monitoring is critical

### 3. Use Only PagerDuty/Opsgenie

**Pros**:
- Enterprise-grade alerting
- Better on-call rotation
- Mobile apps

**Cons**:
- Additional cost ($29-49/user/month)
- Overkill for current team size
- More complexity

**Decision**: Deferred - consider when team grows

## Open Questions

1. **Slack Integration Priority**: Should we implement Slack routing in Phase 1 or wait?
   - **Recommendation**: Wait - see if email optimization is sufficient first

2. **Grafana Dashboard Access**: Do we have public Grafana dashboards for alert links?
   - **Action**: Verify Grafana is accessible or create read-only public dashboards

3. **Runbook Location**: Where should we store runbooks?
   - **Recommendation**: `RSOLV-infrastructure/shared/monitoring/runbooks/`

4. **Alert Testing**: How do we test alert changes without spamming production?
   - **Recommendation**: Use staging AlertManager first, then manual triggers in prod

5. **Historical Alert Data**: Should we retain firing history for analysis?
   - **Recommendation**: Prometheus retains 15 days, sufficient for now

## Success Metrics

1. **Alert Volume**: <5 emails/day to `alerts@rsolv.dev`
2. **False Positive Rate**: <10% of alerts require no action
3. **Response Time**: Critical alerts acted on within 15 minutes
4. **Alert Quality**: >90% of alerts provide sufficient context for action
5. **Infrastructure**: Single production and single staging AlertManager

## References

- **Emergency Changes**: `ALERT-FLOOD-ANALYSIS-2025-11-01.md`
- **Incident History**: `ALERT-FIRE-HISTORY-2025-11-01.md`
- **AlertManager Config**: `RSOLV-infrastructure/shared/monitoring/alertmanager-postmark-config.yaml`
- **RFC-060**: Validation/mitigation monitoring architecture
- **RFC-036**: AST validation monitoring
- **Prometheus Documentation**: https://prometheus.io/docs/alerting/latest/
- **AlertManager Documentation**: https://prometheus.io/docs/alerting/latest/alertmanager/

## Timeline

- **Draft**: 2025-11-01
- **Review**: After RFC-077 completion
- **Implementation Start**: Post RFC-077
- **Target Completion**: 8 weeks from start

## Related Work

- **RFC-060**: Established validation monitoring metrics
- **RFC-036**: Established AST validation monitoring
- **RFC-077**: Tailwind Syntax Template Adoption (prerequisite)

## Appendix A: Current Alert Inventory

### By Namespace

**monitoring** (Production):
- 4 uptime alerts
- 9 RFC-060 validation/mitigation alerts
- 7 AST validation alerts (needs review)
- 4 application/system alerts
- 1 business alert
- **Total**: ~25 alert rules

**default** (Orphaned):
- 3 signup celebration alerts (to be removed)

**rsolv-monitoring-staging** (Staging):
- Similar to production (appropriate for staging)

**rsolv-monitoring** (Duplicate):
- To be removed

### By Severity

| Severity | Count | Current Repeat | Proposed Repeat |
|----------|-------|----------------|-----------------|
| critical | ~8 | 5m-1h | 30m-1h |
| warning | ~15 | 15m-4h | 1h-4h |
| info | ~7 | 0s-24h | 24h or Slack |

## Appendix B: Estimated Alert Frequency

Based on analysis of Prometheus metrics (when platform is healthy):

| Alert | Avg Fires/Week | Notes |
|-------|----------------|-------|
| RSOLVBlogDown | 0 | Only during incidents |
| RSOLVMainSiteDown | 0 | Only during incidents |
| ValidationSuccessRateLow | 2-3 | During deployment windows |
| TestGenerationDurationHigh | 1-2 | AI provider latency spikes |
| HighCPUUsage | 1 | Traffic spikes |
| All Others | <1 | Rare or never |

**Total Expected**: 4-7 alerts/week = ~1/day (healthy state)

During incidents, this can spike to 100+/day (as seen with blog 404).
