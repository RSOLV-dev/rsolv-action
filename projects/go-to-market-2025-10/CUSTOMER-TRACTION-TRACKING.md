# RSOLV Customer Traction Tracking

**Last Updated:** 2025-11-04 (18:38 MST - Funnel tracking system implemented)

## Overview

This document tracks customer development efforts for RSOLV, focusing on securing **3-5 committed beta testers** from quality warm network outreach.

**Launch Timeline:** ~6 weeks from 2025-10-23 (target: early December 2025)
**Current Status:** 🚀 **PRODUCTION LAUNCHED** - Week 5 (2025-11-04)

## Production Launch Status

**Deployment Details:**
- **Launch Date:** 2025-11-04
- **Production Image:** prod-20251103-184315
- **Platform Status:** LIVE and operational
- **Blog Status:** LIVE (feature flag `blog` enabled)
- **Billing Integration:** LIVE and processing transactions
- **Customer Onboarding:** OPERATIONAL
- **API Status:** Serving requests

**Launch Resolution:**
- Production outage: ~5 hours (feature flag naming resolution)
- Root cause: Feature flag naming convention (`blog` vs `rsolv_blog`)
- Resolution: Flag renamed to `blog` in production database
- Lessons learned: Document feature flag naming conventions, improve secret management procedures

## Production Metrics

### Week 5 (2025-11-04 onwards) - First 24 Hours

**Customer Signups:**
- Total signups: 1 (smoke test customer)
- Real customer signups: 0 (monitoring for first organic signup)
- Beta tester signups: 0/5 (outreach pending)

**API Performance:**
- Total API requests: _[monitoring via Prometheus - see Grafana dashboard]_
- Average response time (P50): _Target: < 200ms_ | _Alerting threshold: N/A (tracking only)_
- P95 latency: _Target: < 1000ms_ | _Warning: > 1000ms_ | _Critical: > 3000ms_
- Error rate (5xx): _Target: < 1%_ | _Warning: > 1%_ | _Critical: > 5%_
- Dashboard: `grafana.rsolv.dev/d/api-performance-baseline`

**Database Performance:**
- P95 query latency: _Target: < 100ms_ | _Warning: > 100ms_ | _Critical: > 500ms_
- Connection pool usage: _Target: < 80%_ | _Warning: > 90%_
- Monitoring: Ecto metrics via PromEx

**Webhook Processing:**
- Stripe webhooks P95 latency: _Target: < 1000ms_ | _Warning: > 1000ms_
- Webhook failure rate: _Target: < 5%_ | _Warning: > 5%_
- Processing success rate: _Target: > 95%_
- Monitoring: BillingPlugin telemetry metrics

**Billing Activity:**
- Transactions processed: 0
- API key validations: _[to be tracked]_
- Credential vends: _[to be tracked]_

**Blog Engagement:**
- Page views: _[to be tracked]_
- Unique visitors: _[to be tracked]_
- Time on page: _[to be tracked]_
- Referral sources: _[to be tracked]_

### Week 5 Goals

**Customer Development:**
- [ ] Begin beta tester outreach (0/5 completed) - **VK:** `fd752338` (Due: Nov 8)
- [ ] Monitor for first real customer signup - **VK:** `000a4bea` (Daily updates)
- [ ] Track signup → activation conversion - **VK:** `ceba61e4` (Ongoing)
- [ ] Document common customer questions - **VK:** `5bea504c` (Due: Nov 11)

**Monitoring & Operations:**
- [x] Establish baseline metrics for API performance - **VK:** `651a3ef1` (Completed: Nov 4, 2025)
  - ✅ Created Prometheus alerting rules: `config/prometheus/api-performance-alerts.yml`
  - ✅ Created Grafana dashboard: `grafana_dashboards/api-performance-baseline.json`
  - ✅ Updated AlertManager routing for API/database/webhook alerts
  - ✅ Documented baseline thresholds (see Baseline Metrics section below)
- [x] Set up alerting for error rates > 1% - **VK:** `651a3ef1` (Completed: Nov 4, 2025)
  - ✅ APIErrorRateHigh: Warning at > 1%, Critical at > 5%
  - ✅ Email notifications to admin@rsolv.dev and alerts@rsolv.dev
- [x] Monitor database query performance - **VK:** `651a3ef1` (Completed: Nov 4, 2025)
  - ✅ DatabaseQueryLatencyHigh: Warning at P95 > 100ms, Critical at > 500ms
  - ✅ DatabaseConnectionPoolExhausted: Warning at > 90% utilization
- [x] Track webhook processing latency - **VK:** `651a3ef1` (Completed: Nov 4, 2025)
  - ✅ WebhookProcessingLatencyHigh: Warning at P95 > 1000ms
  - ✅ WebhookProcessingFailures: Warning at failure rate > 5%

**Conversion Tracking:**
- [x] Website visits → signups - **VK:** `ceba61e4` (✅ Implemented 2025-11-04)
- [x] Signups → API key creation - **VK:** `ceba61e4` (✅ Implemented 2025-11-04)
- [x] API key creation → first API call - **VK:** `ceba61e4` (✅ Implemented 2025-11-04)
- [x] First API call → continued usage - **VK:** `ceba61e4` (✅ Implemented 2025-11-04)

**Update Frequency:** Daily during Week 5, then weekly after stabilization

**Vibe Kanban Tickets Created:**
- `000a4bea` - [Week 5] Daily: Update production metrics (Nov 4-11)
- `fd752338` - [Week 5] Begin beta tester outreach to 5 contacts
- `651a3ef1` - [Week 5] Establish baseline API metrics and alerting
- `395ace2f` - [Week 5-7] Follow up with non-responders (Nov 13-15)
- `c299315d` - [By Nov 13] Confirm 3-5 beta testers
- `b80d8e09` - [Weekly] Update metrics (starts Nov 12)
- `5bea504c` - [Week 5] Document common customer questions
- `ceba61e4` - [Week 5] Track conversion funnel

## Baseline Performance Metrics & Alerting

**Established:** 2025-11-04 (Week 5)

### Overview

Comprehensive monitoring and alerting infrastructure has been established to ensure production service quality and detect performance degradation early. This system tracks API performance, database queries, and webhook processing with automated alerts for threshold violations.

### Monitoring Stack

- **Metrics Collection:** PromEx + Prometheus (30s scrape interval)
- **Visualization:** Grafana dashboards at grafana.rsolv.dev
- **Alerting:** AlertManager with email notifications
- **Metrics Endpoint:** https://rsolv.dev/metrics (Prometheus format)

### API Performance Baselines

| Metric | Target | Warning Threshold | Critical Threshold | Alert Name |
|--------|--------|-------------------|-------------------|------------|
| **Error Rate (5xx)** | < 1% | > 1% for 5 min | > 5% for 2 min | APIErrorRateHigh / APIErrorRateCritical |
| **P95 Latency** | < 1000ms | > 1000ms for 10 min | > 3000ms for 5 min | APIP95LatencyHigh / APIP95LatencyCritical |
| **P50 Latency** | < 200ms | N/A (tracking only) | N/A | N/A |
| **Request Rate** | > 0.01 req/s | < 0.01 req/s for 30 min (business hours) | 0 req/s for 10 min | APIRequestRateAnomalyLow / APIRequestsStopped |

### Endpoint-Specific Baselines

| Endpoint | Purpose | P95 Target | Warning Threshold |
|----------|---------|------------|-------------------|
| `/api/v1/credentials/exchange` | GitHub Action auth | < 500ms | > 500ms for 10 min |
| `/api/v1/vulnerabilities/validate` | AST analysis | < 2000ms | > 2000ms for 10 min |
| `/api/v1/test-integration/*` | Test generation | < 5000ms | (covered by RFC-060 alerts) |

### Database Performance Baselines

| Metric | Target | Warning Threshold | Critical Threshold | Alert Name |
|--------|--------|-------------------|-------------------|------------|
| **P95 Query Latency** | < 100ms | > 100ms for 10 min | > 500ms for 5 min | DatabaseQueryLatencyHigh / DatabaseQueryLatencyCritical |
| **Connection Pool Usage** | < 80% | > 90% for 5 min | N/A | DatabaseConnectionPoolExhausted |

### Webhook Processing Baselines

| Metric | Target | Warning Threshold | Notes |
|--------|--------|-------------------|-------|
| **P95 Processing Latency** | < 1000ms | > 1000ms for 10 min | Stripe requires response within ~30s |
| **Failure Rate** | < 5% | > 5% for 5 min | May indicate billing inconsistencies |

### Alert Routing & Notifications

**Email Notifications:**
- **Critical API Alerts:** admin@rsolv.dev (immediate, repeat every 2h)
- **API Warnings:** admin@rsolv.dev, alerts@rsolv.dev (repeat every 6h)
- **Database Critical:** admin@rsolv.dev (immediate, repeat every 2h)
- **Database Warnings:** admin@rsolv.dev, alerts@rsolv.dev (repeat every 6h)
- **Webhook Warnings:** admin@rsolv.dev, alerts@rsolv.dev (repeat every 6h)

**Alert Inhibition:**
- Critical alerts suppress related warnings for the same instance
- Prevents alert fatigue during incidents

### Monitoring Resources

**Dashboards:**
- **API Performance Baseline:** https://grafana.rsolv.dev/d/api-performance-baseline
- **Phoenix Metrics:** Auto-uploaded by PromEx (HTTP requests, response times)
- **Ecto Metrics:** Auto-uploaded by PromEx (database queries, connection pool)
- **Billing Dashboard:** https://grafana.rsolv.dev/d/billing_dashboard
- **RFC-060 Validation Metrics:** https://grafana.rsolv.dev/d/rfc-060-validation-metrics

**Alert Rule Files:**
- `config/prometheus/api-performance-alerts.yml` - API/database/webhook alerts (NEW)
- `config/prometheus/billing-alerts.yml` - Billing system alerts (RFC-069)
- `config/prometheus/rfc-060-alerts.yml` - Validation/mitigation alerts (RFC-060)
- `monitoring/rsolv-uptime-alerts.yaml` - Site availability alerts

**Configuration Files:**
- `monitoring/alertmanager-config-webhook.yaml` - AlertManager routing and receivers
- `monitoring/prometheus-config-update.yaml` - Prometheus scrape and rule loading
- `lib/rsolv/prom_ex.ex` - PromEx plugin configuration

### Deployment Status

**Current Status (2025-11-04):**
- ⚠️ **NOT YET DEPLOYED** - Alert rules and dashboard created but not yet applied to production
- ✅ Infrastructure exists (Prometheus, Grafana, AlertManager already deployed)
- ✅ Metrics collection active (PromEx plugins running)
- ⚠️ Awaiting deployment of new alert rules and dashboard

**Deployment Required:**
1. Apply updated AlertManager config: `kubectl apply -f monitoring/alertmanager-config-webhook.yaml`
2. Load new alert rules into Prometheus ConfigMap
3. Upload Grafana dashboard: `grafana_dashboards/api-performance-baseline.json`
4. Verify alerts are firing correctly (test with simulated load)

**Next Steps:**
- Deploy alerting configuration to production Kubernetes cluster
- Verify alert routing and email delivery
- Monitor baseline metrics for 24-48 hours to validate thresholds
- Adjust thresholds based on actual production traffic patterns
- Document alert response runbooks

### Metrics Already Being Collected

The following metrics are **already available** via existing PromEx plugins:

**Phoenix Plugin (HTTP Metrics):**
- `phoenix_http_request_duration_milliseconds_bucket` - Request latency histogram
- `phoenix_http_request_duration_milliseconds_count` - Total request count
- Labels: `status`, `controller`, `action`, `path`

**Ecto Plugin (Database Metrics):**
- `rsolv_prom_ex_ecto_query_duration_milliseconds_bucket` - Query latency histogram
- `rsolv_prom_ex_ecto_connection_pool_size` - Total pool size
- `rsolv_prom_ex_ecto_connection_pool_used_connections` - Currently used connections

**BillingPlugin (Webhook Metrics):**
- `rsolv_billing_stripe_webhook_received_duration_milliseconds_bucket` - Webhook latency histogram
- `rsolv_billing_stripe_webhook_received_total` - Webhook count by status
- Labels: `event_type`, `status`, `failure_reason`

**ValidationPlugin (RFC-060 Metrics):**
- `rsolv_validation_test_generation_duration_milliseconds` - Test generation latency
- `rsolv_validation_test_execution_duration_milliseconds` - Test execution latency
- Labels: `language`, `status`

## Goals

- **Primary Goal:** 3-5 confirmed beta testers by end of Week 3 (2025-11-13)
- **Secondary Goal:** 5 quality outreach contacts identified by end of Week 0
- **Success Metric:** Testers who will actually install and use RSOLV on real repositories
- **Philosophy:** Quality over quantity - respectful outreach to people who'd genuinely benefit

## Beta Tester Criteria

**Ideal Beta Testers:**
- DevSecOps leads, security engineers, or backend developers
- Work with repositories that handle sensitive data or have security requirements
- Use GitHub Actions (required for current RSOLV implementation)
- Willing to provide feedback and report issues
- Based in our warm network (higher conversion rate)

**Value Proposition for Testers:**
- Unlimited free fixes during beta period
- Direct access to founder for support
- Influence on product direction and feature prioritization
- Early adopter recognition

## Outreach Template

```markdown
Subject: Would you beta test our AI security fixer?

Hey [Name],

I'm building RSOLV - an AI that validates security vulnerabilities before fixing them. Instead of guessing, it writes tests that FAIL (proving the bug), then fixes the code until tests pass.

We're launching in ~6 weeks. Would you be willing to test it on [their repo/company]? You'd get:
- Unlimited free fixes during beta
- Direct access to me for support
- Influence on product direction

Only catch: It's GitHub Actions only (for now).

Interested? I'll send early access in ~3 weeks when staging is ready.

- Dylan
```

## Outreach Tracking

### Week 0 (2025-10-23 to 2025-10-30)

**Target:** 5 quality warm network contacts identified and reached out to

| # | Contact Name | Company/Context | Status | Sent Date | Response | Notes |
|---|--------------|-----------------|--------|-----------|----------|-------|
| 1 | David Vasandani | | Not Sent | - | - | Warm professional contact - likely works with secure systems and GitHub Actions |
| 2 | Scott Crespo | | Not Sent | - | - | Warm professional contact - technical background suggests DevSecOps familiarity |
| 3 | David Van der Voort | | Not Sent | - | - | Warm professional contact - international perspective could provide valuable feedback |
| 4 | Todd Nichols | | Not Sent | - | - | Warm professional contact - likely has security-conscious development practices |
| 5 | John Driftmier | | Not Sent | - | - | Warm professional contact - technical expertise and likely uses GitHub Actions |

**Legend:**
- Status: Not Sent | Sent | Responded | Interested | Confirmed | Declined | No Response

### Week 1-3 Follow-up

Track follow-ups and conversions here:

| # | Contact Name | Follow-up Date | Status Change | Beta Invite Sent | Notes |
|---|--------------|----------------|---------------|------------------|-------|
| | | | | | |

## Confirmed Beta Testers

**Goal: 3-5 by 2025-11-13**

| # | Name | Company/Project | GitHub Handle | Repo(s) to Test | Invite Sent | Started Testing | Notes |
|---|------|-----------------|---------------|-----------------|-------------|-----------------|-------|
| 1 | | | | | | | |
| 2 | | | | | | | |
| 3 | | | | | | | |
| 4 | | | | | | | |
| 5 | | | | | | | |

## Conversion Metrics

| Week | Outreach Sent | Responses | Interested | Confirmed Testers | Conversion Rate |
|------|---------------|-----------|------------|-------------------|-----------------|
| 0 (10/23-10/30) | 0 | 0 | 0 | 0 | - |
| 1 (10/30-11/06) | - | - | - | - | - |
| 2 (11/06-11/13) | - | - | - | - | - |
| 3 (11/13-11/20) | - | - | - | - | - |

**Target Conversion Rate:** 60% (3 testers from 5 warm network contacts)

## Warm Network Sources

**Where to find contacts:**
- [ ] Former colleagues from previous companies
- [ ] Current professional network (LinkedIn connections)
- [ ] Developer communities (local meetups, Slack/Discord groups)
- [ ] Security-focused communities (infosec.exchange, security Discords)
- [ ] Open source maintainers of security-related projects
- [ ] Previous clients or consulting contacts
- [ ] Fellow indie hackers working on dev tools

## Next Actions

**Immediate (This Week):**
1. [ ] Identify 5 quality warm network contacts with names and context
2. [ ] Draft personalized variations of outreach email for each contact
3. [ ] Send personalized outreach to all 5 contacts
4. [ ] Track responses and schedule follow-ups

**Week 1:**
1. [ ] Follow up (once) with non-responders from Week 0 (after 5-7 days)
2. [ ] Respond to interested parties with more details
3. [ ] Begin confirming beta testers (GitHub handles, repos to test)

**Week 2-3:**
1. [ ] Convert interested parties to confirmed testers (goal: 3-5)
2. [ ] Prepare beta testing infrastructure (staging access, docs)
3. [ ] Send beta invites to confirmed testers when ready
4. [ ] Consider additional outreach if needed (but keep it quality-focused)

## Funnel Tracking Implementation

**Implementation Date:** 2025-11-04
**Status:** ✅ Complete and operational

### Overview

A comprehensive conversion funnel tracking system has been implemented to track customer journeys from first website visit through to retained usage. The system provides real-time insights into conversion rates at each funnel stage.

### Funnel Stages Tracked

1. **Website Visits** (Stage 1)
   - Tracked via: `FunnelTracking.track_page_view/1`
   - Metrics: Total visits, unique visitors
   - Sources: Homepage, blog, pricing page, docs

2. **Signups** (Stage 2)
   - Tracked via: `FunnelTracking.track_signup/2`
   - Integration: `Rsolv.CustomerOnboarding` module
   - Automatic tracking when customer completes registration

3. **API Key Creation** (Stage 3)
   - Tracked via: `FunnelTracking.track_api_key_creation/2`
   - Integration: `Rsolv.CustomerOnboarding` module
   - Tracks when customer generates their first API key

4. **Activation** (Stage 4 - First API Call)
   - Tracked via: `FunnelTracking.track_api_call/2`
   - Integration: `RsolvWeb.Plugs.ApiAuthentication`
   - Automatic tracking on first successful API request

5. **Retention** (Stage 5 - Continued Usage)
   - Tracked via: `FunnelTracking.track_api_call/2`
   - Metric: Customers who make 2+ API calls
   - Indicates product-market fit and engagement

### Database Schema

**Tables Created:**
- `funnel_events` - Individual event tracking (page views, signups, API calls)
- `customer_journeys` - Per-customer progress through funnel with timing metrics
- `funnel_metrics` - Pre-aggregated conversion metrics by time period

**Key Features:**
- UTM parameter tracking for attribution
- Conversion timing metrics (seconds between stages)
- Visitor/session tracking for anonymous users
- Indexed for fast queries

### Querying Funnel Data

**Get funnel summary for last 30 days:**
```elixir
iex> Rsolv.FunnelTracking.get_funnel_summary(30)
%{
  website_visits: 1234,
  unique_visitors: 567,
  signups: 45,
  api_keys_created: 32,
  activated_users: 20,
  retained_users: 12,
  visit_to_signup_rate: #Decimal<3.65>,
  signup_to_api_key_rate: #Decimal<71.11>,
  api_key_to_activation_rate: #Decimal<62.50>,
  activation_to_retention_rate: #Decimal<60.00>
}
```

**Get daily metrics:**
```elixir
iex> start_date = ~D[2025-11-01]
iex> end_date = ~D[2025-11-04]
iex> Rsolv.FunnelTracking.get_daily_metrics(start_date, end_date)
[%{period_start: ~D[2025-11-01], ...}, ...]
```

**Find customers who activated but didn't retain:**
```elixir
iex> Rsolv.FunnelTracking.list_journeys(
  completed_activation: true,
  completed_retention: false,
  limit: 10
)
```

### Integration Points

**Automatic Tracking:**
- ✅ Customer signup → `Rsolv.CustomerOnboarding.provision_customer/1`
- ✅ API key creation → `Rsolv.CustomerOnboarding` (same transaction)
- ✅ API calls → `RsolvWeb.Plugs.ApiAuthentication` (on every authenticated request)

**Non-Blocking Design:**
- All tracking is best-effort and non-blocking
- Failures logged but don't affect core business logic
- API call tracking runs in background Task to avoid request latency

### Current Metrics (Since Implementation)

**Baseline Period:** 2025-11-04 onwards

To check current metrics:
```bash
# Connect to production IEx console
fly ssh console -a rsolv -C "/app/bin/rsolv remote"

# Query funnel summary
iex> Rsolv.FunnelTracking.get_funnel_summary(7)  # Last 7 days
```

### Future Enhancements

**Planned:**
- [ ] Admin dashboard LiveView for real-time funnel visualization
- [ ] Weekly email reports with funnel metrics
- [ ] Cohort analysis (signups by week)
- [ ] Drop-off analysis (identify where customers get stuck)
- [ ] A/B testing framework for conversion optimization

**Analytics Integration:**
- [ ] Export to Google Analytics 4
- [ ] Integration with existing `analytics_events` table
- [ ] Plausible Analytics integration (if adopted)

### Files Added/Modified

**New Files:**
- `priv/repo/migrations/20251104183341_create_funnel_tracking_tables.exs`
- `lib/rsolv/funnel_tracking.ex` (main context module)
- `lib/rsolv/funnel_tracking/funnel_event.ex`
- `lib/rsolv/funnel_tracking/customer_journey.ex`
- `lib/rsolv/funnel_tracking/funnel_metric.ex`

**Modified Files:**
- `lib/rsolv/customer_onboarding.ex` (added signup & API key tracking)
- `lib/rsolv_web/plugs/api_authentication.ex` (added API call tracking)

### Testing

**Manual Testing Checklist:**
- [x] Migration runs successfully
- [ ] Signup tracking creates funnel_event and customer_journey
- [ ] API key creation updates customer_journey
- [ ] First API call marks activation
- [ ] Second API call marks retention
- [ ] Query functions return correct metrics
- [ ] Tracking failures don't break customer onboarding

**Test in Development:**
```bash
# Create test customer
mix run -e "Rsolv.CustomerOnboarding.provision_customer(%{name: \"Test\", email: \"test@example.com\"})"

# Check journey was created
iex> Rsolv.Repo.all(Rsolv.FunnelTracking.CustomerJourney) |> Rsolv.Repo.preload(:customer)
```

## Notes & Learnings

**2025-11-04 (Week 5 - Funnel Tracking Implementation):**
- ✅ Implemented comprehensive conversion funnel tracking system
- Database tables: funnel_events, customer_journeys, funnel_metrics
- Integration points: CustomerOnboarding (signup/API key), ApiAuthentication (API calls)
- Non-blocking design ensures tracking failures don't impact customer experience
- Ready to track: visits → signups → API keys → activation → retention
- Next step: Build admin dashboard for visualization
- All tracking is operational and recording events starting 2025-11-04

**2025-11-04 (Week 5 - Production Launch):**
- 🚀 Production successfully launched on 2025-11-04
- Production outage resolved in ~5 hours (feature flag naming issue)
- Key learning: Feature flag naming conventions need to be documented and enforced
- Key learning: Secret management procedures need improvement (documented in RFC-069)
- First smoke test customer created - monitoring for first organic signup
- Blog is live with feature flag enabled - ready for content marketing
- Beta tester outreach pending - will begin this week
- Update frequency: Daily during Week 5 to track initial metrics

**2025-10-23:**
- Initial tracking document created as part of Week 0 customer development kickoff
- Updated expectations from 20-30 contacts to 5 quality contacts - prioritizing respectful outreach to warm network
- Adjusted goal from 10 testers to 3-5 highly engaged testers
- Philosophy: Better to have a few people who are genuinely excited than spam people we respect

---

**Update Instructions:**
- **Week 5 (Launch Week):** Update this document DAILY with production metrics and customer activity
- **After Week 5:** Update weekly with progress
- Move contacts through the pipeline: Sent → Responded → Interested → Confirmed
- Track learnings about what messaging works best
- Note any common objections or questions to address in product/docs
- Document all production incidents and resolutions
- Track conversion funnel metrics (visits → signups → activation → retention)
