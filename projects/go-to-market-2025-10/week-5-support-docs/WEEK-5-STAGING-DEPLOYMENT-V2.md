# Week 5 Customer Support Documentation - Staging Deployment v2 (Feature Flag)

**Date:** 2025-11-04
**Branch:** vk/0c81-week-5-create-cu
**Deployment Image:** ghcr.io/rsolv-dev/rsolv-platform:support-docs-staging-v4
**Status:** ✅ Complete and Verified

## Overview

Successfully deployed customer support documentation to staging with feature flag protection. This deployment includes the `:customer_support_docs` feature flag that allows us to deploy to production with the feature disabled, then enable it when ready.

## Feature Flag Implementation

### Changes Made

1. **lib/rsolv/feature_flags.ex**:
   - Added `:customer_support_docs` to `early_access` role features
   - Added feature description: "Customer support documentation pages"

2. **lib/rsolv_web/router.ex**:
   - Created `:require_customer_support_docs` pipeline with `FeatureFlagPlug`
   - Moved support routes to separate scope with feature flag protection
   - Routes redirect to "/" with message when flag disabled

### Feature Flag Behavior

- **When enabled**: All support pages return HTTP 200
- **When disabled**: Requests redirect to "/" with "Customer support documentation is currently unavailable"
- **Default state**: Disabled (must be explicitly enabled)

## Deployment Process

### 1. Build and Push Docker Image

```bash
cd /var/tmp/vibe-kanban/worktrees/0c81-week-5-create-cu
DOCKER_HOST=10.5.0.5 docker build -t ghcr.io/rsolv-dev/rsolv-platform:support-docs-staging-v4 .
DOCKER_HOST=10.5.0.5 docker push ghcr.io/rsolv-dev/rsolv-platform:support-docs-staging-v4
```

**Build Time:** ~20 seconds (mostly cached layers)
**Image Digest:** sha256:c67d05487a8ed7008a3ef21b9386605d5fc47c3318443b4a9819689adabc2eec

### 2. Deploy to Staging

```bash
kubectl set image deployment/staging-rsolv-platform \
  rsolv-platform=ghcr.io/rsolv-dev/rsolv-platform:support-docs-staging-v4 \
  -n rsolv-staging

kubectl rollout status deployment/staging-rsolv-platform -n rsolv-staging --timeout=5m
```

**Rollout Time:** ~60 seconds (zero-downtime rolling update)
**Replicas:** 2/2 updated successfully

### 3. Enable Feature Flag

```bash
kubectl exec -n rsolv-staging staging-rsolv-platform-[pod-id] -- \
  bin/rsolv rpc 'FunWithFlags.enable(:customer_support_docs)'
```

**Result:**
```
INSERT INTO "fun_with_flags_toggles" ... VALUES (true, "_fwf_none", "customer_support_docs", "boolean", true)
FunWithFlags.Notifications: publish change for 'customer_support_docs'
```

## Verification Results

### Support Pages Status

All 6 support pages verified accessible:

```bash
✅ https://rsolv-staging.com/support - HTTP 200 (index)
✅ https://rsolv-staging.com/support/onboarding - HTTP 200
✅ https://rsolv-staging.com/support/billing-faq - HTTP 200
✅ https://rsolv-staging.com/support/api-keys - HTTP 200
✅ https://rsolv-staging.com/support/credits - HTTP 200
✅ https://rsolv-staging.com/support/payment-troubleshooting - HTTP 200
```

### Content Verification

Each page includes:
- ✅ Proper page title and meta tags
- ✅ Responsive Tailwind CSS layout
- ✅ Dark mode support
- ✅ Navigation breadcrumbs
- ✅ Comprehensive, actionable content
- ✅ Mobile-friendly design

### Infrastructure Verification

- ✅ Zero downtime during deployment
- ✅ Both staging replicas healthy
- ✅ No errors in application logs
- ✅ Feature flag properly stored in database
- ✅ Routes correctly protected by feature flag

## Production Deployment Plan

### Phase 1: Deploy with Feature Flag Disabled

**Ticket:** 08a23c12-4128-4697-92e1-aa1835035a30

1. Build production image: `ghcr.io/rsolv-dev/rsolv-platform:support-docs-prod-v1`
2. Deploy to production namespace
3. Verify deployment stable with feature disabled
4. Confirm existing production services unaffected

**Risk:** Low - feature is hidden behind disabled flag

### Phase 2: Enable Feature Flag

**Ticket:** 589a195c-ba81-4134-afe2-5df7623de661

1. Wait 24-48 hours after Phase 1 deployment
2. Enable flag: `FunWithFlags.enable(:customer_support_docs)`
3. Verify all 6 pages accessible on production
4. Monitor logs and metrics
5. Announce availability to customers

**Risk:** Very low - instant rollback via `FunWithFlags.disable()`

## Rollback Procedures

### Immediate Rollback (Hide Pages)

```bash
kubectl exec -n rsolv-staging [pod-name] -- \
  bin/rsolv rpc 'FunWithFlags.disable(:customer_support_docs)'
```

**Effect:** Pages immediately redirect to "/" (no deployment needed)

### Full Rollback (Previous Image)

```bash
kubectl set image deployment/staging-rsolv-platform \
  rsolv-platform=ghcr.io/rsolv-dev/rsolv-platform:[previous-tag] \
  -n rsolv-staging
```

## Technical Details

### Feature Flag Architecture

- **Storage:** PostgreSQL (`fun_with_flags_toggles` table)
- **Cache:** In-memory with pub/sub notifications
- **Scope:** Global boolean flag (applies to all users)
- **Performance:** Zero overhead when disabled (route check happens early)

### Route Protection

Routes are protected at the pipeline level, before controllers:

```elixir
scope "/support", RsolvWeb do
  pipe_through [:browser, :require_customer_support_docs]
  # ... routes
end
```

When feature is disabled, `FeatureFlagPlug` intercepts request and redirects.

### SEO Considerations

- Sitemap includes support pages (always, for crawler discovery)
- Pages return 302 redirect when disabled (not 404)
- Redirect message is user-friendly
- Once enabled, pages immediately available for indexing

## Documentation

Related files:
- Implementation summary: `WEEK-5-IMPLEMENTATION-SUMMARY.md`
- Original staging deployment: `WEEK-5-STAGING-DEPLOYMENT.md`
- RFC reference: RFC-069-FRIDAY (Week 5, lines 71-83)

## Next Steps

1. ✅ Staging deployment complete
2. ✅ Feature flag tested and working
3. ✅ Production deployment tickets created
4. ⏳ Await approval to deploy to production (Phase 1)
5. ⏳ Deploy to production with flag disabled
6. ⏳ Enable flag on production when ready (Phase 2)

## Success Metrics

- ✅ Zero deployment errors
- ✅ Zero application errors in logs
- ✅ All 6 pages return HTTP 200 when enabled
- ✅ Feature flag toggle works instantly
- ✅ Rollback procedure tested (disable/enable cycle)
- ✅ Production deployment strategy documented

---

**Deployed by:** Claude (Vibe Kanban)
**Verified by:** Automated curl tests + manual review
**Approved for production:** Pending
