# RFC-078 Implementation Tracking

**RFC**: [RFC-078: Public Site & Self-Service Signup](../../RFCs/RFC-078-PUBLIC-SITE-SELF-SERVICE.md)
**Status**: Draft
**Timeline**: Week 5 (Nov 4-8, 2025)
**Owner**: Product Team
**Priority**: Critical (blocks launch)

## Overview

Create public-facing pages to enable self-service customer acquisition:
- `/` - Landing page with value prop and CTA
- `/pricing` - Transparent pricing comparison
- `/signup` - Self-service signup (convert early_access_live.ex)

**Critical Gap**: Backend billing/provisioning ready (RFC-065/066), but no public signup flow exists.

## Dependencies

**Must Complete First:**
- ✅ RFC-064: Master plan coordination
- ✅ RFC-065: Customer provisioning API
- ✅ RFC-066: Stripe billing integration
- 🔄 RFC-069: Integration Week (completes Week 4)

**Enables:**
- RFC-070: Customer authentication (post-launch)
- RFC-071: Customer portal UI (post-launch)
- RFC-067: GitHub Marketplace launch

## Implementation Schedule

### Week 5 Day-by-Day Plan

#### Monday (Nov 4)
- [ ] **Landing Page (/)**
  - [ ] RED: Write tests for hero, features, CTA
  - [ ] GREEN: Implement landing_live.ex
  - [ ] REFACTOR: Extract reusable components
  - [ ] VERIFY: Lighthouse score ≥ 90

#### Tuesday (Nov 5)
- [ ] **Pricing Page (/pricing)**
  - [ ] RED: Write tests for pricing tiers, calculator, FAQ
  - [ ] GREEN: Implement pricing_live.ex
  - [ ] REFACTOR: Create pricing calculator component
  - [ ] VERIFY: All pricing amounts correct

#### Wednesday (Nov 6)
- [ ] **Signup Flow (Part 1)**
  - [ ] RED: Write tests for form, validation
  - [ ] GREEN: Convert early_access_live.ex → signup_live.ex
  - [ ] Integrate RFC-065 API (provision_customer)
  - [ ] VERIFY: Customer creation working

#### Thursday (Nov 7)
- [ ] **Signup Flow (Part 2)**
  - [ ] RED: Write tests for success state, error handling
  - [ ] GREEN: Implement API key display, email confirmation
  - [ ] REFACTOR: Extract form components
  - [ ] VERIFY: Rate limiting working (10/hour per IP)

#### Friday (Nov 8)
- [ ] **Integration & Polish**
  - [ ] E2E testing: Landing → Signup → First Fix
  - [ ] Accessibility audit (WCAG 2.1 AA)
  - [ ] Mobile responsiveness testing (iPhone, Android)
  - [ ] Performance optimization (Lighthouse)
  - [ ] Copy review & refinement

## Test Coverage Goals

**Target: 80%+ for all pages**

### Landing Page Tests
- [ ] Hero section displays with CTA
- [ ] CTA links to /signup
- [ ] Features section displays
- [ ] Pricing teaser links to /pricing
- [ ] Mobile responsive layout
- [ ] Dark mode compatible

### Pricing Page Tests
- [ ] All pricing tiers display
- [ ] Correct pricing amounts ($599, $29, 10 credits)
- [ ] Pricing calculator interactive
- [ ] FAQ section displays
- [ ] CTA links to /signup
- [ ] Mobile responsive layout

### Signup Page Tests
- [ ] Signup form displays
- [ ] Customer creation via RFC-065 API
- [ ] API key displayed on success
- [ ] Email confirmation sent
- [ ] Duplicate email error handling
- [ ] Email format validation
- [ ] Rate limiting (10/hour per IP)
- [ ] Disposable email rejection

## Success Metrics

### Functional Requirements
- [ ] Landing page loads < 2s (p95)
- [ ] All CTAs link correctly
- [ ] Signup form creates customer successfully
- [ ] API key displayed and emailed
- [ ] Rate limiting prevents abuse
- [ ] Error states handled gracefully

### User Experience
- [ ] Clear value prop within 5 seconds
- [ ] Frictionless signup (< 2 minutes)
- [ ] Mobile-friendly (320px+)
- [ ] Dark mode compatible
- [ ] Accessible (keyboard nav, screen readers)

### Business Metrics (Target)
- [ ] Signup conversion rate > 10% (landing → signup)
- [ ] API key retrieval rate > 95% (signup → key saved)
- [ ] Setup completion rate > 60% (signup → first scan)
- [ ] Support tickets < 5% of signups

### Technical Requirements
- [ ] Test coverage ≥ 80%
- [ ] CI pipeline passes (tests, Credo, format)
- [ ] Lighthouse score ≥ 90 for all pages
- [ ] SEO meta tags added
- [ ] Sitemap updated
- [ ] Analytics configured

## Files to Create

```
lib/rsolv_web/
├── live/
│   ├── landing_live.ex            # Landing page (/)
│   ├── pricing_live.ex            # Pricing page (/pricing)
│   └── signup_live.ex             # Signup (convert from early_access_live.ex)
└── templates/
    └── layout/
        └── public.html.heex       # Public pages layout
```

## Files to Modify

```
lib/rsolv_web/
├── router.ex                      # Add routes for /, /pricing, /signup
└── live/
    └── early_access_live.ex       # Convert to signup_live.ex
```

## Testing Checklist

### Unit Tests
- [ ] Landing page renders correctly
- [ ] Pricing page displays all tiers
- [ ] Signup form validation
- [ ] Customer creation integration
- [ ] Rate limiting enforcement
- [ ] Error handling

### Integration Tests
- [ ] Landing → Pricing flow
- [ ] Landing → Signup flow
- [ ] Signup → Customer creation → Email
- [ ] Duplicate email handling
- [ ] Rate limit enforcement

### E2E Tests
- [ ] Complete customer journey: Landing → Signup → Dashboard → First Fix
- [ ] Mobile device testing (iPhone, Android)
- [ ] Browser compatibility (Chrome, Firefox, Safari, Edge)
- [ ] Screen reader testing (VoiceOver, NVDA)

### Performance Tests
- [ ] Lighthouse audit (Desktop ≥ 90)
- [ ] Lighthouse audit (Mobile ≥ 80)
- [ ] Page load time < 2s (p95)
- [ ] Time to Interactive < 3s
- [ ] Core Web Vitals passing

## Deployment Plan

### Feature Flag Strategy

**Feature Flag:** `public_site` (FunWithFlags)

**Purpose:** Deploy code to production throughout Week 5 with flag OFF, enabling safe testing on staging before production launch.

**Approach:**
1. **Monday-Thursday:** Deploy each day's changes to production with flag OFF
2. **Staging Testing:** Enable flag ON in staging environment for all testing
3. **Friday Go-Live:** Enable flag ON in production after final validation

**Benefits:**
- Zero-downtime deployments throughout the week
- Full production environment testing (with flag ON in staging)
- Instant rollback capability (disable flag, no code deployment)
- No regression risk to existing functionality

**Implementation:**
```elixir
# In each new route/controller
defmodule RsolvWeb.SignupLive do
  use RsolvWeb, :live_view

  def mount(_params, _session, socket) do
    if FunWithFlags.enabled?(:public_site) do
      # New public signup UI
    else
      # Redirect to early access or 404
    end
  end
end
```

### Staging Deployment (Monday-Thursday, Continuous)
1. Deploy to staging with feature flag OFF
2. Manually enable `public_site` flag in staging database
3. Smoke test new functionality
4. Run automated test suite
5. Performance/accessibility checks
6. Deploy to production with flag OFF (safe, code inactive)

### Production Deployment (Friday, Nov 8)
1. **Pre-Launch Verification (Morning)**
   - [ ] All tests passing on staging (flag ON)
   - [ ] Lighthouse score ≥ 90
   - [ ] Accessibility audit complete
   - [ ] Mobile responsiveness confirmed
   - [ ] Security review complete
   - [ ] Analytics/monitoring configured
   - [ ] Latest code deployed to production (flag OFF)

2. **Go-Live Procedure (Afternoon)**
   ```bash
   # Connect to production database
   psql $DATABASE_URL

   # Enable public_site flag
   INSERT INTO fun_with_flags_toggles (flag_name, gate_type, target, enabled)
   VALUES ('public_site', 'boolean', NULL, true)
   ON CONFLICT (flag_name, gate_type, target)
   DO UPDATE SET enabled = true;

   # Verify flag enabled
   SELECT * FROM fun_with_flags_toggles WHERE flag_name = 'public_site';
   ```

3. **Post-Launch Monitoring (First Hour)**
   - [ ] Smoke test all three pages (/, /pricing, /signup)
   - [ ] Complete test signup end-to-end
   - [ ] Monitor error rates (Sentry/logs)
   - [ ] Verify analytics tracking
   - [ ] Check funnel metrics
   - [ ] Watch for spam signups

### Rollback Plan
**Immediate Rollback (< 30 seconds):**
```bash
# Disable feature flag (instant rollback, no deployment)
psql $DATABASE_URL -c "UPDATE fun_with_flags_toggles SET enabled = false WHERE flag_name = 'public_site';"
```

**If issues persist after flag disable:**
1. Investigate logs/errors
2. Quick fix and redeploy if simple
3. Full rollback to previous image if complex

## Risk Mitigation

| Risk | Mitigation | Status |
|------|------------|--------|
| Spam signups | Rate limiting (10/hour per IP) | ✅ Spec'd |
| Disposable emails | Email validation (RFC-065) | ✅ Implemented |
| Poor conversion | A/B testing copy, optimize CTA | ⏳ Post-launch |
| Mobile UX issues | Thorough mobile testing | 🔄 Week 5 |
| Slow page load | Lighthouse audit, optimize | 🔄 Week 5 |
| Abandoned signups | Follow-up email (RFC-065) | ✅ Implemented |

## Open Questions

- [ ] **Analytics tool**: Which tool? (Google Analytics, Plausible, PostHog?)
- [ ] **CAPTCHA**: Add immediately or wait for spam issues?
- [ ] **Legal pages**: Terms of Service and Privacy Policy ready?
- [ ] **Email deliverability**: Postmark configured and tested?
- [ ] **Domain setup**: rsolv.dev SSL and DNS confirmed working?

## Current Status

**As of 2025-11-01:**
- ✅ RFC-078 drafted and reviewed
- ✅ Added to go-to-market project tracking
- ⏳ Waiting for RFC-069 completion (Week 4)
- ⏳ Week 5 implementation scheduled

**Blockers:** None
**Risks:** None identified

## Weekly Updates

### Week 4 (Oct 28 - Nov 1)
- RFC-078 drafted
- Gap identified and documented
- Integrated into project timeline
- Dependencies confirmed

### Week 5 (Nov 4-8) - IMPLEMENTATION WEEK
_Updates will be added daily_

### Week 6 (Nov 11-15) - LAUNCH WEEK
_Post-deployment monitoring and optimization_

## Completion Criteria

Before marking RFC-078 as "Implemented":

1. ✅ All three pages deployed to production
2. ✅ Self-service signup working end-to-end
3. ✅ Test coverage ≥ 80%
4. ✅ Lighthouse score ≥ 90 for all pages
5. ✅ Mobile responsive (tested on iPhone, Android)
6. ✅ Accessibility audit passed (WCAG 2.1 AA)
7. ✅ Analytics tracking configured
8. ✅ SEO meta tags added
9. ✅ Sitemap updated
10. ✅ At least 3 successful test signups on production

## Related Documents

- [RFC-078: Public Site & Self-Service Signup](../../RFCs/RFC-078-PUBLIC-SITE-SELF-SERVICE.md)
- [Go-to-Market Project README](README.md)
- [Week 5 Completion](WEEK-5-COMPLETION.md) _(to be created)_
- RFC-064: Master plan
- RFC-065: Customer provisioning
- RFC-066: Stripe billing
- RFC-069: Integration week
