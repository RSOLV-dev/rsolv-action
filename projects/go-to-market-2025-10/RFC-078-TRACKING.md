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

### Staging Deployment (Thursday EOD)
1. Deploy to rsolv-staging.com
2. Smoke test all pages
3. Verify signup flow end-to-end
4. Check analytics tracking
5. Accessibility audit

### Production Deployment (Friday)
1. Final QA on staging
2. Deploy to production
3. Smoke test on production
4. Monitor error rates
5. Watch conversion metrics

### Rollback Plan
If issues arise:
1. Feature flag to revert to early access flow
2. OR: Quick fix and redeploy
3. OR: Full rollback to previous version

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
