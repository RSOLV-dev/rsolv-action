# RFC-067: GitHub Marketplace Submission Decision

**Decision Date**: 2025-10-30
**Decision**: **Continue Strategic Deferral**
**Status**: Approved
**Next Review**: Upon RFC-069 completion (Integration Week)

## Executive Summary

After comprehensive analysis of readiness, market conditions, and strategic dependencies, we recommend **continuing the strategic deferral** of GitHub Marketplace submission until the customer signup flow (RFCs 064-069) is complete and deployed to production.

**Key Rationale**: GitHub Actions publish immediately without review period, enabling instant submission when ready. Submitting now would create a poor first impression with users who can install the action but cannot sign up for API keys.

## Decision

**DEFER marketplace submission until:**
1. ✅ Customer signup flow operational (RFC-065)
2. ✅ Stripe billing integrated (RFC-066)
3. ✅ Integration week complete (RFC-069)
4. ✅ Production deployment stable (24+ hours)
5. ✅ End-to-end flow tested (install → signup → scan)

**Estimated submission date**: Week of November 11-18, 2025 (post-RFC-069)

## Analysis: Submit Now vs Wait

### Option A: Submit Now (NOT RECOMMENDED)

**Pros:**
- ✅ All documentation complete (~25k words)
- ✅ action.yml updated and validated
- ✅ README marketplace-ready
- ✅ Rate limiting implemented (500/hour)
- ✅ docs.rsolv.dev deployed (8 pages)
- ✅ Technical infrastructure ready

**Cons (Critical Issues):**
- ❌ **No customer signup flow** - Users hit dead end after install
- ❌ **Poor first impression** - Can't get API key, can't use product
- ❌ **Support burden** - Manual API key generation required
- ❌ **Marketplace reviews** - Negative reviews hurt long-term discoverability
- ❌ **Wasted launch momentum** - Can't convert interested users
- ❌ **Trust damage** - "Product not ready" perception hard to overcome

**Risk Assessment**: **CRITICAL - Do not submit**

### Option B: Continue Deferral (RECOMMENDED)

**Pros:**
- ✅ **Complete user journey** - Install → signup → API key → scan (seamless)
- ✅ **Professional first impression** - Product actually works end-to-end
- ✅ **No review delay** - GitHub Actions publish instantly, no lost time
- ✅ **Launch coordination** - Marketplace + billing go live together
- ✅ **Conversion ready** - Can capture interested users immediately
- ✅ **Positive reviews** - Users have working product to review
- ✅ **Support efficiency** - Automated provisioning reduces manual work

**Cons:**
- ⚠️ Delayed marketplace presence (2-3 weeks)
- ⚠️ Prep work sitting idle temporarily

**Risk Assessment**: **LOW - Recommended approach**

## Strategic Rationale

### 1. GitHub Marketplace Dynamics

**Key Insight**: GitHub Actions publish **immediately** with no review period.

- Traditional app stores: Submit → Wait days/weeks → Approval → Launch
- GitHub Marketplace: Submit → **Instant publication** → Live immediately

**Implication**: We can submit the moment we're ready. No penalty for waiting.

### 2. First Impression is Everything

Marketplace success depends heavily on:
1. **Initial install experience** - Does it work immediately?
2. **User reviews** - Early reviews set reputation for years
3. **Support requests** - High friction = negative perception

**Current state without signup flow:**
```
User installs action
  → Needs API key
    → Visits rsolv.dev
      → No signup button
        → Emails support@rsolv.dev
          → Waits for manual provisioning
            → 😞 Frustrated user, likely abandons
```

**Future state with signup flow:**
```
User installs action
  → Needs API key
    → Visits rsolv.dev/signup
      → Enters email
        → API key delivered instantly
          → Returns to workflow
            → First scan succeeds
              → 😊 Delighted user, likely converts
```

### 3. Launch Coordination Benefits

Publishing marketplace + billing together enables:
- **Unified launch announcement** (blog, social, Hacker News)
- **Working demo** for launch day (install → scan → results)
- **Conversion capture** (interested users → paying customers immediately)
- **Authentic testimonials** (users with real experience, not just install)

### 4. Documentation Site Review Requirement

**Blocking Issue Identified** (RFC-067 line 230-233):

```
- [ ] **BLOCKING**: Human review of docs site content before marketplace submission
  - Review all 8 pages at https://docs.rsolv.dev for accuracy, completeness, and professionalism
  - [... full review criteria ...]
  - Sign-off required before proceeding with marketplace submission
```

**Status**: ❌ Human review not yet completed

**Pages requiring review:**
1. Installation guide with workflow examples
2. Troubleshooting (8 common issues)
3. API reference (pattern/validation endpoints)
4. FAQ (15+ questions)
5. Workflow templates (5 ready-to-use)
6. Configuration options
7. Getting started tutorial
8. Documentation landing page

**Action Required**: Dylan to review all docs.rsolv.dev content before submission.

## Prerequisites for Submission

### Must Complete (Production Blockers)

From RFC-067 and RFC-069:

**Technical Prerequisites:**
- [x] action.yml updated with marketplace metadata (completed Week 1)
- [x] README rewritten for marketplace format (completed Week 2)
- [x] Rate limiting implemented (500/hour per API key, Mnesia-based)
- [x] Documentation site deployed (docs.rsolv.dev with 8 pages)
- [ ] **BLOCKING**: Human review of docs.rsolv.dev content
- [ ] Logo created (500x500px, shield icon, blue color)
- [ ] Screenshots captured (3-5 high-quality images)
- [x] support@rsolv.dev configured and monitored (forwards to dylan@arborealstudios.com)

**Integration Prerequisites (RFCs 064-069):**
- [ ] RFC-065: Automated provisioning working (signup → API key)
- [ ] RFC-066: Stripe billing integrated (payment → credits)
- [ ] RFC-069: Integration week complete (all systems connected)
- [ ] Production deployment stable (24+ hours, no critical errors)
- [ ] End-to-end tested (install → signup → scan → billing)

**Launch Prerequisites:**
- [x] Launch blog post written (~3,000 words)
- [x] Email templates created (3 versions + follow-ups)
- [x] Social media content prepared (Mastodon, Bluesky, LinkedIn)
- [x] Hacker News post drafted (Show HN format)
- [x] FAQ documentation complete (50+ questions)
- [x] Press kit ready (founder bio, quotes, boilerplate)
- [ ] Demo video recorded (3-5 minute walkthrough, optional but recommended)
- [ ] NodeGoat/RailsGoat testing complete (E2E validation)

### Should Complete (Nice to Have)

- [ ] Demo video created (installation walkthrough)
- [ ] Case study from early beta user
- [ ] GitHub Stars program application (if eligible)
- [ ] Partnership outreach prepared (high-profile OSS projects)

## Submission Timeline

### Current Phase: Integration (Week 4 of RFC-064)
**Dates**: October 28 - November 3, 2025
**Focus**: Connect provisioning, billing, marketplace, testing (RFC-069)

**Status**: In progress (currently October 30)

### Week 5: Production Preparation
**Dates**: November 4-10, 2025
**Focus**: Final staging verification, E2E testing, performance validation

**Key Milestones:**
- Staging stable 24+ hours
- E2E test suite passing (signup → scan → billing)
- Load testing complete
- Rollback procedures tested
- Support documentation verified

**Gate Criteria:**
- [ ] All "Must Complete" items checked
- [ ] Human review of docs.rsolv.dev complete and signed off
- [ ] E2E flow working (install → signup → scan)
- [ ] No critical bugs in staging
- [ ] Monitoring and alerting operational

### Week 6: Production Launch + Marketplace Submission
**Dates**: November 11-17, 2025
**Focus**: Deploy to production, submit to marketplace, execute launch plan

**Monday (Nov 11): Production Deployment**
- Deploy billing/provisioning to production
- Verify signup flow working
- Monitor for 24 hours

**Wednesday (Nov 13): Marketplace Submission**
- Upload logo and screenshots
- Draft GitHub Release (tag v1.0.0 or appropriate version)
- Check "Publish to GitHub Marketplace"
- Select categories: Security (primary), Code Quality, CI/CD
- **Action goes live immediately** (no review wait)

**Thursday (Nov 14): Launch Execution**
- Publish blog post (rsolv.dev/blog)
- Email warm network (3 templates)
- Social media blitz (Mastodon, Bluesky, LinkedIn)
- Hacker News Show HN post
- Dev.to and Medium cross-posting

**Friday (Nov 15): Active Monitoring**
- Respond to all comments/questions within 1-4 hours
- Monitor installation metrics
- Track signup → conversion flow
- Fix any critical issues immediately

## Success Metrics

### Launch Metrics (First 30 Days)

From RFC-067 and RFC-064:

| Metric | Target | Measurement |
|--------|--------|-------------|
| Marketplace Installs | 15-30 | GitHub Marketplace dashboard |
| Trial Signups | 3-6 (~20% conversion) | Database: `customers.subscription_type = 'trial'` |
| Paying Customers | 1-2 | Database: `customers.subscription_type IN ('pay_as_you_go', 'pro')` |
| Marketplace Rating | 4.5+ stars | GitHub Marketplace listing (if reviews received) |
| Support Response Time | <24 hours (goal: <4 hours) | support@rsolv.dev tracking |

**Pivot Indicators** (when to adjust strategy):
- <10 installs in first 30 days → Reassess GTM strategy, increase marketing
- <15% trial signup rate → Improve onboarding, reduce friction
- High churn (>50% in 7 days) → Polish trial experience, add value
- Negative reviews → Emergency support/fix cycle, over-communicate

### Business Metrics (Post-Launch, Ongoing)

From RFC-064:

| Metric | Target | Tracking Frequency |
|--------|--------|-------------------|
| Trial → Paid Conversion | ≥ 15% | Weekly |
| Monthly Churn Rate | < 5% | Monthly |
| Customer Lifetime Value | > $300 | Monthly |
| Monthly Recurring Revenue | Growth trend | Monthly |

## Risks & Mitigation

### Critical Risks

| Risk | Impact | Probability | Mitigation |
|------|--------|-------------|------------|
| **No customer traction** | **Critical** | **Medium** | Multi-channel GTM (RFC-067), warm network outreach, content marketing. Track daily in `CUSTOMER-TRACTION-TRACKING.md`. |
| Integration issues delay launch | High | Medium | RFC-069 integration week, continuous testing, rollback plan ready |
| Negative marketplace reviews | High | Low | Delay until product fully working, excellent support (<4hr response) |
| Production instability | High | Low | Staging validation (24+ hours stable), feature flags, monitoring |

### Medium Risks

| Risk | Impact | Probability | Mitigation |
|------|--------|-------------|------------|
| Documentation gaps discovered | Medium | Medium | Human review of docs.rsolv.dev before submission (BLOCKING) |
| Support overload | Medium | Low | Automated provisioning reduces manual work, comprehensive FAQ |
| Stripe payment failures | Medium | Low | Extensive testing in staging, webhook retry logic, monitoring |

## Communication Plan

**Two-person operation (Dylan + Claude)** - formal plan not needed, but key touchpoints:

### Pre-Submission
- **Daily**: Progress updates via Claude Code sessions during RFC-069
- **Weekly**: Review RFC-069 checklist (Monday integration, Friday completion)
- **Blocking**: Human review of docs.rsolv.dev must complete before submission approval

### Launch Week
- **Daily**: Monitor metrics, respond to users, fix issues
- **Real-time**: Critical bug response (<4 hours)
- **Weekly**: Customer traction review (track in CUSTOMER-TRACTION-TRACKING.md)

### Post-Launch
- **Daily** (Week 1): Close monitoring, rapid iteration
- **Weekly** (Weeks 2-4): Metrics review, content updates
- **Monthly**: Business metrics, strategic adjustments

## Recommendation

**CONTINUE STRATEGIC DEFERRAL** until RFCs 064-069 complete.

### Approval Criteria

Before submission, ALL must be true:
1. ✅ RFC-069 integration week complete
2. ✅ Production deployment stable (24+ hours)
3. ✅ E2E flow tested and working (install → signup → scan → billing)
4. ✅ Human review of docs.rsolv.dev complete and signed off (BLOCKING)
5. ✅ Logo and screenshots ready
6. ✅ Launch materials prepared (blog, email, social)
7. ✅ Monitoring and alerting operational
8. ✅ Rollback plan tested

**Estimated submission date**: November 13, 2025 (Week 6, Day 3)

## Next Actions

### Immediate (This Week - Integration Week)
- [ ] Continue RFC-069 integration work
- [ ] Monitor staging stability
- [ ] Address integration issues as they arise

### Week 5 (Nov 4-10): Production Prep
- [ ] **CRITICAL**: Dylan reviews all docs.rsolv.dev content for sign-off
- [ ] Create logo (500x500px, shield icon, blue color)
- [ ] Capture screenshots (3-5 images from demo workflow)
- [ ] Final E2E testing (NodeGoat, RailsGoat, real OSS project)
- [ ] Verify staging stable 24+ hours
- [ ] Deploy to production (feature-flagged if needed)
- [ ] Record demo video (optional, 3-5 minutes)

### Week 6 (Nov 11-17): Launch
- [ ] **Monday**: Production deployment, verify signup flow
- [ ] **Wednesday**: Submit to GitHub Marketplace
- [ ] **Thursday**: Execute launch plan (blog, email, social, HN)
- [ ] **Friday**: Active monitoring, user support, rapid iteration

## Approval

**Recommended by**: Claude Code (AI Analysis)
**Decision authority**: Dylan Fitzgerald
**Date**: 2025-10-30

**Approval signature**: _______________ (Dylan Fitzgerald)

## References

- **RFC-067**: `/RFCs/RFC-067-GITHUB-MARKETPLACE-PUBLISHING.md`
- **RFC-064**: `/RFCs/RFC-064-BILLING-PROVISIONING-MASTER-PLAN.md`
- **RFC-069**: `/RFCs/RFC-069-INTEGRATION-WEEK.md`
- **Week 2 Progress**: `/projects/go-to-market-2025-10/RFC-067-WEEK-2-PROGRESS.md`
- **Launch Materials**: `/projects/go-to-market-2025-10/` (7 documents, ~25k words)

---

**Document Status**: Draft for review
**Next Review**: Upon RFC-069 completion (estimated Nov 3, 2025)
**Update Frequency**: Weekly during integration, daily during launch week
