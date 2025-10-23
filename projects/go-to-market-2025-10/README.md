# Go-to-Market Launch Project (2025-10)

**Status:** In Progress - Week 0 Complete ✅
**Timeline:** Weeks 0-6 (Oct 23 - Dec 2025)
**Project Lead:** Dylan
**RFCs:** 064-069 (Master Plan, Provisioning, Billing, Marketplace, Testing, Integration Week)

## Overview

This directory contains working documents for the 6-week go-to-market launch project, implementing RFCs 064-069 to transform RSOLV from manual provisioning to fully automated self-service with GitHub Marketplace presence.

**Target State:**
- Instant customer provisioning from multiple sources (marketplace, direct signup, early access)
- Automated Stripe billing with Pro plan ($599/month)
- GitHub Marketplace listing
- Self-service onboarding (no manual intervention)

## Week 0 Status ✅ COMPLETE

### Completed Security & Infrastructure
- ✅ **Pre-commit Security Hook** - Blocks Stripe production keys (`sk_live_*`)
  - Location: `/home/dylan/dev/rsolv/.git/hooks/pre-commit`
  - Verified `.env` in `.gitignore` and `.env.example` has only placeholders
  - Tested successfully (blocks commits with fake keys)

- ✅ **Support Infrastructure Verification**
  - `support@rsolv.dev` - Configured and forwarding to dylan@arborealstudios.com
  - `docs.rsolv.dev` - **⚠️ BLOCKER: Exists but returns 404 (no content)**

- ✅ **Customer Development Framework**
  - Created quality-focused beta tester outreach plan (5 contacts → 3-5 testers)
  - See `CUSTOMER-TRACTION-TRACKING.md` for tracking

- ✅ **Telemetry Event Registry**
  - Created namespace registry to prevent RFC collisions
  - See `INTEGRATION-CHECKLIST.md` Appendix for event definitions

- ✅ **Branching Strategy Established**
  - Integration branch approach (Option A) chosen
  - Branch `feature/billing-provisioning-integration` created
  - All RFC work branches from/merges to integration branch (NOT main)

### Week 0 Documents
- `WEEK-0-COMPLETION.md` - Detailed Week 0 completion summary
- `CUSTOMER-TRACTION-TRACKING.md` - Beta tester outreach tracking
- `INTEGRATION-CHECKLIST.md` - RFC-065-068 integration readiness criteria + telemetry registry

## Branching Strategy

**Integration Branch Approach:** All RFC implementations use `feature/billing-provisioning-integration` as base.

**Workflow for RFC Implementers:**
```bash
# Start new RFC work
git checkout feature/billing-provisioning-integration
git pull
git checkout -b feature/rfc-065-customer-onboarding  # or rfc-066, rfc-068

# ... do work ...
git commit -m "RFC-065: Add email verification"
git push -u origin feature/rfc-065-customer-onboarding

# Open PR targeting feature/billing-provisioning-integration (NOT main)
# After review, merge to integration branch
```

**Week 4 Integration:**
- Integration branch continuously integrates all RFCs (Weeks 1-3)
- Week 4: Full E2E testing on integration branch
- After stable: Merge `feature/billing-provisioning-integration` → `main`

**Expected File Conflicts** (resolve during integration):
- `mix.exs` - Both RFC-065 and RFC-066 add dependencies
- `lib/rsolv_web/router.ex` - Both add routes
- `config/config.exs` - Both add configuration
- `priv/repo/migrations/` - Sequential timestamps (no conflict)

See `INTEGRATION-CHECKLIST.md` for conflict resolution protocol.

## Critical Blocker

### docs.rsolv.dev Has No Content ⚠️
- **Impact:** Blocks GitHub Marketplace submission (Week 2 per RFC-067)
- **Required Content:**
  - Installation guide (GitHub Actions setup)
  - Troubleshooting section (5+ common issues)
  - API reference (platform endpoints if applicable)
- **Current:** Domain accessible with SSL, returns 404
- **Timeline:** Must complete during Week 1 before marketplace submission

## Active Vibe Kanban Tasks

See [Vibe Kanban Rsolv Project](https://app.vibekanban.com):

1. **Create docs.rsolv.dev content** (HIGH PRIORITY)
2. **Identify 5 warm network contacts for beta testing**
3. **Send personalized outreach to contacts**
4. **Test social media posting** (Mastodon, Bluesky, LinkedIn)
5. **Follow up with beta tester responses (Week 1)**

## RFC Implementation Timeline

### Week 0 (Oct 23-30) ✅
- Security controls established
- Support infrastructure verified
- Customer development framework created
- **Next:** docs.rsolv.dev creation (blocker)

### Week 1 (Oct 30 - Nov 6)
**Foundation Week** - Per RFC-064 tasks:
- RFC-065: Build provisioning pipeline, email validation, customer creation
- RFC-066: Add Stripe dependency, create service module, webhook endpoint
- RFC-067: Update action.yml, create logo, improve docs, **submit to marketplace**
- RFC-068: Docker Compose setup, Stripe CLI, test factories

### Week 2 (Nov 6-13)
**Core Features** - Per RFC-064 tasks:
- RFC-065: Customer dashboard LiveView, usage statistics
- RFC-066: Payment methods, subscriptions, usage billing, invoices
- RFC-067: Marketplace review response, demo video, launch materials
- RFC-068: Integration tests, CI/CD, staging deployment

### Week 3 (Nov 13-20)
**Polish & Testing**
- Complete all RFC features to 80%+ readiness
- Prepare for Week 4 integration

### Week 4 (Nov 20-27) - Integration Week
**RFC-069: Integration Week**
- Monday: Integration kickoff
- Tue-Thu: Resolve conflicts, end-to-end testing
- Friday: Production deployment

### Week 5-6 (Nov 27 - Dec 11)
**Launch & Optimize**
- Production preparation and monitoring
- Public launch
- Customer support and iteration

## Integration Ready Criteria

All RFCs must meet readiness criteria before Week 4 integration (see `INTEGRATION-CHECKLIST.md`):
- All tests passing (`mix test`)
- OpenAPI specs complete
- Deployed to staging
- No hardcoded secrets
- ADRs created

## Project Documents

- `README.md` - This file (project overview and status)
- `INTEGRATION-CHECKLIST.md` - Integration readiness tracking for RFCs 065-068
  - **Appendix**: Interface contracts and specifications (data types, function signatures, migration coordination)
- `CUSTOMER-TRACTION-TRACKING.md` - Beta tester outreach and conversion tracking
- `WEEK-0-COMPLETION.md` - Week 0 detailed completion summary

## Archive Instructions

Upon project completion (post-Week 6 launch):

1. **Archive this directory:**
   ```bash
   mv projects/go-to-market-2025-10 archived_docs/go-to-market-2025-10
   ```

2. **Transfer permanent knowledge to:**
   - ADR-025: Customer Onboarding Implementation (RFC-065)
   - ADR-026: Billing & Credits Implementation (RFC-066)
   - ADR-027: GitHub Action Polish Implementation (RFC-067)
   - ADR-028: Testing Standards Implementation (RFC-068)
   - Relevant API documentation (OpenAPI specs)
   - Developer guides (`docs/`)

3. **Delete temporary/obsolete content** that was only useful during integration.

## References

- RFC-064: Billing & Provisioning Master Plan (6-week timeline)
- RFC-065: Automated Customer Provisioning
- RFC-066: Stripe Billing Integration
- RFC-067: GitHub Marketplace Publishing
- RFC-068: Billing Testing Infrastructure
- RFC-069: Integration Week Plan

## Success Metrics

**Week 0:**
- ✅ Pre-commit hook prevents credential leaks
- ✅ Support email verified
- ⏳ 5 warm contacts identified and reached out to
- ⏳ 3-5 beta testers confirmed by Week 3

**Week 6 Launch:**
- Automated provisioning working from all sources
- Stripe billing processing payments
- GitHub Marketplace listing live
- Zero-intervention customer onboarding
