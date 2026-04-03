# GitHub Marketplace Assets Tracking

**RFC:** RFC-067 - GitHub Marketplace Publishing
**Status:** TRACKING FOR FUTURE LAUNCH
**Last Updated:** 2025-10-28

---

## Overview

This document tracks all assets required for GitHub Marketplace submission. The marketplace submission is **strategically deferred** until customer signup flow is operational (post RFC-070/071), but all assets are being tracked now to ensure rapid launch when ready.

**Key Insight:** GitHub Actions publish **immediately** without review, so we can submit instantly when signup flow is complete.

---

## 🎯 Asset Checklist

### ✅ COMPLETE - Ready for Launch

| Asset | Status | Location | Notes |
|-------|--------|----------|-------|
| **action.yml** | ✅ READY | `/action.yml` | Marketplace metadata complete |
| **README.md** | ✅ READY | `/README.md` | Marketing-focused, 636 lines |
| **Documentation Site** | ✅ LIVE | https://docs.rsolv.dev | HTTP 200, content complete |
| **Support Email** | ✅ READY | support@rsolv.dev | Configured and working |
| **Workflow Templates** | ✅ READY | `.github/workflows/TEMPLATE-*.yml` | Simple scan + full pipeline |
| **Launch Materials** | ✅ READY | `go-to-market-2025-10/` | ~25,000 words |
| **E2E Testing** | ✅ VERIFIED | Multiple test files | 20/20 tests passing |
| **Backend API** | ✅ PRODUCTION | https://api.rsolv.dev | All endpoints verified |

### ⚠️ PENDING - Needed Before Launch

| Asset | Status | Priority | Blocker | Est. Effort | Notes |
|-------|--------|----------|---------|-------------|-------|
| **Logo (500x500px)** | ⚠️ NEEDED | HIGH | **YES** | 2-4 hours | Shield icon, blue color scheme |
| **Screenshots (3-5)** | ⚠️ NEEDED | HIGH | **YES** | 2-3 hours | Scan, validate, mitigate modes |
| **Customer Signup Flow** | ⚠️ NEEDED | CRITICAL | **YES** | RFC-070/071 | Prerequisite for launch |

### ⏸️ OPTIONAL - Enhances Listing

| Asset | Status | Priority | Blocker | Est. Effort | Notes |
|-------|--------|----------|---------|-------------|-------|
| **Demo Video (3 min)** | ⏸️ OPTIONAL | MEDIUM | NO | 4-6 hours | Screen recording + editing |
| **Usage Analytics** | ⏸️ OPTIONAL | LOW | NO | N/A | Post-launch tracking |
| **Customer Testimonials** | ⏸️ OPTIONAL | LOW | NO | N/A | Collect after beta users |

---

## 📋 Detailed Asset Requirements

### 1. Logo (500x500px PNG) ⚠️

**Status:** NEEDED
**Priority:** HIGH
**Blocker:** YES

#### Requirements
- **Format:** PNG (transparent background preferred)
- **Dimensions:** 500x500 pixels
- **Design:** Shield icon with blue color scheme
- **Style:** Professional, matches GitHub aesthetic

#### Current Status
- action.yml specifies: `icon: 'shield'`, `color: 'blue'`
- Need custom graphic design for marketplace listing
- Temporary: Can use GitHub's default shield icon initially

#### Action Items
- [ ] Hire graphic designer or use design tool
- [ ] Create shield icon with "RSOLV" branding
- [ ] Export at 500x500px PNG
- [ ] Test on GitHub Marketplace preview
- [ ] Optimize file size (<100KB)

#### Estimated Timeline
- Design: 1-2 hours
- Revisions: 1-2 hours
- **Total: 2-4 hours**

---

### 2. Screenshots (3-5 Images) ⚠️

**Status:** NEEDED
**Priority:** HIGH
**Blocker:** YES

#### Requirements
- **Quantity:** 3-5 high-quality screenshots
- **Format:** PNG or JPG
- **Dimensions:** At least 1280x720px (HD)
- **Content:** Show action in real GitHub workflows

#### Required Screenshots

**1. Scan Mode in Action** (REQUIRED)
- Show RSOLV scanning a repository
- Highlight vulnerabilities detected
- Display GitHub Actions workflow output
- Include pattern detection (170+ patterns)

**2. Validate Mode - Test Generation** (REQUIRED)
- Show RED test being generated
- Display test integration into existing file
- Highlight realistic attack vectors (e.g., NoSQL injection)
- Show AST integration (not append)

**3. Mitigate Mode - Fix Application** (REQUIRED)
- Show AI-generated security fix
- Display before/after code comparison
- Highlight test passing after fix (GREEN)
- Show trust score calculation

**4. PR Comment with Results** (RECOMMENDED)
- Show RSOLV comment on GitHub PR
- Display scan results summary
- Include fix recommendations
- Show metrics (files scanned, vulns found, trust score)

**5. GitHub Actions Workflow** (OPTIONAL)
- Show complete workflow YAML
- Highlight configuration options
- Display successful run badge
- Show integration with existing CI/CD

#### Action Items
- [ ] Set up demo repository with vulnerabilities
- [ ] Run RSOLV action in all three modes
- [ ] Capture high-quality screenshots (HD)
- [ ] Annotate screenshots with callouts
- [ ] Optimize images for web (<500KB each)
- [ ] Test on GitHub Marketplace preview

#### Estimated Timeline
- Setup demo repo: 30 minutes
- Capture screenshots: 1 hour
- Editing/annotations: 1-1.5 hours
- **Total: 2-3 hours**

---

### 3. Demo Video (3 minutes) ⏸️

**Status:** OPTIONAL
**Priority:** MEDIUM
**Blocker:** NO

#### Requirements
- **Duration:** 3 minutes maximum
- **Format:** MP4 (H.264 codec)
- **Resolution:** 1080p minimum
- **Content:** End-to-end workflow demonstration

#### Suggested Content

**0:00-0:30 - Introduction**
- What is RSOLV?
- Problem: Insecure code, low test coverage
- Solution: AI-generated security fixes with RED tests

**0:30-1:30 - Scan Mode**
- Show repository with vulnerabilities
- Run RSOLV scan
- Display detected issues (SQL injection, XSS, etc.)
- Highlight 170+ security patterns

**1:30-2:30 - Validate + Mitigate**
- Show RED test generation
- Display test integration into existing file
- Run test (fails on vulnerable code)
- Apply AI fix
- Run test again (passes after fix)
- Show trust score: 100

**2:30-3:00 - Results & Call-to-Action**
- Show PR with fixes and tests
- Display metrics (files scanned, vulns fixed, trust score)
- CTA: "Get started at rsolv.dev"

#### Action Items (If Creating Video)
- [ ] Write script and storyboard
- [ ] Set up screen recording (OBS Studio, Loom, etc.)
- [ ] Record demo walkthrough
- [ ] Edit video (add captions, callouts, branding)
- [ ] Export at 1080p MP4
- [ ] Upload to YouTube (unlisted)
- [ ] Link from marketplace listing

#### Estimated Timeline
- Scripting: 1 hour
- Recording: 1-2 hours
- Editing: 2-3 hours
- **Total: 4-6 hours**

---

### 4. Customer Signup Flow (RFC-070/071) ⚠️

**Status:** IN PROGRESS (Other RFCs)
**Priority:** CRITICAL
**Blocker:** YES - LAUNCH PREREQUISITE

#### Requirements
- User can sign up at rsolv.dev
- User receives API key immediately
- User can access customer portal
- Self-service onboarding complete

#### Dependencies
- **RFC-070:** Customer Authentication & API Key Management
- **RFC-071:** Customer Portal UI & Account Management

#### Current Status
- Backend API operational (api.rsolv.dev)
- Documentation site live (docs.rsolv.dev)
- Support email configured (support@rsolv.dev)
- **Missing:** Self-service signup flow

#### Why This is a Launch Blocker
- Users can install GitHub Action from marketplace
- But cannot get API key to actually use it
- Results in frustrated users and negative reviews
- Better to launch complete product

#### Action Items
- [ ] Wait for RFC-070 completion (authentication)
- [ ] Wait for RFC-071 completion (customer portal)
- [ ] Verify end-to-end signup flow works
- [ ] Test API key generation and validation
- [ ] Confirm self-service onboarding
- [ ] **Then:** Submit to GitHub Marketplace

#### Estimated Timeline
- **Per RFC-070/071 schedules**
- Expected: Post-Integration Week (RFC-069)

---

## 🎨 Logo Design Specifications

### Design Brief

**Concept:** Shield icon representing security protection

**Colors:**
- Primary: Blue (#0066CC or GitHub blue #0969DA)
- Secondary: White or light gray for contrast
- Accent: Optional gradient for depth

**Typography:**
- "RSOLV" text (optional, icon may be standalone)
- Font: Sans-serif, bold, professional
- Consider: GitHub-style typefaces (Inter, SF Pro)

**Style Guidelines:**
- Modern, minimal, professional
- Recognizable at small sizes (favicon)
- Scalable vector graphics (SVG source)
- Works on light and dark backgrounds

**Examples to Reference:**
- GitHub Security icon (shield with checkmark)
- Dependabot logo (simple, friendly)
- GitHub Actions logo (hexagon, workflow)

### Deliverables Needed
1. **Primary Logo:** 500x500px PNG (marketplace requirement)
2. **SVG Source:** Scalable vector for future use
3. **Favicon:** 32x32px for docs.rsolv.dev
4. **Social Media:** 1200x630px for Open Graph images

---

## 📸 Screenshot Capture Guide

### Tools Recommended
- **macOS:** Screenshot (Cmd+Shift+4 for selection)
- **Windows:** Snipping Tool or Greenshot
- **Linux:** Flameshot or GNOME Screenshot
- **Annotations:** Skitch, Snagit, or Photopea

### Capture Settings
- **Resolution:** Retina/HiDPI if possible (2560x1440 or higher)
- **Format:** PNG (lossless) for initial capture
- **Browser:** Chrome or Firefox in full-screen mode
- **Theme:** GitHub light theme (more familiar to users)

### Annotation Best Practices
1. **Arrows:** Point to key features
2. **Callouts:** Explain what's happening
3. **Highlights:** Use colored boxes/circles to draw attention
4. **Text:** Keep annotations concise (5-10 words max)
5. **Consistency:** Use same color scheme across all screenshots

### Before Capture Checklist
- [ ] Demo repository is clean (no unrelated noise)
- [ ] GitHub Actions workflow is successful
- [ ] RSOLV output is clear and complete
- [ ] No sensitive information visible (API keys, tokens)
- [ ] Browser window is maximized
- [ ] Zoom level is 100% (not 125% or 150%)

---

## 🚀 Launch Sequence (When Ready)

### Pre-Launch Checklist
- [ ] Logo created (500x500px PNG)
- [ ] 3-5 screenshots captured and annotated
- [ ] Customer signup flow operational (RFC-070/071 complete)
- [ ] action.yml verified with latest metadata
- [ ] README.md final review
- [ ] docs.rsolv.dev content review
- [ ] Backend API production verified
- [ ] E2E testing re-run and passing
- [ ] Launch materials reviewed (~25,000 words)

### Launch Day Tasks
1. **Upload Assets to Repository**
   - Add logo to `/assets/logo.png`
   - Add screenshots to `/assets/screenshots/`
   - Update README with screenshots
   - Commit and push to main branch

2. **Create GitHub Release**
   - Tag: `v1.0.0` (first marketplace release)
   - Title: "RSOLV v1.0.0 - GitHub Marketplace Launch"
   - Description: Release notes with changelog
   - Attach: Logo and screenshots (GitHub auto-publishes)

3. **Verify Marketplace Listing**
   - Check https://github.com/marketplace/actions/rsolv
   - Verify logo displays correctly
   - Verify screenshots are visible
   - Test "Use this action" button

4. **Execute Launch Plan**
   - Publish blog post (LAUNCH-BLOG-POST.md)
   - Send email to warm network (EMAIL-TEMPLATE-WARM-NETWORK.md)
   - Post on social media (SOCIAL-MEDIA-LAUNCH-POSTS.md)
   - Submit to Hacker News (HACKER-NEWS-SHOW-HN.md)

5. **Monitor Metrics**
   - GitHub Marketplace installs
   - API key activations (from customer portal)
   - Support email volume (support@rsolv.dev)
   - User feedback and reviews

### Post-Launch Monitoring
- **Day 1-7:** Daily metrics check, respond to early feedback
- **Day 7-30:** Weekly metrics review, adjust messaging if needed
- **Day 30:** Evaluate against success criteria (15-30 installs)
- **Day 90:** Evaluate paying customer acquisition (1-2 customers)

---

## 📊 Asset Completion Status

### Overall Progress: 60% Complete

```
✅ COMPLETE (60%)
├── action.yml (marketplace metadata)
├── README.md (marketing content)
├── Documentation site (docs.rsolv.dev)
├── Support infrastructure (support@rsolv.dev)
├── Workflow templates (YAML files)
├── Launch materials (~25,000 words)
├── E2E testing (20/20 tests passing)
└── Backend API (production-ready)

⚠️ IN PROGRESS (30%)
├── Customer signup flow (RFC-070/071)
└── [Waiting for dependency RFCs]

⚠️ NEEDED (10%)
├── Logo (500x500px PNG) - 2-4 hours
└── Screenshots (3-5 images) - 2-3 hours
```

**Estimated Time to Complete:** 4-7 hours (logo + screenshots)
**PLUS:** RFC-070/071 completion (customer signup)

---

## 🎯 Success Metrics (Post-Launch)

### 30-Day Targets
- **Installs:** 15-30 GitHub repositories
- **Active Users:** 10-20 developers
- **API Calls:** 100-500 security scans
- **Support Tickets:** <5 (low friction indicates good UX)

### 90-Day Targets
- **Paying Customers:** 1-2 on Pro plan
- **Total Installs:** 50-100 repositories
- **Monthly Scans:** 500-1000
- **User Retention:** >60% (users scanning regularly)

### Qualitative Success
- ✅ Positive user feedback and reviews
- ✅ Low support burden (docs are effective)
- ✅ Users discover RSOLV organically (SEO, word-of-mouth)
- ✅ Feature requests indicate engagement

---

## 📚 Related Documentation

### Week Progress Documents
- **Week 1:** `docs/rfcs/RFC-067-WEEK-1-PROGRESS.md`
- **Week 2:** `/home/dylan/dev/rsolv/projects/go-to-market-2025-10/RFC-067-WEEK-2-PROGRESS.md`
- **Week 3:** `WEEK-3-E2E-VERIFICATION.md`

### Launch Materials (Week 2)
- `MARKETPLACE-SUBMISSION-CHECKLIST.md` - Publication process
- `LAUNCH-BLOG-POST.md` - Blog post content
- `EMAIL-TEMPLATE-WARM-NETWORK.md` - Email outreach
- `SOCIAL-MEDIA-LAUNCH-POSTS.md` - Social content
- `HACKER-NEWS-SHOW-HN.md` - HN submission
- `FAQ-DOCUMENTATION.md` - Customer FAQs
- `PRESS-KIT.md` - Media resources

### Technical Documentation
- `action.yml` - Action metadata
- `README.md` - User guide
- `docs/PHASE-4-E2E-TESTING.md` - E2E testing
- `docs/THREE-PHASE-ARCHITECTURE.md` - Architecture

---

## 🎓 Lessons Learned

### What Worked Well
1. ✅ **Strategic Deferral**
   - Avoiding premature launch prevents user frustration
   - Assets tracked now, rapid launch when ready

2. ✅ **Complete Technical Preparation**
   - All engineering work complete (E2E tests, API, docs)
   - Only asset creation (design) remains

3. ✅ **Comprehensive Launch Materials**
   - ~25,000 words ready to deploy
   - Multiple channels prepared (blog, email, social, HN)

### Areas for Improvement
1. ⚠️ **Asset Creation Timing**
   - Could have started design earlier
   - Graphic design is often on critical path

2. ⚠️ **Screenshot Automation**
   - Consider automated screenshot generation in CI
   - Keep screenshots up-to-date with product changes

3. ⚠️ **Video Production**
   - Demo video would enhance listing significantly
   - Resource constraint - consider post-launch

---

## 📝 Notes

### Design Resources
- **Freelance Designers:** Fiverr, Upwork ($50-200 for logo)
- **DIY Tools:** Canva, Figma, Adobe Express
- **Icon Libraries:** Heroicons, Feather Icons, Font Awesome
- **Color Palette:** GitHub brand guide, Tailwind CSS colors

### Screenshot Tools
- **Capture:** Native OS tools (free)
- **Annotation:** Skitch (free), Snagit ($50)
- **Editing:** Photopea (free, web-based), GIMP (free), Photoshop ($10/mo)

### Video Production
- **Recording:** OBS Studio (free), Loom (free tier), ScreenFlow ($169)
- **Editing:** DaVinci Resolve (free), iMovie (free on macOS), Adobe Premiere ($21/mo)
- **Hosting:** YouTube (unlisted), Vimeo (free tier)

---

## ✅ Action Items Summary

### Immediate (Ready to Execute)
- [ ] Create logo (2-4 hours) - Can start any time
- [ ] Capture screenshots (2-3 hours) - Can start any time

### Waiting on Dependencies
- [ ] Customer signup flow (RFC-070/071) - In progress
- [ ] Final marketplace submission - After dependencies complete

### Optional Enhancements
- [ ] Create demo video (4-6 hours) - Post-launch OK
- [ ] Collect customer testimonials - Post-launch
- [ ] Set up usage analytics - Post-launch

---

**Document Version:** 1.0
**Last Updated:** 2025-10-28
**Maintained By:** RSOLV Engineering Team
**Review Status:** ✅ Asset tracking complete, ready for execution
