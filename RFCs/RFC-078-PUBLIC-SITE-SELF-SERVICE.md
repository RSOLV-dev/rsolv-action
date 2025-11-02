# RFC-078: Public Site & Self-Service Signup

**Status**: Draft (Week 5 - Production Preparation)
**Created**: 2025-11-01
**Timeline**: 1 week (Week 5, parallel to production prep)
**Priority**: Critical (blocks launch)
**Author**: Product Team

## Related RFCs

**Dependencies (Required):**
- RFC-064 (Billing & Provisioning Master Plan) - Coordination
- RFC-065 (Automated Customer Provisioning) - Backend API
- RFC-066 (Stripe Billing Integration) - Billing backend
- RFC-069 (Integration Week) - Must complete first

**Enables:**
- RFC-070 (Customer Authentication) - Login after signup
- RFC-071 (Customer Portal UI) - Post-login dashboard
- RFC-067 (GitHub Marketplace Publishing) - Public launch

## Quick Start

**Current State**: Backend billing/provisioning ready, but no public-facing signup flow.

**Target State**: Complete self-service customer journey from landing → signup → onboarding → first fix.

**Key Pages:**
- `/` - Landing page with value prop and CTA
- `/pricing` - Transparent pricing with Pro/PAYG comparison
- `/signup` - Self-service signup form (replaces early access waitlist)

**Critical Gap**: Can't launch billing without public signup pages.

## Summary

Create public-facing pages that enable self-service customer acquisition and align marketing messaging with the new billing model (10 free credits, Pro plan at $599/month, PAYG at $29/fix). Convert existing early access waitlist into production signup flow.

**Scope**: Public pages only. Customer portal (RFC-071) is separate, post-auth work.

## Problem Statement

### The Gap

**Backend is Ready:**
- ✅ API-first customer onboarding (RFC-065)
- ✅ Stripe billing integration (RFC-066)
- ✅ Credit system (5 free + 5 with payment)
- ✅ Pro plan ($599/month, 60 fixes)
- ✅ PAYG pricing ($29/fix)

**Customer-Facing is Missing:**
- ❌ No way to discover pricing (no /pricing page)
- ❌ No self-service signup (early_access_live.ex is waitlist)
- ❌ Landing page still shows "request early access"
- ❌ No alignment with "10 free credits" messaging
- ❌ No public CTAs for conversion

### Impact

**Without public pages:**
- Can't onboard customers independently
- Can't run marketing campaigns
- Can't launch GitHub Marketplace
- Backend capabilities invisible to customers
- Poor first impression (404 on /signup)

**Current User Experience (Broken):**
```
User visits rsolv.dev
  → Sees "Request Early Access"
  → Submits email to waitlist
  → Gets confirmation email
  → **DEAD END** (no follow-up, manual provisioning required)
```

**Target User Experience (Self-Service):**
```
User visits rsolv.dev
  → Sees "Get 10 Free Credits"
  → Clicks "Start Free Trial"
  → Lands on /signup
  → Enters email
  → Creates account (RFC-065 API)
  → Receives welcome email with API key
  → Follows setup wizard to first fix
```

## Proposed Solution

### Three Core Pages

#### 1. Landing Page (/) - Marketing & Conversion

**Current State**: Early access messaging (outdated)

**New Design:**
```html
<!-- Hero Section -->
<section class="hero">
  <h1>Automated Security Fixes for Your Codebase</h1>
  <p>AI-powered vulnerability detection and remediation.
     Get 10 free credits to start.</p>
  <button>Start Free Trial</button>
  <span>No credit card required</span>
</section>

<!-- Value Proposition -->
<section class="features">
  - Detects real vulnerabilities (not false positives)
  - Generates tested fixes automatically
  - Creates pull requests with validation
  - Supports JavaScript, Python, Ruby
</section>

<!-- Social Proof -->
<section class="testimonials">
  - Beta customer quotes
  - Fix attempt statistics
  - Framework coverage
</section>

<!-- Pricing Teaser -->
<section class="pricing-cta">
  <h2>Start with 10 Free Credits</h2>
  <p>Upgrade to Pro ($599/month, 60 fixes) or pay as you go ($29/fix)</p>
  <a href="/pricing">View Full Pricing</a>
</section>
```

**Key Messaging:**
- Clear value proposition (security + automation)
- Trust signals (real vulnerabilities, tested fixes)
- Low friction (10 free credits, no card)
- Social proof (when available)

**Conversion Goals:**
- Primary: Click "Start Free Trial" → /signup
- Secondary: Learn more → /pricing
- Tertiary: Explore docs → docs.rsolv.dev

#### 2. Pricing Page (/pricing) - Transparency & Trust

**Design Principles:**
- Crystal clear pricing (no hidden fees)
- Visual comparison (Trial vs Pro vs PAYG)
- Calculator (estimate your cost)
- FAQ (address common questions)

**Pricing Table:**
```
┌──────────────┬──────────────┬──────────────┐
│ Free Trial   │ Pro Plan     │ Pay-As-You-Go│
├──────────────┼──────────────┼──────────────┤
│ 10 credits   │ $599/month   │ $29/fix      │
│ (5 + 5*)     │ 60 fixes     │ No minimum   │
│              │ $15 overage  │              │
│ No card      │ Best value   │ Flexible     │
│ required     │ at scale     │ usage        │
└──────────────┴──────────────┴──────────────┘

* 5 on signup, +5 when adding payment method
```

**Interactive Calculator:**
```
"How many fixes per month?" [Slider: 0-100]

You: 25 fixes/month
- Trial: Free for first 10 fixes
- Pro: $599/month (save $126 vs PAYG)
- PAYG: $725/month

Recommendation: Pro plan saves you money!
```

**FAQ Section:**
- What counts as a "fix"?
- When does billing start?
- How do credits work?
- What if I exceed 60 fixes on Pro?
- Can I cancel anytime?
- Do you offer refunds?

**Trust Elements:**
- Money-back guarantee (if applicable)
- Cancel anytime policy
- Transparent billing schedule
- Contact support link

#### 3. Signup Page (/signup) - Frictionless Onboarding

**Current State**: early_access_live.ex (waitlist)

**New Flow:**
```
1. Email capture
   - Email validation (no disposable domains)
   - Rate limiting (10/hour per IP)
   - Privacy policy acceptance

2. Account creation (RFC-065 API)
   - POST /api/v1/customers/onboard
   - Returns: customer_id, api_key
   - 5 credits automatically added

3. Success state
   - Show API key prominently (copy button)
   - Warning: "Save this now - shown only once"
   - Next steps: Setup wizard link
   - Email confirmation sent (backup)

4. Post-signup
   - Redirect to setup wizard (when RFC-071 ready)
   - OR show installation instructions inline
   - Download workflow file button
   - Test connection link
```

**Form Design (Minimal Friction):**
```html
<form action="/signup" method="post">
  <input type="email" name="email" required
         placeholder="your@email.com">

  <label>
    <input type="checkbox" required>
    I agree to the <a href="/terms">Terms</a> and
    <a href="/privacy">Privacy Policy</a>
  </label>

  <button type="submit">Start Free Trial</button>

  <p class="subtext">
    Get 10 free credits. No credit card required.
  </p>
</form>
```

**Success Screen:**
```html
<div class="success">
  <h1>🎉 Welcome to RSOLV!</h1>

  <div class="api-key-display">
    <label>Your API Key (save this now!):</label>
    <code>rsolv_abc123...</code>
    <button>Copy</button>
  </div>

  <div class="next-steps">
    <h2>Next Steps:</h2>
    <ol>
      <li>Add API key to GitHub secrets</li>
      <li>Install RSOLV workflow</li>
      <li>Run your first scan</li>
    </ol>

    <a href="/dashboard/setup">Start Setup Wizard</a>
    <a href="https://docs.rsolv.dev">View Documentation</a>
  </div>

  <p class="email-note">
    We've also emailed your API key to {email}
  </p>
</div>
```

**Error Handling:**
- Duplicate email → "Account exists. <a href="/login">Sign in?</a>"
- Invalid email → Inline validation
- Rate limit exceeded → "Too many attempts. Try again in X minutes."
- Server error → "Something went wrong. Please try again or contact support."

### Architecture & Implementation

#### File Structure
```
lib/rsolv_web/
├── live/
│   ├── landing_live.ex            # Landing page (/)
│   ├── pricing_live.ex            # Pricing page (/pricing)
│   └── signup_live.ex             # Signup page (/signup, convert from early_access_live.ex)
├── controllers/
│   └── page_controller.ex         # Static pages (if needed)
└── templates/
    └── layout/
        ├── public.html.heex       # Layout for public pages
        └── marketing.css          # Marketing-specific styles
```

#### Route Configuration
```elixir
# lib/rsolv_web/router.ex
scope "/", RsolvWeb do
  pipe_through :browser

  # Public marketing pages
  live "/", LandingLive, :index
  live "/pricing", PricingLive, :index
  live "/signup", SignupLive, :index  # Replaces early_access_live

  # Legal pages (if needed)
  get "/terms", PageController, :terms
  get "/privacy", PageController, :privacy

  # Existing authenticated routes...
  pipe_through :require_customer_auth
  # ...
end
```

#### API Integration
```elixir
# SignupLive handles form submission
defmodule RsolvWeb.SignupLive do
  use RsolvWeb, :live_view

  alias Rsolv.CustomerOnboarding  # RFC-065 module

  def handle_event("signup", %{"email" => email}, socket) do
    case CustomerOnboarding.provision_customer(%{email: email}) do
      {:ok, %{customer: customer, api_key: api_key}} ->
        {:noreply,
         socket
         |> assign(:success, true)
         |> assign(:api_key, api_key.key_value)  # Raw key (shown only once)
         |> assign(:customer_email, customer.email)}

      {:error, :duplicate_email} ->
        {:noreply, put_flash(socket, :error, "Account already exists. Sign in?")}

      {:error, :rate_limit_exceeded} ->
        {:noreply, put_flash(socket, :error, "Too many attempts. Try again in 10 minutes.")}

      {:error, changeset} ->
        {:noreply, assign(socket, :changeset, changeset)}
    end
  end
end
```

### Design System

**Use Existing Tailwind Infrastructure:**
- Build on RFC-077 (Tailwind Syntax template patterns)
- Reuse dark mode system (already implemented)
- Match docs.rsolv.dev visual language
- Mobile-first responsive design

**Color Palette:**
```css
/* Light mode */
--primary: #2563eb (blue-600)
--secondary: #059669 (emerald-600)
--background: #F5F5F5 (soft white)
--text: #1f2937 (gray-800)

/* Dark mode */
--primary: #3b82f6 (blue-500)
--secondary: #10b981 (emerald-500)
--background: #020617 (slate-950)
--text: #f9fafb (gray-50)
```

**Typography:**
- Headings: System font stack (fast load)
- Body: Inter or similar (professional, readable)
- Code: JetBrains Mono or Fira Code

**Components:**
- Buttons: Primary (blue), Secondary (gray)
- Forms: Inline validation, accessible labels
- Cards: Subtle shadows, hover states
- Hero: Gradient backgrounds (blue → emerald)

### Test-Driven Development

**ALL features follow RED-GREEN-REFACTOR:**

#### Landing Page Tests
```elixir
# test/rsolv_web/live/landing_live_test.exs

test "displays hero with CTA" do
  {:ok, view, html} = live(conn, ~p"/")
  assert html =~ "Automated Security Fixes"
  assert html =~ "Start Free Trial"
end

test "CTA links to /signup" do
  {:ok, view, _html} = live(conn, ~p"/")
  assert view |> element("a[href='/signup']") |> has_element?()
end

test "displays features section" do
  {:ok, view, html} = live(conn, ~p"/")
  assert html =~ "Detects real vulnerabilities"
  assert html =~ "Generates tested fixes"
end

test "displays pricing teaser with link" do
  {:ok, view, html} = live(conn, ~p"/")
  assert html =~ "Start with 10 Free Credits"
  assert view |> element("a[href='/pricing']") |> has_element?()
end
```

#### Pricing Page Tests
```elixir
# test/rsolv_web/live/pricing_live_test.exs

test "displays all pricing tiers" do
  {:ok, view, html} = live(conn, ~p"/pricing")
  assert html =~ "Free Trial"
  assert html =~ "Pro Plan"
  assert html =~ "Pay-As-You-Go"
end

test "shows correct pricing amounts" do
  {:ok, view, html} = live(conn, ~p"/pricing")
  assert html =~ "$599/month"
  assert html =~ "$29/fix"
  assert html =~ "10 credits"
end

test "includes pricing calculator" do
  {:ok, view, _html} = live(conn, ~p"/pricing")
  assert view |> element("input[type='range']") |> has_element?()
end

test "displays FAQ section" do
  {:ok, view, html} = live(conn, ~p"/pricing")
  assert html =~ "What counts as a fix?"
  assert html =~ "When does billing start?"
end
```

#### Signup Page Tests
```elixir
# test/rsolv_web/live/signup_live_test.exs

test "displays signup form" do
  {:ok, view, html} = live(conn, ~p"/signup")
  assert html =~ "Start Free Trial"
  assert view |> element("input[type='email']") |> has_element?()
end

test "creates customer and displays API key on valid signup" do
  {:ok, view, _html} = live(conn, ~p"/signup")

  view
  |> form("#signup-form", %{email: "new@customer.com"})
  |> render_submit()

  html = render(view)
  assert html =~ "Welcome to RSOLV"
  assert html =~ "rsolv_"  # API key prefix
  assert html =~ "new@customer.com"
end

test "shows error for duplicate email" do
  insert(:customer, email: "existing@customer.com")

  {:ok, view, _html} = live(conn, ~p"/signup")

  view
  |> form("#signup-form", %{email: "existing@customer.com"})
  |> render_submit()

  assert view |> element(".error") |> render() =~ "Account already exists"
end

test "validates email format" do
  {:ok, view, _html} = live(conn, ~p"/signup")

  view
  |> form("#signup-form", %{email: "invalid-email"})
  |> render_submit()

  assert view |> element(".error") |> render() =~ "invalid format"
end

test "enforces rate limiting" do
  # Simulate 10 signups from same IP
  for _ <- 1..10 do
    CustomerOnboarding.provision_customer(%{
      email: "test#{:rand.uniform(10000)}@example.com",
      ip_address: "127.0.0.1"
    })
  end

  {:ok, view, _html} = live(conn, ~p"/signup")

  view
  |> form("#signup-form", %{email: "rate@limited.com"})
  |> render_submit()

  assert view |> element(".error") |> render() =~ "Too many attempts"
end
```

## Implementation Phases

### Phase 1: Landing Page (Day 1-2)
- **RED**: Write tests for hero, features, CTA
- **GREEN**: Implement landing_live.ex
- **REFACTOR**: Extract reusable components
- **RESULT**: Deployable landing page

### Phase 2: Pricing Page (Day 2-3)
- **RED**: Write tests for pricing tiers, calculator, FAQ
- **GREEN**: Implement pricing_live.ex
- **REFACTOR**: Create pricing calculator component
- **RESULT**: Transparent pricing page

### Phase 3: Signup Flow (Day 3-5)
- **RED**: Write tests for form, validation, success state
- **GREEN**: Convert early_access_live.ex → signup_live.ex
- **REFACTOR**: Extract form components
- **RESULT**: Self-service signup working

### Phase 4: Integration & Polish (Day 5-7)
- E2E testing: Landing → Signup → First Fix
- Accessibility audit (WCAG 2.1 AA)
- Mobile responsiveness testing
- Performance optimization (Lighthouse)
- Copy review & refinement

## Success Criteria

### Functional Requirements
- [ ] Landing page loads < 2s (p95)
- [ ] All CTAs link correctly
- [ ] Signup form creates customer via RFC-065 API
- [ ] API key displayed and emailed successfully
- [ ] Rate limiting prevents abuse (10/hour per IP)
- [ ] Error states handled gracefully

### User Experience
- [ ] Clear value proposition within 5 seconds
- [ ] Frictionless signup (< 2 minutes)
- [ ] Mobile-friendly (320px+)
- [ ] Dark mode compatible
- [ ] Accessible (keyboard navigation, screen readers)

### Business Metrics
- [ ] Signup conversion rate > 10% (landing → signup)
- [ ] API key retrieval rate > 95% (signup → key saved)
- [ ] Setup completion rate > 60% (signup → first scan)
- [ ] Support tickets < 5% of signups

### Technical Requirements
- [ ] Test coverage ≥ 80% for all pages
- [ ] CI pipeline passes (tests, Credo, format)
- [ ] No performance regressions
- [ ] SEO optimized (meta tags, sitemap)
- [ ] Analytics integrated (if applicable)

## Rollout Plan

### Week 5 (Nov 4-8): Development
- **Monday**: Landing page implementation
- **Tuesday**: Pricing page implementation
- **Wednesday**: Signup flow conversion
- **Thursday-Friday**: Integration testing & polish

### Deployment Strategy
- **Staging First**: Full E2E testing on staging.rsolv.dev
- **Smoke Tests**: Verify signup flow with test accounts
- **Production Rollout**: Deploy with feature flag (optional)
- **Monitoring**: Watch error rates, conversion metrics

### Feature Flag (Optional)
```elixir
# If using feature flags for gradual rollout
def show_new_signup? do
  FunWithFlags.enabled?(:self_service_signup)
end

# Fallback to early access if flag disabled
if show_new_signup?() do
  live "/signup", SignupLive, :index
else
  live "/signup", EarlyAccessLive, :index
end
```

## Risks & Mitigations

| Risk | Impact | Probability | Mitigation |
|------|--------|-------------|------------|
| Spam signups | High | Medium | Rate limiting (10/hour per IP), CAPTCHA if needed |
| Disposable emails | Medium | High | Email validation (RFC-065 already handles) |
| Abandoned signups | Low | High | Follow-up email sequence (already in RFC-065) |
| Poor conversion | High | Medium | A/B testing copy, optimize CTA placement |
| Mobile UX issues | Medium | Medium | Thorough mobile testing, responsive design |
| Slow page load | Medium | Low | Lighthouse audit, optimize assets |

## Open Questions

1. **Analytics Integration**: Which tool? (Google Analytics, Plausible, PostHog?)
2. **A/B Testing**: Tool needed for conversion optimization?
3. **CAPTCHA**: Start without it, add if spam becomes issue?
4. **Legal Pages**: Terms of Service and Privacy Policy ready?
5. **Email Deliverability**: Postmark configured and tested?
6. **Domain Setup**: rsolv.dev SSL and DNS ready?

## Future Enhancements (Post-Launch)

- Social proof section (testimonials, case studies)
- Video walkthrough on landing page
- Live chat support widget
- SEO blog integration (link to blog posts)
- Customer success stories
- Framework-specific landing pages
- A/B testing different copy variations
- Localization (i18n) for international markets

## Timeline

**Week 5 (Nov 4-8, 2025)**
- Day 1-2: Landing page
- Day 2-3: Pricing page
- Day 3-5: Signup flow
- Day 5-7: Integration & polish

**Deployment**: End of Week 5 (concurrent with RFC-069 production deployment)

**Critical Path**: Must complete before Week 6 launch (RFC-067 marketplace submission)

## Acceptance Criteria

Before marking RFC-078 as "Implemented":

1. All three pages deployed to production
2. Self-service signup working end-to-end
3. Test coverage ≥ 80%
4. Lighthouse score ≥ 90 for all pages
5. Mobile responsive (tested on iPhone, Android)
6. Accessibility audit passed (WCAG 2.1 AA)
7. Analytics tracking configured
8. SEO meta tags added
9. Sitemap updated
10. At least 3 successful test signups on production

## Related Documentation

- RFC-064: Master plan coordination
- RFC-065: Backend provisioning API
- RFC-066: Billing integration details
- RFC-069: Integration week timeline
- RFC-077: Tailwind design system patterns
- ADR-TBD: Public Site Implementation (post-launch)

## Questions?

Contact: Dylan (product lead)
Status Updates: `projects/go-to-market-2025-10/RFC-078-TRACKING.md`
