# RFC-071: Customer Portal UI

**Status**: Draft (Future Work)
**Created**: 2025-10-16
**Timeline**: 4-5 weeks (starts after RFC-070 completes)
**Priority**: High (enables customer self-service)
**Author**: Product Team

## Related RFCs

**Dependencies (Required):**
- RFC-064 (Billing & Provisioning Master Plan) - Must complete first
- RFC-065 (Automated Customer Provisioning) - Provides customer creation and backend data
- RFC-066 (Stripe Billing Integration) - Provides billing backend and Stripe integration
- RFC-070 (Customer Authentication) - Provides login/session management (hard dependency)

**Related:**
- RFC-068 (Billing Testing Infrastructure) - Provides testing infrastructure
- RFC-056 (Admin UI) - Staff-facing interface (reference for LiveView patterns)

## Summary

Build a unified customer self-service portal that consolidates billing management, usage tracking, API key management, installation guidance, and account settings into a cohesive experience. This RFC provides the customer-facing UI that sits on top of the authentication (RFC-070) and backend services (RFC-065, RFC-066).

**Scope:** Customer portal UI only. Authentication is RFC-070 (prerequisite).

## Problem Statement

Customers need a single, cohesive portal for managing their RSOLV experience. Currently:

- **No customer dashboard exists** - Customers have no way to view their usage, manage API keys, or handle billing
- **Provisioning happens but is invisible** - RFC-065 creates customers, but they can't see what happened
- **Billing backend exists but no UI** - RFC-066 provides Stripe integration, but no customer-facing interface
- **Poor onboarding experience** - No guidance for getting started with RSOLV

This fragmentation leads to:
- High support burden (customers asking for basic info)
- Poor conversion (trial users don't know how to upgrade)
- Confusion about usage limits and billing
- Manual API key delivery

## Proposed Solution

### Unified Customer Portal at `/dashboard`

Single entry point for all customer self-service needs, organized into logical sections:

```mermaid
graph TB
    A[/dashboard] --> B[Overview]
    A --> C[Usage & Limits]
    A --> D[API Keys]
    A --> E[Billing]
    A --> F[Setup & Install]
    A --> G[Account Settings]

    B --> B1[Current Plan]
    B --> B2[Quick Stats]
    B --> B3[Recent Activity]

    C --> C1[Usage Chart]
    C --> C2[Fix History]
    C --> C3[Overage Warnings]

    D --> D1[Active Keys]
    D --> D2[Generate Key]
    D --> D3[Revoke Key]

    E --> E1[Payment Method]
    E --> E2[Invoices]
    E --> E3[Upgrade/Downgrade]

    F --> F1[Workflow Generator]
    F --> F2[Test Connection]
    F --> F3[Documentation]

    G --> G1[Profile]
    G --> G2[Notifications]
    G --> G3[Security]
```

### Customer Journey After Signup

```sequence
Title: Customer Journey After Signup

Customer->Portal: First login (from welcome email)
Portal->Onboarding: Show setup wizard
Onboarding->Customer: Step 1: Install GitHub Action
Customer->Onboarding: Download workflow file
Onboarding->Customer: Step 2: Add API key to secrets
Customer->Onboarding: Test connection
Onboarding->Portal: Mark onboarding complete
Portal->Customer: Show dashboard overview
```

## Test-Driven Development Methodology

**ALL features MUST follow RED-GREEN-REFACTOR cycle:**

### RED: Write Failing Tests First
Write failing test(s) that **fully describe the desired behavior** you'll implement. This may be multiple tests, not just one. The goal is to comprehensively specify what "passing" means before writing any implementation code.

### GREEN: Minimal Code to Pass
Implement the feature with minimal code to make all tests pass. This phase only works if the RED phase fully described the desired behavior through comprehensive tests.

### REFACTOR: Clean Up, Keeping Tests Green
Improve code quality - making it more readable and idiomatic - while keeping all tests green. In alternating refactor phases, improve the tests themselves (changing only tests OR implementation at a time, never both).

**Testing Infrastructure:** Provided by RFC-068. Test database, fixtures, and patterns are available. Tests are written here during TDD implementation.

## Architecture

### Route Structure

```elixir
# lib/rsolv_web/router.ex
scope "/", RsolvWeb do
  pipe_through [:browser, :require_customer_auth]  # RFC-070 provides this

  live_session :customer_portal, on_mount: [{RsolvWeb.LiveHooks, :ensure_authenticated}] do
    # Main dashboard
    live "/dashboard", CustomerPortal.DashboardLive, :index

    # Usage & limits
    live "/dashboard/usage", CustomerPortal.UsageLive, :index

    # API key management
    live "/dashboard/api-keys", CustomerPortal.APIKeysLive, :index

    # Billing
    live "/dashboard/billing", CustomerPortal.BillingLive, :index
    live "/dashboard/billing/upgrade", CustomerPortal.BillingLive, :upgrade
    live "/dashboard/billing/invoices/:id", CustomerPortal.InvoiceLive, :show

    # Setup & installation
    live "/dashboard/setup", CustomerPortal.SetupLive, :index

    # Account settings
    live "/dashboard/settings", CustomerPortal.SettingsLive, :index
  end
end
```

### Component Structure

```
lib/rsolv_web/live/customer_portal/
├── dashboard_live.ex                 # Overview page
├── usage_live.ex                     # Usage tracking & history
├── api_keys_live.ex                  # API key management
├── billing_live.ex                   # Billing management
├── invoice_live.ex                   # Invoice details
├── setup_live.ex                     # Installation wizard
├── settings_live.ex                  # Account settings
└── components/
    ├── stats_card.ex                 # Reusable stat display
    ├── usage_chart.ex                # Usage visualization
    ├── plan_selector.ex              # Plan upgrade/downgrade
    ├── workflow_generator.ex         # GitHub workflow builder
    └── api_key_display.ex            # Masked key display
```

## TDD Implementation Plan

### Week 1: Core Portal & Navigation (RED-GREEN-REFACTOR)

#### Day 1-2: Dashboard Overview

**Tests to Write First:**
```elixir
test "requires authentication" # RFC-070 provides this
test "displays customer name"
test "shows current plan badge"
test "displays usage stats (X/Y fixes)"
test "shows recent activity (last 5 fixes)"
test "navigation links to all sections"
test "first-time user sees onboarding checklist"
test "completed setup hides onboarding"
```

**Implementation:**
- [ ] Write failing test: "displays customer name"
- [ ] Create DashboardLive module with mount
- [ ] Write failing test: "shows current plan badge"
- [ ] Add plan display logic from Customers context
- [ ] Write failing test: "displays usage stats"
- [ ] Integrate with Customers context for usage data
- [ ] Write failing test: "shows onboarding checklist"
- [ ] Add onboarding component with setup progress
- [ ] Refactor: Extract stats into reusable component
- [ ] Run test suite: MUST be GREEN

#### Day 3: Navigation & Layout

**Tests to Write First:**
```elixir
test "sidebar shows all sections"
test "highlights active section"
test "mobile menu toggles correctly"
test "breadcrumbs show current location"
test "dark mode works across all pages"
test "logout link redirects to home"
```

**Implementation:**
- [ ] Write failing tests for navigation
- [ ] Create shared layout component
- [ ] Add sidebar navigation
- [ ] Implement mobile responsive menu
- [ ] Add dark mode support (consistent with site)
- [ ] Refactor: Extract navigation component
- [ ] Run test suite: MUST be GREEN

#### Day 4-5: Usage & Limits Page

**Tests to Write First:**
```elixir
test "displays current usage as percentage"
test "shows usage chart (last 30 days)"
test "lists recent fix attempts with status"
test "filters by date range"
test "exports usage data to CSV"
test "shows overage warning when > 90%"
test "trial users see upgrade CTA at 80% usage"
```

**Implementation:**
- [ ] Write failing tests for usage display
- [ ] Create UsageLive module
- [ ] Implement usage calculation from Billing context (RFC-066)
- [ ] Add chart component (using Chart.js or similar)
- [ ] Write failing test: "shows overage warning"
- [ ] Add warning banner for high usage
- [ ] Write failing test: "trial users see upgrade CTA"
- [ ] Add conditional upgrade prompt
- [ ] Refactor: Extract chart into component
- [ ] Run test suite: MUST be GREEN

### Week 2: API Keys & Billing (TDD)

#### Day 1-2: API Key Management

**Tests to Write First:**
```elixir
test "lists active API keys with masked display"
test "shows created date for each key"
test "generates new API key on button click"
test "displays full key only once after generation"
test "copies key to clipboard"
test "revokes API key with confirmation"
test "prevents revoking last active key"
test "shows revoked keys separately"
test "rate limits API key generation (3 per hour)"
```

**Implementation:**
- [ ] Write failing tests for API key listing
- [ ] Create APIKeysLive module
- [ ] Display keys with `rsolv_****` masking (from RFC-065)
- [ ] Write failing test: "generates new API key"
- [ ] Integrate with Customers.create_api_key/1
- [ ] Write failing test: "copies to clipboard"
- [ ] Add JavaScript hook for copy functionality
- [ ] Write failing test: "revokes with confirmation"
- [ ] Add confirmation modal and revoke logic
- [ ] Write failing test: "prevents revoking last key"
- [ ] Add validation preventing last key deletion
- [ ] Refactor: Extract key display component
- [ ] Run test suite: MUST be GREEN

#### Day 3-5: Billing Management

**Tests to Write First:**
```elixir
test "displays current subscription plan"
test "shows next billing date"
test "trial users see days remaining"
test "lists payment methods"
test "adds payment method via Stripe Elements"
test "removes payment method"
test "prevents removing last payment method"
test "displays invoice history"
test "downloads invoice PDF"
test "shows upgrade options for trial users"
test "processes plan upgrade with confirmation"
test "calculates prorated charges correctly"
test "shows downgrade options with end-of-period change"
```

**Implementation:**
- [ ] Write failing tests for billing display
- [ ] Create BillingLive module
- [ ] Integrate with Billing context (RFC-066)
- [ ] Write failing test: "displays subscription plan"
- [ ] Fetch subscription data from Stripe
- [ ] Write failing test: "adds payment method"
- [ ] Add Stripe Elements integration (Stripe.js)
- [ ] Write failing test: "shows upgrade options"
- [ ] Create PlanSelector component
- [ ] Write failing test: "processes plan upgrade"
- [ ] Implement upgrade flow with Stripe API
- [ ] Write failing test: "calculates prorated charges"
- [ ] Add proration calculation display
- [ ] Write failing test: "lists invoices"
- [ ] Fetch invoices from Stripe
- [ ] Refactor: Extract Stripe Elements component
- [ ] Run test suite: MUST be GREEN

### Week 3: Setup & Settings (TDD)

#### Day 1-2: Installation Wizard

**Tests to Write First:**
```elixir
test "generates GitHub workflow YAML"
test "customizes workflow for different triggers"
test "shows installation instructions"
test "validates API key connection"
test "displays setup progress (0/3 steps)"
test "marks setup complete after validation"
test "shows troubleshooting tips on failure"
test "one-click download of workflow file"
```

**Implementation:**
- [ ] Write failing tests for workflow generation
- [ ] Create SetupLive module
- [ ] Build workflow template generator
- [ ] Write failing test: "validates API key"
- [ ] Add connection test endpoint (calls backend)
- [ ] Write failing test: "tracks setup progress"
- [ ] Implement multi-step wizard UI
- [ ] Write failing test: "one-click download"
- [ ] Add download button with proper headers
- [ ] Refactor: Extract workflow generator component
- [ ] Run test suite: MUST be GREEN

#### Day 3-4: Account Settings

**Tests to Write First:**
```elixir
test "displays current email"
test "updates name"
test "changes email with verification"
test "updates password (uses RFC-070 backend)"
test "enables email notifications"
test "configures notification preferences"
test "shows security settings (2FA placeholder)"
test "displays account activity log"
test "allows account deletion with confirmation"
```

**Implementation:**
- [ ] Write failing tests for settings display
- [ ] Create SettingsLive module
- [ ] Write failing test: "updates name"
- [ ] Add name update form
- [ ] Write failing test: "changes email with verification"
- [ ] Implement email change flow (use RFC-070 backend)
- [ ] Write failing test: "updates password"
- [ ] Add password change (delegates to RFC-070)
- [ ] Write failing test: "configures notifications"
- [ ] Add notification preferences form
- [ ] Refactor: Extract settings sections
- [ ] Run test suite: MUST be GREEN

### Week 4: Polish & Integration (TDD)

#### Day 1-2: Onboarding Flow

**Tests to Write First:**
```elixir
test "first-time user sees 3-step wizard"
test "wizard step 1: download workflow"
test "wizard step 2: shows API key"
test "wizard step 3: test connection"
test "successful connection completes onboarding"
test "completed onboarding shows dashboard"
test "onboarding can be skipped (dismissed)"
test "dismissed onboarding can be restarted"
```

**Implementation:**
- [ ] Write failing tests for onboarding
- [ ] Add onboarding wizard component
- [ ] Implement 3-step flow
- [ ] Write failing test: "test connection"
- [ ] Add backend test endpoint
- [ ] Write failing test: "marks complete on success"
- [ ] Update customer.onboarding_completed_at
- [ ] Refactor: Extract wizard component
- [ ] Run test suite: MUST be GREEN

#### Day 3-4: Contextual Help & UX Polish

**Tests to Write First:**
```elixir
test "dashboard shows contextual help tooltips"
test "usage page explains fix counting"
test "billing page links to pricing documentation"
test "all pages have consistent dark mode"
test "mobile responsive on all pages"
test "loading states show skeletons"
test "errors display with retry options"
test "empty states show helpful guidance"
```

**Implementation:**
- [ ] Write failing test: "contextual help tooltips"
- [ ] Add help tooltips and guides
- [ ] Polish dark mode across all pages
- [ ] Add loading skeletons
- [ ] Implement error states with retry
- [ ] Add empty states with CTAs
- [ ] Test mobile responsiveness
- [ ] Run test suite: MUST be GREEN

#### Day 5: Integration Testing

**Tests to Write First:**
```elixir
test "complete onboarding flow (login → wizard → test → dashboard)"
test "upgrade from trial to paid (dashboard → billing → upgrade → success)"
test "API key lifecycle (generate → use → revoke)"
test "usage tracking updates in real-time"
test "billing updates reflect in dashboard"
```

**Implementation:**
- [ ] Write integration test: "onboarding flow"
- [ ] Verify end-to-end onboarding works
- [ ] Write integration test: "upgrade flow"
- [ ] Verify end-to-end upgrade works
- [ ] Write integration test: "API key lifecycle"
- [ ] Verify generate/use/revoke flow
- [ ] Run full test suite: MUST be GREEN
- [ ] Deploy to staging

### Week 5: Beta Testing & Launch Prep (Optional Buffer)

**If ahead of schedule:**
- [ ] Additional polish and refinement
- [ ] Performance optimization
- [ ] Additional tests for edge cases
- [ ] Beta testing with 5-10 customers
- [ ] Gather feedback and iterate
- [ ] Prepare for production launch

## UI/UX Design

### Design System
- **Framework**: Phoenix LiveView for real-time updates
- **Styling**: Tailwind CSS (existing setup) with custom design tokens
- **Icons**: Heroicons (Phoenix default)
- **Charts**: Chart.js via Alpine.js or Phoenix Chart
- **Responsive**: Mobile-first approach
- **Dark Mode**: Consistent with existing site theme

### Key Components

#### Stats Card (Reusable)
```elixir
<.stats_card
  title="Fixes Used"
  value={@customer.trial_fixes_used}
  max={@customer.trial_fixes_limit}
  percentage={usage_percentage(@customer)}
  trend="up"
  trend_value="12% vs last month"
/>
```

#### Usage Chart
```elixir
<.usage_chart
  data={@usage_data}
  period="30d"
  show_limit={true}
  limit_value={@customer.monthly_limit}
/>
```

#### Plan Selector
```elixir
<.plan_selector
  current_plan={@customer.subscription_plan}
  available_plans={@plans}
  on_select={&handle_plan_select/1}
/>
```

### Page Layouts

#### Dashboard Overview (Mobile-First)
- Header: Name, plan badge
- Stats cards: 2x2 grid (mobile: stacked)
- Recent activity: Last 5 fixes
- Quick actions: Generate key, Upgrade plan, View docs
- Onboarding checklist (if incomplete)

#### Usage & Limits
- Current period usage: Progress bar + percentage
- Chart: Last 30/90 days (selectable)
- Fix history table: Pagination, filters
- Export button: CSV download

#### API Keys
- Active keys table: Masked display, created date
- Generate button: Modal with key copy
- Revoked keys: Separate collapsed section
- Warning: "Never share your API keys"

#### Billing
- Current plan card: Name, price, next billing
- Payment methods: Card list with default badge
- Add payment: Stripe Elements modal
- Invoice history: Table with download links
- Upgrade section: Plan comparison cards

#### Setup Wizard
- Progress indicator: 3 steps
- Step 1: Download workflow file
- Step 2: Add API key to GitHub secrets
- Step 3: Test connection
- Success state: Checkmark + next steps

#### Settings
- Tabs: Profile, Notifications, Security
- Profile: Name, email (with verification via RFC-070)
- Notifications: Email toggles
- Security: Password change (via RFC-070), activity log

## Data Integration Points

### From RFC-065 (Provisioning)
- Customer record (name, email, created_at)
- Trial usage (trial_fixes_used, trial_fixes_limit)
- API keys (via Customers context)
- Onboarding status (onboarding_completed_at)

### From RFC-066 (Billing)
- Stripe customer data (via Billing context)
- Subscription details (plan, status, period_end)
- Payment methods (via Stripe API)
- Invoice history (via Stripe API)
- Usage records (for PAYG/Teams)

### From RFC-070 (Authentication)
- Customer session (current_customer)
- Password change functionality
- Email change with verification
- Account activity log

### New Data Requirements

```elixir
# Add to customers table (migration)
ALTER TABLE customers ADD COLUMN notification_preferences JSONB DEFAULT '{"email_usage_alerts": true, "email_invoices": true}';

# Customer activity tracking (from RFC-070, used here)
# customer_audit_logs table already created by RFC-070
```

## Security Considerations

1. **Authentication**: All routes require customer authentication (RFC-070)
2. **Authorization**: Customers can only see their own data
3. **API Key Display**: Always masked except during generation
4. **Payment Data**: Use Stripe Elements (PCI compliant, no card data touches our servers)
5. **Rate Limiting**: Prevent abuse of API key generation (3 per hour)
6. **CSRF Protection**: Phoenix built-in tokens
7. **Activity Logging**: Track sensitive operations (from RFC-070)
8. **Data Validation**: All inputs validated server-side

## Testing Requirements

### Unit Tests (Written During TDD)
```elixir
# Dashboard
test "calculates usage percentage correctly"
test "formats plan display name"
test "sorts recent activity by date"

# API Keys
test "masks API key correctly (rsolv_****)"
test "validates key generation permissions"
test "prevents revoking last active key"

# Billing
test "calculates proration for plan upgrade"
test "formats invoice amounts correctly"
test "validates payment method before delete"

# Setup
test "generates valid GitHub workflow YAML"
test "validates API key connection"
test "tracks setup completion state"

# Settings
test "updates notification preferences"
test "validates name changes"
test "delegates password change to RFC-070"
```

### Integration Tests (Written During TDD)
```elixir
test "complete onboarding flow (login → wizard → dashboard)"
test "upgrade from trial to paid (dashboard → billing → confirm)"
test "API key lifecycle (generate → use → revoke)"
test "usage tracking displays correctly"
```

## Success Metrics

### User Experience
- **Time to First Scan**: < 10 minutes from signup
- **Onboarding Completion**: > 80% within 24 hours
- **Dashboard Engagement**: > 60% visit within 7 days
- **API Key Regeneration**: < 5% (indicates good security UX)

### Technical
- **Test Coverage**: ≥ 95% for customer portal
- **Page Load Time**: < 1 second (all pages)
- **Mobile Usability**: 100% responsive
- **Accessibility**: WCAG 2.1 AA compliant

### Business
- **Trial to Paid Conversion**: > 20% (baseline)
- **Self-Service Rate**: > 90% (reduce support burden)
- **Customer Satisfaction**: > 4.5/5 (post-onboarding survey)

## Risks & Mitigation

| Risk | Impact | Mitigation |
|------|--------|------------|
| Stripe Elements complexity | High | Use official SDK, thorough testing |
| Mobile UX poor | Medium | Mobile-first design, testing on real devices |
| Overwhelming onboarding | Medium | Progressive disclosure, skip options |
| Performance on usage charts | Low | Cache data, lazy load charts |
| RFC-070 delays | High | Start after RFC-070 completes (hard dependency) |

## Future Enhancements (Out of Scope)

1. **Team Management**: Invite users, role-based access
2. **Webhooks**: Customer-configured webhooks for events
3. **Advanced Analytics**: Trends, predictions, benchmarking
4. **2FA**: Two-factor authentication (extend RFC-070)
5. **OAuth**: Social login (extend RFC-070)
6. **API Documentation**: Interactive API explorer
7. **Support Chat**: In-app support widget

## Dependencies & Prerequisites

**Required (Must Complete First):**
- ✅ RFC-064 (Billing & Provisioning Master Plan) - Completes first
- ✅ RFC-065 (Provisioning) - Provides customer creation, API keys
- ✅ RFC-066 (Billing) - Provides Stripe integration backend
- ✅ RFC-070 (Customer Authentication) - **HARD DEPENDENCY** - Must complete first

**Nice to Have:**
- RFC-068 (Testing Infrastructure) - For test patterns and staging

**Blockers:**
- **RFC-070 must complete first** - No portal without authentication

## Implementation Timeline

### Week 1: Core Portal
- Dashboard overview
- Navigation & layout
- Usage & limits page

### Week 2: API Keys & Billing
- API key management
- Billing integration
- Payment methods

### Week 3: Setup & Settings
- Installation wizard
- Account settings
- Onboarding flow

### Week 4: Polish & Integration
- Contextual help
- UX polish
- Integration testing
- Staging deployment

### Week 5: Beta & Launch (Buffer/Optional)
- Beta testing
- Feedback iteration
- Production launch prep

## Rollout Plan

1. **Development (Weeks 1-4)**: Build with TDD, connect to real backends
2. **Staging (Week 4)**: Deploy to staging
3. **Beta Testing (Week 5 or separate)**: 10 beta customers
4. **General Availability**: All customers after beta success

## Next Steps

1. Wait for RFC-070 (Customer Authentication) to complete
2. Review and approve RFC-071 draft
3. Create feature branch: `feature/customer-portal-ui`
4. Begin Week 1 TDD implementation
5. Daily standups with RFC-070 team for coordination

## References

- RFC-064: Billing & Provisioning Master Plan (prerequisite)
- RFC-065: Automated Customer Provisioning (customer creation, API keys)
- RFC-066: Stripe Billing Integration (billing backend)
- RFC-070: Customer Authentication (hard dependency)
- RFC-068: Billing Testing Infrastructure (testing patterns)
- RFC-056: Admin UI (reference for LiveView patterns)
- [Phoenix LiveView Guide](https://hexdocs.pm/phoenix_live_view/Phoenix.LiveView.html)
- [Stripe Elements](https://stripe.com/docs/stripe-js)
