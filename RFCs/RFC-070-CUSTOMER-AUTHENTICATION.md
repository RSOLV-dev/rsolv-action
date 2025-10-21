# RFC-070: Customer Authentication

**Status**: Draft (Future Work)
**Created**: 2025-10-16
**Timeline**: 2 weeks (starts after RFC-064 production launch)
**Priority**: High (prerequisite for RFC-071)
**Author**: Product Team

## Related RFCs

**Dependencies (Required):**
- RFC-064 (Billing & Provisioning Master Plan) - Must complete first
- RFC-065 (Automated Customer Provisioning) - Provides customer creation
- RFC-049 (Customer Management Consolidation) - Implemented → ADR-026 (provides backend auth)

**Enables:**
- RFC-071 (Customer Portal UI) - Customer-facing dashboard (depends on this)

**Related:**
- RFC-056 (Admin UI) - Admin authentication (reference for patterns)

## Summary

Build customer-facing authentication layer including registration, login, logout, password reset, and session management. Currently, customer authentication backend exists (ADR-026) but has no customer-facing pages - only admin UI exists.

**Scope:** Customer authentication pages and flows only. Portal UI is RFC-071.

**Implementation Standards:** This RFC MUST follow best practices for authentication in the latest releases of Elixir and Phoenix as of October 16, 2025. **Elixir 1.19.0 was released today** - take full advantage of new functionality and support. Consult current Phoenix documentation, Elixir 1.19.0 release notes, OWASP guidelines, and community standards for authentication patterns, security measures, and recommended libraries.

## Problem Statement

### Current State

**Backend exists but incomplete:**
- ✅ `Rsolv.Customers` context has full auth backend
- ✅ Password hashing (Bcrypt), session tokens (Mnesia)
- ✅ `register_customer/1`, `authenticate/2`, `create_session_token/1`
- ❌ No customer registration page (only early access email signup)
- ❌ No customer login page
- ❌ No password reset flow
- ❌ `CustomerAuth.require_authenticated_customer/2` redirects to `/admin/login` (wrong!)

**Issues:**
1. Customers created via RFC-065 provisioning have no way to log in
2. Admin login at `/admin/login` is staff-only
3. Password reset doesn't exist for customers
4. Session management incomplete

## Proposed Solution

### Customer Authentication Routes

```elixir
# lib/rsolv_web/router.ex
scope "/", RsolvWeb do
  pipe_through :browser

  # Public authentication routes
  get "/login", CustomerSessionController, :new
  post "/login", CustomerSessionController, :create
  delete "/logout", CustomerSessionController, :delete

  get "/register", CustomerRegistrationController, :new
  post "/register", CustomerRegistrationController, :create

  get "/reset-password", CustomerResetPasswordController, :new
  post "/reset-password", CustomerResetPasswordController, :create
  get "/reset-password/:token", CustomerResetPasswordController, :edit
  put "/reset-password/:token", CustomerResetPasswordController, :update

  # Email confirmation (optional for now)
  get "/confirm/:token", CustomerConfirmationController, :confirm
end
```

### Architecture

**Controller Pattern** (Following Phoenix conventions):
```elixir
defmodule RsolvWeb.CustomerSessionController do
  use RsolvWeb, :controller
  alias Rsolv.Customers

  def new(conn, _params) do
    render(conn, "new.html", error_message: nil)
  end

  def create(conn, %{"email" => email, "password" => password}) do
    case Customers.authenticate(email, password) do
      {:ok, customer} ->
        token = Customers.create_session_token(customer)
        conn
        |> put_session(:customer_token, token)
        |> put_flash(:info, "Welcome back!")
        |> redirect(to: "/dashboard")

      {:error, :invalid_credentials} ->
        render(conn, "new.html", error_message: "Invalid email or password")
    end
  end

  def delete(conn, _params) do
    token = get_session(conn, :customer_token)
    Customers.delete_session_token(token)
    conn
    |> clear_session()
    |> put_flash(:info, "Logged out successfully")
    |> redirect(to: "/")
  end
end
```

**Session Management:**
- Uses Mnesia for session storage (already configured)
- Session timeout: 30 days (configurable)
- Auto-renewal on activity
- Secure cookie flags (httpOnly, secure, sameSite)

**Security Features:**
1. **Rate Limiting**: 5 failed login attempts → 15 minute lockout
2. **CSRF Protection**: Phoenix built-in tokens
3. **Password Requirements**: 12+ chars, complexity validation
4. **Bcrypt Hashing**: Already implemented in Customer schema
5. **Session Tokens**: Cryptographically random, hashed in DB
6. **Audit Logging**: Track login attempts, password changes

## Test-Driven Development Methodology

**ALL features MUST follow RED-GREEN-REFACTOR cycle:**

### RED: Write Failing Tests First
Write failing test(s) that **fully describe the desired behavior** you'll implement. This may be multiple tests, not just one. The goal is to comprehensively specify what "passing" means before writing any implementation code.

### GREEN: Minimal Code to Pass
Implement the feature with minimal code to make all tests pass. This phase only works if the RED phase fully described the desired behavior through comprehensive tests.

### REFACTOR: Clean Up, Keeping Tests Green
Improve code quality - making it more readable and idiomatic - while keeping all tests green. In alternating refactor phases, improve the tests themselves (changing only tests OR implementation at a time, never both).

## TDD Implementation Plan

### Week 1: Registration & Login (RED-GREEN-REFACTOR)

#### Day 1-2: Customer Registration

**Tests to Write First:**
```elixir
test "GET /register displays registration form"
test "POST /register with valid data creates customer"
test "POST /register with invalid email shows error"
test "POST /register with weak password shows error"
test "POST /register with duplicate email shows error"
test "successful registration creates session"
test "successful registration redirects to dashboard"
test "successful registration sends welcome email"
test "rate limits registration (3 per IP per hour)"
```

**Implementation:**
- [ ] Write failing test: "displays registration form"
- [ ] Create CustomerRegistrationController with new/1
- [ ] Create registration form template
- [ ] Write failing test: "creates customer with valid data"
- [ ] Implement create/2 action calling Customers.register_customer/1
- [ ] Write failing test: "validates email format"
- [ ] Add email validation with error display
- [ ] Write failing test: "validates password strength"
- [ ] Add password validation (12+ chars, complexity)
- [ ] Write failing test: "prevents duplicate emails"
- [ ] Add unique email constraint handling
- [ ] Write failing test: "creates session on success"
- [ ] Add session token creation and storage
- [ ] Write failing test: "rate limits registration"
- [ ] Add Hammer rate limiter integration
- [ ] Refactor: Extract validation logic
- [ ] Run test suite: MUST be GREEN

#### Day 3: Customer Login

**Tests to Write First:**
```elixir
test "GET /login displays login form"
test "POST /login with valid credentials creates session"
test "POST /login with valid credentials redirects to dashboard"
test "POST /login with invalid email shows error"
test "POST /login with invalid password shows error"
test "POST /login increments failed attempt counter"
test "POST /login locks account after 5 failed attempts"
test "locked account shows lockout message with time"
test "rate limits login attempts (10 per IP per minute)"
test "remember me checkbox sets longer session"
```

**Implementation:**
- [ ] Write failing test: "displays login form"
- [ ] Create CustomerSessionController with new/1
- [ ] Create login form template
- [ ] Write failing test: "creates session with valid credentials"
- [ ] Implement create/2 calling Customers.authenticate/2
- [ ] Write failing test: "shows error on invalid credentials"
- [ ] Add error handling and display
- [ ] Write failing test: "locks account after 5 failures"
- [ ] Implement account lockout logic in Customers context
- [ ] Write failing test: "rate limits login attempts"
- [ ] Add Hammer rate limiter
- [ ] Refactor: Extract session logic
- [ ] Run test suite: MUST be GREEN

#### Day 4-5: Password Reset

**Tests to Write First:**
```elixir
test "GET /reset-password displays password reset form"
test "POST /reset-password with valid email sends reset link"
test "POST /reset-password with invalid email shows generic message"
test "reset email contains valid token link"
test "GET /reset-password/:token displays password change form"
test "GET /reset-password/:token with invalid token shows error"
test "GET /reset-password/:token with expired token shows error"
test "PUT /reset-password/:token with valid password updates customer"
test "PUT /reset-password/:token with weak password shows error"
test "PUT /reset-password/:token invalidates all sessions"
test "PUT /reset-password/:token invalidates the reset token"
test "rate limits password reset (3 per email per hour)"
```

**Implementation:**
- [ ] Write failing test: "displays password reset form"
- [ ] Create CustomerResetPasswordController with new/1
- [ ] Create password reset request form
- [ ] Write failing test: "sends reset email with valid email"
- [ ] Implement create/2 generating reset token
- [ ] Add reset token to customers table (migration)
- [ ] Write failing test: "reset email contains valid link"
- [ ] Create password reset email template
- [ ] Write failing test: "displays password change form"
- [ ] Implement edit/2 validating reset token
- [ ] Write failing test: "updates password with valid token"
- [ ] Implement update/2 changing password
- [ ] Write failing test: "invalidates all sessions on reset"
- [ ] Add session invalidation logic
- [ ] Write failing test: "rate limits password reset"
- [ ] Add Hammer rate limiter
- [ ] Refactor: Extract token generation
- [ ] Run test suite: MUST be GREEN

### Week 2: Security & Polish (TDD)

#### Day 1-2: Session Management

**Tests to Write First:**
```elixir
test "session expires after 30 days of inactivity"
test "session renews on activity"
test "DELETE /logout clears session"
test "DELETE /logout redirects to home page"
test "logout invalidates session token in database"
test "logged out session cannot access protected pages"
test "concurrent sessions allowed (multiple devices)"
test "session cookie has secure flags (httpOnly, secure)"
test "session cookie sameSite=lax"
```

**Implementation:**
- [ ] Write failing test: "session expires after 30 days"
- [ ] Implement session expiration checking
- [ ] Write failing test: "session renews on activity"
- [ ] Add session renewal in CustomerAuth plug
- [ ] Write failing test: "logout clears session"
- [ ] Implement CustomerSessionController.delete/2
- [ ] Write failing test: "logout invalidates database token"
- [ ] Add Customers.delete_session_token/1
- [ ] Write failing test: "session cookie security flags"
- [ ] Configure cookie options in session plug
- [ ] Refactor: Extract session helpers
- [ ] Run test suite: MUST be GREEN

#### Day 3: Rate Limiting & Security

**Tests to Write First:**
```elixir
test "rate limiter allows 5 login attempts in 5 minutes"
test "rate limiter blocks 6th login attempt"
test "rate limiter shows time until reset"
test "rate limiter uses IP address as key"
test "rate limiter allows requests after timeout"
test "CSRF token required for all forms"
test "CSRF token validation prevents attacks"
test "audit log records login attempts"
test "audit log records password changes"
test "audit log records account lockouts"
```

**Implementation:**
- [ ] Write failing test: "allows 5 login attempts"
- [ ] Add Hammer dependency to mix.exs
- [ ] Configure Hammer rate limiter
- [ ] Write failing test: "blocks 6th attempt"
- [ ] Implement rate limit check in login
- [ ] Write failing test: "shows time until reset"
- [ ] Add rate limit error display
- [ ] Write failing test: "audit log records events"
- [ ] Create customer_audit_logs table (migration)
- [ ] Implement audit logging module
- [ ] Add audit calls to critical actions
- [ ] Refactor: Extract rate limit helpers
- [ ] Run test suite: MUST be GREEN

#### Day 4: Fix CustomerAuth Plug

**Tests to Write First:**
```elixir
test "require_authenticated_customer redirects to /login"
test "require_authenticated_customer sets return_to in session"
test "after login, redirects to return_to path"
test "authenticated customer can access protected routes"
test "fetch_current_customer assigns customer to conn"
test "fetch_current_customer handles missing session"
test "fetch_current_customer handles invalid token"
```

**Implementation:**
- [ ] Write failing test: "redirects to /login (not /admin/login)"
- [ ] Fix CustomerAuth.require_authenticated_customer/2
- [ ] Update redirect from `/admin/login` to `/login`
- [ ] Write failing test: "sets return_to in session"
- [ ] Add return_to logic
- [ ] Write failing test: "redirects to return_to after login"
- [ ] Implement return_to redirect in login controller
- [ ] Write failing test: "fetch_current_customer assigns customer"
- [ ] Verify fetch_current_customer/2 works correctly
- [ ] Refactor: Clean up CustomerAuth module
- [ ] Run test suite: MUST be GREEN

#### Day 5: Integration & Polish

**Tests to Write First:**
```elixir
test "complete registration flow (form → email → dashboard)"
test "complete login flow (form → dashboard)"
test "complete password reset flow (request → email → change → login)"
test "lockout flow (5 failures → lockout → wait → success)"
test "session persistence across requests"
test "logout from multiple tabs works correctly"
test "error messages user-friendly and helpful"
test "forms have proper labels and accessibility"
```

**Implementation:**
- [ ] Write integration test: "registration flow"
- [ ] Verify end-to-end registration works
- [ ] Write integration test: "login flow"
- [ ] Verify end-to-end login works
- [ ] Write integration test: "password reset flow"
- [ ] Verify end-to-end password reset works
- [ ] Polish form templates (accessibility, UX)
- [ ] Add helpful error messages
- [ ] Test dark mode support
- [ ] Run full test suite: MUST be GREEN
- [ ] Deploy to staging

## Database Changes

```sql
-- Add reset token fields to customers table
ALTER TABLE customers ADD COLUMN reset_password_token VARCHAR(255);
ALTER TABLE customers ADD COLUMN reset_password_sent_at TIMESTAMP;
ALTER TABLE customers ADD COLUMN failed_login_attempts INTEGER DEFAULT 0;
ALTER TABLE customers ADD COLUMN locked_at TIMESTAMP;

CREATE INDEX idx_customers_reset_token ON customers(reset_password_token);

-- Audit logging table
CREATE TABLE customer_audit_logs (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  customer_id INTEGER REFERENCES customers(id),
  event_type VARCHAR(50) NOT NULL, -- 'login', 'logout', 'password_change', etc.
  ip_address INET,
  user_agent TEXT,
  metadata JSONB,
  created_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX idx_audit_logs_customer_id ON customer_audit_logs(customer_id);
CREATE INDEX idx_audit_logs_created_at ON customer_audit_logs(created_at DESC);
CREATE INDEX idx_audit_logs_event_type ON customer_audit_logs(event_type);
```

## UI/UX Design

### Design System
- **Framework**: Phoenix Templates (HEEx) with Tailwind CSS
- **Styling**: Match existing site design (dark mode support)
- **Icons**: Heroicons
- **Forms**: Accessible labels, ARIA attributes
- **Responsive**: Mobile-first

### Page Designs

#### Login Page (`/login`)
- Clean centered form
- Email and password inputs
- "Remember me" checkbox
- "Forgot password?" link
- "Don't have an account? Sign up" link
- Error message display area
- Rate limit message (if applicable)

#### Registration Page (`/register`)
- Centered form
- Name, email, password inputs
- Password strength indicator
- Terms of service checkbox
- "Already have an account? Log in" link
- Error message display area
- Success → redirect to dashboard

#### Password Reset Request (`/reset-password`)
- Simple form with email input
- "Send reset link" button
- Generic success message (security: don't reveal if email exists)
- "Remember your password? Log in" link

#### Password Reset Change (`/reset-password/:token`)
- New password input
- Confirm password input
- Password strength indicator
- "Change password" button
- Token validation errors displayed
- Success → redirect to login

## Security Considerations

1. **Password Storage**: Bcrypt with cost factor 12 (already implemented)
2. **Session Tokens**: Cryptographically random, hashed in database
3. **CSRF Protection**: Phoenix built-in tokens on all forms
4. **Rate Limiting**: Hammer library for all auth endpoints
5. **Account Lockout**: 5 failed attempts → 15 minute lockout
6. **Password Reset**: Tokens expire in 1 hour, single-use
7. **Secure Cookies**: httpOnly, secure (HTTPS only), sameSite=lax
8. **Audit Logging**: All authentication events logged with IP/user agent
9. **Email Security**: Generic messages on password reset (don't reveal if email exists)
10. **Session Security**: 30-day expiration, renewal on activity

## Testing Requirements

### Unit Tests (Written During TDD)
```elixir
# Registration
test "validates email format"
test "validates password strength"
test "hashes password with bcrypt"
test "prevents duplicate emails"

# Login
test "authenticates valid credentials"
test "rejects invalid credentials"
test "increments failed attempt counter"
test "locks account after 5 failures"

# Password Reset
test "generates secure reset token"
test "expires reset token after 1 hour"
test "invalidates used reset token"
test "invalidates all sessions on password change"

# Sessions
test "creates session token"
test "validates session token"
test "expires old session tokens"
test "renews active sessions"
```

### Integration Tests (Written During TDD)
```elixir
test "complete registration flow"
test "complete login flow"
test "complete password reset flow"
test "account lockout flow"
test "session persistence"
```

## Success Metrics

### Technical
- **Test Coverage**: ≥ 95% for authentication code
- **Page Load Time**: < 500ms (auth pages)
- **Rate Limit Effectiveness**: 0 brute force successes
- **Session Security**: 0 unauthorized access incidents

### User Experience
- **Registration Completion**: > 90% who start form
- **Login Success Rate**: > 95% (first attempt)
- **Password Reset Completion**: > 80% who request
- **Mobile Usability**: 100% responsive

## Risks & Mitigation

| Risk | Impact | Mitigation |
|------|--------|------------|
| Rate limiter false positives | Medium | Generous limits, clear messaging |
| Email delivery failures | High | Retry logic, fallback SMTP |
| Session fixation attacks | High | Regenerate session ID on login |
| Brute force attacks | High | Rate limiting + account lockout |

## Dependencies & Prerequisites

**Required (Must Complete First):**
- ✅ RFC-064 (Billing & Provisioning) - Completes first
- ✅ RFC-065 (Provisioning) - Creates customers
- ✅ RFC-049 (Customer Management) - Implemented → ADR-026

**Enables:**
- 🔜 RFC-071 (Customer Portal) - Requires authentication

**Blockers:**
- None - Can start immediately after RFC-064 completes

## Implementation Timeline

### Week 1: Registration & Login
- Registration page and flow
- Login page and flow
- Password reset request and change
- TDD tests for all flows

### Week 2: Security & Polish
- Session management
- Rate limiting and lockout
- Audit logging
- Fix CustomerAuth plug
- Integration tests and staging deployment

## Rollout Plan

1. **Development (Weeks 1-2)**: Build with TDD
2. **Staging (Week 2, Day 5)**: Deploy to staging
3. **Beta Testing (1 week)**: Test with 5-10 beta customers
4. **Production (After beta)**: Enable for all customers

## Next Steps

1. Wait for RFC-064 production launch to complete
2. Review and approve RFC-070 draft
3. Create feature branch: `feature/customer-auth`
4. Begin Week 1 TDD implementation
5. Coordinate with RFC-071 team on handoff

## References

- RFC-064: Billing & Provisioning Master Plan (prerequisite)
- RFC-065: Automated Customer Provisioning (customer creation)
- RFC-071: Customer Portal UI (depends on this)
- RFC-049/ADR-026: Customer Management Consolidation (backend auth)
- RFC-056: Admin UI (reference for auth patterns)
- [Elixir 1.19.0 Release Notes](https://elixir-lang.org/blog/2025/10/16/elixir-v1-19-0-released/) - Released October 16, 2025
- [Phoenix Authentication Guide](https://hexdocs.pm/phoenix/1.7.10/custom_authentication.html)
- [OWASP Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)
