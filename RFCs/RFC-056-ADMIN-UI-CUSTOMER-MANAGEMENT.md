# RFC-056: Admin UI for Customer Management

**Status**: Approved  
**Created**: 2025-09-10  
**Approved**: 2025-09-10  
**Author**: Infrastructure Team  
**Related**: 
- RFC-049 (Customer Management Consolidation) - **Implemented** → ADR-026
- RFC-054 (Distributed Rate Limiter) - **Implemented** → ADR-025
- RFC-055 (Customer Schema Consolidation) - **Implemented**

## Summary

Implement a Phoenix LiveView-based admin interface for staff members to manage customer accounts. Staff authentication leverages the unified Customer model (with `is_staff: true` flag) per RFC-049, but throughout this document we'll refer to them simply as "staff" for clarity. This RFC is split from RFC-049 to reduce scope and provide clearer separation between backend consolidation and frontend implementation.

## Problem Statement

After RFC-049 completes the customer consolidation and adds authentication capabilities, we need an admin interface for:
- Staff members to manage customer accounts
- Viewing customer details and usage
- Creating/updating/deactivating customers
- Managing customer limits and quotas

Currently, admin tasks require direct database access or API calls, which is not sustainable for operations.

## Proposed Solution

Build a LiveView-based admin dashboard accessible to staff members (Customer records with `is_staff: true` flag).

### Architecture

```elixir
# Routes in router.ex
scope "/admin", RsolvWeb.Admin do
  pipe_through [:browser, :require_customer_auth, :require_staff]
  
  live_session :admin, on_mount: [{RsolvWeb.LiveHooks, :ensure_staff}] do
    live "/", DashboardLive, :index
    live "/customers", CustomerLive.Index, :index
    live "/customers/new", CustomerLive.Index, :new
    live "/customers/:id", CustomerLive.Show, :show
    live "/customers/:id/edit", CustomerLive.Index, :edit
  end
end
```

## TDD Methodology: Red-Green-Refactor-Review

Following BetterSpecs principles and RFC-049's successful approach:

### Core Principles
1. **Write failing tests FIRST** - No code without a failing test
2. **One assertion per test** - Keep tests focused and clear
3. **Zero failures before proceeding** - Every increment must be GREEN
4. **Use contexts** - Organize with "when", "with", "without"
5. **Short descriptions** - Under 40 characters
6. **Test behavior, not implementation** - Focus on what, not how

### TDD Workflow for Each Feature
```mermaid
graph LR
    A[Write Failing Test] --> B[Run Test - RED]
    B --> C[Write Minimal Code]
    C --> D[Run Test - GREEN]
    D --> E[Refactor if Needed]
    E --> F[Run All Tests - GREEN]
    F --> G[Review & Commit]
    G --> H[Deploy to Staging]
```

### Example TDD Cycle (Login Form)
```elixir
# Step 1: RED - Write failing test
test "renders login form", %{conn: conn} do
  conn = get(conn, ~p"/admin/login")
  assert html_response(conn, 200) =~ "Admin Login"
end
# ❌ Test fails: route doesn't exist

# Step 2: GREEN - Minimal implementation
defmodule RsolvWeb.Admin.SessionController do
  use RsolvWeb, :controller
  
  def new(conn, _params) do
    render(conn, :new, error_message: nil)
  end
end
# ✅ Test passes

# Step 3: REFACTOR - Improve code quality
defmodule RsolvWeb.Admin.SessionController do
  use RsolvWeb, :controller
  alias Rsolv.Customers
  
  def new(conn, _params) do
    render(conn, :new, 
      error_message: nil,
      page_title: "Admin Login")
  end
end
# ✅ All tests still pass

# Step 4: REVIEW - Ensure idiomatic code
# - Check Credo/Dialyzer
# - Verify pattern consistency
# - Update documentation
```

### Test Organization (BetterSpecs-compliant)

```elixir
# test/rsolv_web/controllers/admin/session_controller_test.exs
defmodule RsolvWeb.Admin.SessionControllerTest do
  use RsolvWeb.ConnCase, async: true
  alias Rsolv.Customers

  describe ".create" do
    context "when credentials are valid" do
      context "with staff member" do
        test "creates session", %{conn: conn} do
          # RED: Write test first
          {:ok, staff} = Customers.register_customer(%{
            email: "admin@test.com",
            password: "Valid123!Pass",
            is_staff: true
          })
          
          # Act
          conn = post(conn, ~p"/admin/login", %{
            "session" => %{"email" => "admin@test.com", "password" => "Valid123!Pass"}
          })
          
          # Assert - one assertion per test
          assert redirected_to(conn) == ~p"/admin"
        end
        
        test "sets session token", %{conn: conn} do
          {:ok, staff} = Customers.register_customer(%{
            email: "admin2@test.com",
            password: "Valid123!Pass",
            is_staff: true
          })
          
          conn = post(conn, ~p"/admin/login", %{
            "session" => %{"email" => "admin2@test.com", "password" => "Valid123!Pass"}
          })
          
          assert get_session(conn, :customer_token)
        end
      end
      
      context "without staff flag" do
        test "denies access", %{conn: conn} do
          {:ok, customer} = Customers.register_customer(%{
            email: "user@test.com",
            password: "Valid123!Pass",
            is_staff: false
          })
          
          conn = post(conn, ~p"/admin/login", %{
            "session" => %{"email" => "user@test.com", "password" => "Valid123!Pass"}
          })
          
          assert html_response(conn, 401) =~ "unauthorized"
        end
      end
    end
    
    context "when credentials are invalid" do
      test "renders login", %{conn: conn} do
        conn = post(conn, ~p"/admin/login", %{
          "session" => %{"email" => "bad@test.com", "password" => "wrong"}
        })
        
        assert html_response(conn, 200) =~ "Invalid email or password"
      end
    end
    
    context "when rate limited" do
      test "blocks after 10 attempts", %{conn: conn} do
        # Make 10 failed attempts
        for i <- 1..10 do
          post(conn, ~p"/admin/login", %{
            "session" => %{"email" => "test@test.com", "password" => "wrong#{i}"}
          })
        end
        
        # 11th attempt should be blocked
        conn = post(conn, ~p"/admin/login", %{
          "session" => %{"email" => "test@test.com", "password" => "wrong11"}
        })
        
        assert conn.status == 429
      end
    end
  end
end
```

## Implementation Plan: Incremental TDD

Each increment follows strict RED → GREEN → REFACTOR → REVIEW cycle.

### Development Workflow

1. **Feature Branch**: Create `feature/admin-ui` branch for development
   ```bash
   git checkout -b feature/admin-ui
   ```

2. **Incremental Commits**: Commit after each GREEN state
   ```bash
   git add -A
   git commit -m "feat(admin): implement login form with tests passing"
   ```

3. **PR Review**: Create PR after each major increment for review
4. **Merge Strategy**: Squash merge to main after full increment completion

### Increment 1: Login Form (2 hours)
**Todo List:**
- [ ] Write failing test: "renders login form"
- [ ] Implement minimal login page
- [ ] Write failing test: "shows email field"
- [ ] Add email input field
- [ ] Write failing test: "shows password field"  
- [ ] Add password input field
- [ ] Write failing test: "submits to session path"
- [ ] Add form action
- [ ] Run test suite: MUST be GREEN
- [ ] Refactor for idiomaticity
- [ ] Deploy to staging

### Increment 2: Authentication Logic (3 hours)
**Todo List:**
- [ ] Write failing test: "authenticates valid staff member"
- [ ] Implement Customers.authenticate_customer_by_email_and_password/2 call
- [ ] Write failing test: "creates session token"
- [ ] Implement session creation
- [ ] Write failing test: "redirects to dashboard"
- [ ] Add redirect logic
- [ ] Write failing test: "rejects invalid password"
- [ ] Handle authentication failure
- [ ] Write failing test: "rejects non-staff users"
- [ ] Check is_staff flag
- [ ] Run test suite: MUST be GREEN
- [ ] Deploy to staging

### Increment 3: Rate Limiting (1 hour)
**Todo List:**
- [ ] Write failing test: "allows 10 attempts"
- [ ] Integrate Mnesia rate limiter
- [ ] Write failing test: "blocks 11th attempt"
- [ ] Return 429 on limit exceeded
- [ ] Write failing test: "resets after 1 minute"
- [ ] Verify timeout behavior
- [ ] Run test suite: MUST be GREEN
- [ ] Deploy to staging

### Increment 4: Customer List LiveView (4 hours)
**Todo List:**
- [ ] Write failing test: "mounts with customers"
- [ ] Create CustomerLive.Index module
- [ ] Write failing test: "renders customer table"
- [ ] Add table template
- [ ] Write failing test: "shows customer name"
- [ ] Display customer fields
- [ ] Write failing test: "paginates at 20"
- [ ] Implement pagination
- [ ] Write failing test: "filters by status"
- [ ] Add status filter
- [ ] Write failing test: "updates filter on click"
- [ ] Implement live filtering
- [ ] Write failing test: "sorts by column"
- [ ] Add sorting functionality
- [ ] Run test suite: MUST be GREEN
- [ ] Deploy to staging

**Test Example (BetterSpecs-compliant):**
```elixir
# test/rsolv_web/live/admin/customer_live_test.exs
describe "Index" do
  import Phoenix.LiveViewTest
  
  setup [:create_staff_member]
  
  test "lists customers", %{conn: conn} do
    customer = customer_fixture()
    {:ok, _index_live, html} = live(conn, ~p"/admin/customers")
    
    assert html =~ customer.name
  end
  
  test "paginates at 20", %{conn: conn} do
    for i <- 1..25, do: customer_fixture(name: "Customer #{i}")
    
    {:ok, view, _html} = live(conn, ~p"/admin/customers")
    
    assert view |> element("#customer-19") |> has_element?()
    refute view |> element("#customer-21") |> has_element?()
  end
  
  test "filters by status", %{conn: conn} do
    active = customer_fixture(active: true)
    inactive = customer_fixture(active: false)
    
    {:ok, view, _html} = live(conn, ~p"/admin/customers")
    
    view |> element("[phx-click=filter][phx-value-status=inactive]") |> render_click()
    
    refute view |> element("#customer-#{active.id}") |> has_element?()
    assert view |> element("#customer-#{inactive.id}") |> has_element?()
  end
end
```

### Increment 5: Customer Details (2 hours)
**Todo List:**
- [ ] Write failing test: "shows customer info"
- [ ] Create CustomerLive.Show
- [ ] Write failing test: "displays API keys"
- [ ] Add API keys section
- [ ] Write failing test: "shows usage stats"
- [ ] Add usage display
- [ ] Run test suite: MUST be GREEN
- [ ] Deploy to staging

### Increment 6: Customer Edit (3 hours)
**Todo List:**
- [ ] Write failing test: "renders edit form"
- [ ] Create edit modal
- [ ] Write failing test: "updates customer"
- [ ] Implement update logic
- [ ] Write failing test: "validates changes"
- [ ] Add validation
- [ ] Write failing test: "shows success"
- [ ] Add flash message
- [ ] Run test suite: MUST be GREEN
- [ ] Deploy to staging

## Security Considerations

1. **Authentication**: Requires password login (no API key access for admin)
2. **Authorization**: Only records with `is_staff: true` can access
3. **Rate limiting**: Prevent brute force attacks on admin login
4. **Audit trail**: Log all admin actions with timestamp and actor
5. **CSRF protection**: Phoenix's built-in CSRF tokens
6. **Session timeout**: Auto-logout after inactivity

## UI/UX Design

### Technology Stack
- Phoenix LiveView for real-time updates
- Tailwind CSS for styling (using existing setup)
- Alpine.js for client-side interactions if needed

### Key Views

1. **Dashboard**: Overview of system metrics
2. **Customer List**: Sortable, filterable table
3. **Customer Detail**: Comprehensive customer information
4. **Customer Form**: Create/edit customer with validation

## Test Helpers and Fixtures

Following RFC-049's pattern with `APITestHelpers`:

```elixir
# test/support/admin_test_helpers.ex
defmodule Rsolv.AdminTestHelpers do
  use RsolvWeb.ConnCase
  
  def create_staff_member(_context) do
    {:ok, staff} = Customers.register_customer(%{
      email: "staff#{System.unique_integer()}@test.com",
      password: "StaffP@ssw0rd2025!",
      is_staff: true,
      admin_level: "full"
    })
    
    {:ok, staff: staff}
  end
  
  def log_in_staff(%{conn: conn, staff: staff}) do
    token = Customers.generate_customer_session_token(staff)
    conn = conn
           |> Phoenix.ConnTest.init_test_session(%{})
           |> Plug.Conn.put_session(:customer_token, token)
    
    {:ok, conn: conn}
  end
  
  def customer_fixture(attrs \\ %{}) do
    {:ok, customer} = 
      attrs
      |> Enum.into(%{
        name: "Customer #{System.unique_integer()}",
        email: "customer#{System.unique_integer()}@test.com",
        monthly_limit: 100,
        active: true
      })
      |> Customers.create_customer()
    
    customer
  end
end
```

## Success Metrics

### TDD Process Metrics
- **Test Coverage**: 100% for admin UI components
- **Test-First Compliance**: Every feature has failing test before implementation
- **Green Suite**: Zero test failures at each increment completion
- **Test Speed**: Full admin test suite runs in < 5 seconds
- **BetterSpecs Adherence**: All tests follow documented patterns

### Business Metrics
- Staff can manage customers without database access
- Reduced time to onboard new customers (< 2 minutes)
- Complete audit trail for all admin actions
- No security vulnerabilities in admin interface
- Responsive UI that works on mobile devices
- Zero production incidents from admin operations

## Future Enhancements

1. **Role-based access control** - Different admin levels
2. **API for admin operations** - Programmatic admin access
3. **Webhooks** - Notify external systems of customer changes
4. **Self-service portal** - Let customers manage their own accounts

## Dependencies

All dependencies are now satisfied:
- ✅ RFC-049 (Customer Management Consolidation) - **Completed** as ADR-026
- ✅ RFC-054 (Distributed Rate Limiter) - **Completed** as ADR-025
- ✅ RFC-055 (Customer Schema Consolidation) - **Completed**
- ✅ Existing Phoenix LiveView setup - Already in place
- ✅ Tailwind CSS configuration - Already configured

## Risks

1. **Security**: Admin interface is high-value target
   - Mitigation: Multiple layers of authentication, rate limiting, audit logs

2. **Performance**: Large customer lists could be slow
   - Mitigation: Pagination, database indexes, query optimization

3. **Complexity**: LiveView state management can be complex
   - Mitigation: Start simple, add features incrementally

## References

- [Phoenix LiveView Documentation](https://hexdocs.pm/phoenix_live_view)
- [BetterSpecs](https://betterspecs.org) - Testing best practices
- [ADR-026](../ADRs/ADR-026-CUSTOMER-MANAGEMENT-CONSOLIDATION.md) - Customer consolidation implementation
- [ADR-025](../ADRs/ADR-025-DISTRIBUTED-RATE-LIMITING-WITH-MNESIA.md) - Rate limiting implementation
- RFC-055 - Customer schema consolidation details