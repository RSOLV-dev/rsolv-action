# RFC-056: Admin UI for Customer Management

**Status**: Draft  
**Created**: 2025-09-10  
**Author**: Infrastructure Team  
**Related**: 
- RFC-049 (Customer Management Consolidation) - Must be completed first
- RFC-054 (Distributed Rate Limiter) - Already implemented

## Summary

Implement a Phoenix LiveView-based admin interface for staff customers to manage other customers. This RFC is split from RFC-049 to reduce scope and provide clearer separation between backend consolidation and frontend implementation.

## Problem Statement

After RFC-049 completes the customer consolidation and adds authentication capabilities, we need an admin interface for:
- Staff members to manage customer accounts
- Viewing customer details and usage
- Creating/updating/deactivating customers
- Managing customer limits and quotas

Currently, admin tasks require direct database access or API calls, which is not sustainable for operations.

## Proposed Solution

Build a LiveView-based admin dashboard accessible to customers with `is_staff: true` flag.

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

## Testing Strategy

Following BetterSpecs and ExUnit best practices:

1. **Test files**:
   - `test/rsolv_web/live/admin/customer_live_test.exs` - LiveView tests
   - `test/rsolv_web/controllers/admin/session_controller_test.exs` - Auth tests

2. **Test organization**:
   ```elixir
   describe "authentication" do
     test "requires staff access"
     test "redirects non-staff customers"
     test "rate limits login attempts"
   end
   
   describe "customer management" do
     test "lists all customers"
     test "filters by status"
     test "creates new customer"
     test "updates customer details"
   end
   ```

## Implementation Plan

### Phase 1: Authentication & Authorization

1. **Login page** for customer email/password authentication
2. **Staff check middleware** to verify is_staff flag
3. **Rate limiting** on login attempts using RFC-054's Mnesia implementation
4. **Session management** with secure cookies

### Phase 2: Customer Management Views

1. **Customer list** with pagination and search
2. **Customer details** showing usage, limits, billing info
3. **Customer edit** for updating limits, status, metadata
4. **Customer creation** for manual customer onboarding

### Phase 3: Advanced Features

1. **Usage analytics** - graphs showing customer API usage
2. **Audit log** - track admin actions for compliance
3. **Bulk operations** - update multiple customers at once
4. **Export functionality** - CSV export of customer data

## Security Considerations

1. **Authentication**: Requires customer password login (no API key access)
2. **Authorization**: Only customers with `is_staff: true` can access
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

## Success Metrics

- Staff can manage customers without database access
- Reduced time to onboard new customers
- Audit trail for all admin actions
- No security vulnerabilities in admin interface
- Responsive UI that works on mobile devices

## Future Enhancements

1. **Role-based access control** - Different admin levels
2. **API for admin operations** - Programmatic admin access
3. **Webhooks** - Notify external systems of customer changes
4. **Self-service portal** - Let customers manage their own accounts

## Dependencies

- RFC-049 must be completed first (customer authentication)
- RFC-054 (rate limiter) already implemented
- Existing Phoenix LiveView setup
- Tailwind CSS configuration

## Risks

1. **Security**: Admin interface is high-value target
   - Mitigation: Multiple layers of authentication, rate limiting, audit logs

2. **Performance**: Large customer lists could be slow
   - Mitigation: Pagination, database indexes, query optimization

3. **Complexity**: LiveView state management can be complex
   - Mitigation: Start simple, add features incrementally

## References

- [Phoenix LiveView Documentation](https://hexdocs.pm/phoenix_live_view)
- [BetterSpecs](https://betterspecs.org) for testing guidelines
- RFC-049 for customer model changes
- RFC-054 for rate limiting implementation