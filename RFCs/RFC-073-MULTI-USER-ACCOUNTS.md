# RFC-073: Multi-User Account Management

**Status**: Draft (Future Work - post RFC-064)
**Created**: 2025-10-20
**Timeline**: TBD
**Dependencies**: RFC-070 (Customer Authentication), RFC-071 (Customer Portal)

## Related RFCs

**Depends on:**
- RFC-070 (Customer Authentication) - Auth system required
- RFC-071 (Customer Portal UI) - UI for team management

**Enables:**
- Organizational/team usage
- Role-based access control
- Shared billing across team members

## Summary

Enable multiple users to collaborate on a shared RSOLV account with team invitations, role-based permissions, and shared billing.

**Note:** This RFC is about multi-user account features, not about specific subscription plan names or pricing tiers.

## Problem

Current model: One customer = One user
- Organizations need multiple team members with access
- No way to share API keys securely
- No delegation or role separation
- All billing tied to single owner

## Proposed Solution

### Multi-User Features
- Team invitations via email
- Role-based permissions (Owner, Admin, Developer, Viewer)
- Shared dashboard and API keys
- Activity audit log per user

### Billing Implications
- Single billing entity (account owner)
- Usage attributed to account, not individual users
- Subscription shared across team

## Benefits

- **Enterprise-ready** - Support organizational usage
- **Better security** - No shared credentials
- **Audit trail** - Track who did what
- **Scalability** - Grow with customer needs

## Technical Approach

**To be determined:**
- User roles and permissions model
- Invitation flow (email + signup)
- Database schema (accounts vs users)
- API key scoping (account-level vs user-level)

## Next Steps

1. Complete RFC-070 and RFC-071
2. Research enterprise customer requirements
3. Design team management UX
4. Create detailed implementation plan
