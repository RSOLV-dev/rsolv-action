# ADR-026: Customer Management Consolidation

**Status**: Implemented  
**Date**: 2025-09-11  
**RFC**: RFC-049  

## Context

The RSOLV platform had evolved with multiple overlapping user/customer management systems:
- Legacy `User` entity with authentication via `UserToken`
- `Billing.Customer` schema for billing management
- `Customers.Customer` for API customers
- Duplicate authentication logic across modules
- Inconsistent data models between billing and customer management

This created significant technical debt:
- Complex data synchronization requirements
- Confusion about which entity to use for authentication
- Duplicate functionality across modules
- Increased maintenance burden
- Potential security issues from multiple auth paths

## Decision

We consolidated all user/customer management into a single `Customers.Customer` entity:

1. **Removed User Entity Completely**
   - Deleted `Accounts.User` and `Accounts.UserToken` schemas
   - Removed `Billing.Customer` schema
   - Eliminated `LegacyAccounts` module
   - Total reduction: ~1,049 lines of code

2. **Enhanced Customer Schema**
   - Added authentication fields directly to `Customers.Customer`:
     - `password_hash` - Bcrypt with work factor 12
     - `is_staff` - Boolean flag for admin access
     - `admin_level` - Granular permissions (read_only, limited, full)
   - Maintained all existing customer fields for backward compatibility

3. **Implemented Distributed Rate Limiting**
   - Mnesia-based distributed rate limiter (RFC-054)
   - 10 login attempts per minute per email
   - Cluster-wide rate limiting across all nodes

4. **Unified Authentication Flow**
   - Single `authenticate_customer_by_email_and_password/2` function
   - Integrated rate limiting at authentication layer
   - Strong password requirements (12+ chars, mixed case, numbers, special)

## Implementation Details

### Migration Strategy
1. Added authentication fields via migration (non-breaking)
2. Updated all test helpers to use new authentication
3. Removed User references systematically
4. Deleted legacy controllers and modules
5. Achieved zero test failures before deployment

### Key Changes
- **Database**: Two migrations added authentication fields
- **API**: All endpoints now use Customer-based auth
- **Tests**: New `APITestHelpers` module for consistent test setup
- **Pattern Controller**: Removed legacy `/patterns/*` endpoints
- **Rate Limiting**: Mnesia tables auto-replicate across cluster

## Consequences

### Positive
- **Simplified Architecture**: Single source of truth for user/customer data
- **Reduced Complexity**: 1,049 lines of code removed
- **Improved Security**: Single authentication path to audit and secure
- **Better Performance**: No cross-schema queries or data synchronization
- **Easier Maintenance**: One model to update instead of four
- **Distributed Rate Limiting**: Protection against brute force attacks

### Negative
- **Migration Risk**: All authentication flows had to be updated simultaneously
- **No Rollback Path**: Once User entity removed, cannot easily revert
- **API Surface Changes**: Legacy pattern endpoints removed (but unused)

### Neutral
- **Password Storage**: Now directly on Customer vs separate User entity
- **Admin Flags**: Moved from User to Customer (same functionality)

## Metrics

- **Code Reduction**: -1,049 net lines
- **Files Deleted**: 6 major files (User, UserToken, LegacyAccounts, etc.)
- **Test Coverage**: Maintained 100% (0 failures)
- **Deployment**: Successfully deployed to staging and production
- **Performance**: No degradation observed

## Lessons Learned

1. **Test-First Approach Critical**: Maintaining zero test failures throughout ensured confidence
2. **Helper Modules Valuable**: `APITestHelpers` simplified test migration significantly
3. **Incremental Migration Works**: Adding fields before removing entities reduced risk
4. **Distributed Systems Need Distributed Solutions**: Mnesia for rate limiting across cluster

## Related

- **RFC-049**: Customer Management Consolidation (specification)
- **RFC-054**: Distributed Rate Limiter with Mnesia (implemented)
- **RFC-055**: Customer Schema Consolidation (implemented)
- **ADR-025**: Distributed Rate Limiting with Mnesia