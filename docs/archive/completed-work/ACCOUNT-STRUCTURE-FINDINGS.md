# RSOLV Account Structure - Revised Analysis for RFC

**Date**: 2025-09-03  
**Status**: Ready for RFC Development  
**Context**: Deep dive into account/customer/billing structure while debugging demo API key issues
**Key Finding**: Multiple duplicate and legacy systems need consolidation

## Executive Summary

The RSOLV platform has three parallel customer systems that need consolidation:
1. **Customers.Customer** - Primary system with User relationship and proper structure
2. **Billing.Customer** - Duplicate schema without User relationship (should be merged)
3. **LegacyAccounts** - Hardcoded test/demo accounts (should be eliminated)

No customer self-service API exists. The system requires managed onboarding.

## Current Account Entities

### 1. User (`Rsolv.Accounts.User`)
**Location**: `lib/rsolv/accounts/user.ex`
- Root authentication entity
- Contains email, password (hashed)
- Has many customers (1:N relationship)
- Has email subscription preferences
- Standard Phoenix authentication setup

### 2. Customer (`Rsolv.Customers.Customer`) 
**Location**: `lib/rsolv/customers/customer.ex`
- Primary business entity for API access
- Belongs to a User
- Contains:
  - API key (auto-generated or custom)
  - Monthly usage limits
  - Current usage tracking
  - GitHub organization
  - Plan type (trial, pay_as_you_go, etc.)
  - Metadata map
- Has many API keys (supports multiple keys per customer)
- Has many fix attempts

### 3. Billing Customer (`Rsolv.Billing.Customer`) - SHOULD BE MERGED
**Location**: `lib/rsolv/billing/customer.ex`
- Duplicate schema that should be consolidated with Customers.Customer
- Contains billing-specific fields that should be added to main Customer:
  - Trial tracking (fixes used/limit/expired)
  - Subscription plan
  - Stripe customer ID
  - Rollover fixes
- **Critical Issue**: No User relationship (breaks account hierarchy)
- **Action**: Merge these fields into Customers.Customer and migrate data

### 4. ForgeAccount (`Rsolv.Phases.ForgeAccount`)
**Location**: `lib/rsolv/phases/forge_account.ex`
- Links customers to source control providers
- Contains:
  - Forge type (currently only GitHub)
  - Namespace (organization/username)
  - Verification status
  - Metadata
- Belongs to Customer
- Used for repository access and permissions

### 5. ApiKey (`Rsolv.Customers.ApiKey`)
**Location**: `lib/rsolv/customers/api_key.ex` (inferred)
- Multiple keys per customer
- Supports key rotation
- Has name/description
- Tracks creation date

## Account Creation Flow

### Current Process (Inferred)
1. User registers (creates `User` record)
2. Customer created linked to User (creates `Customer` record)
3. API key auto-generated or specified
4. ForgeAccount optionally created for GitHub integration
5. Billing/subscription set up separately

### Issues Discovered
1. **No public API for customer creation** - All creation is internal
2. **Duplicate customer schemas** - `Customers.Customer` vs `Billing.Customer`
3. **Unclear relationship** between the two customer types
4. **No self-service path** for API key generation

## API Endpoints

### Available
- `/api/v1/credentials/exchange` - Exchange API key for temporary credentials
- `/api/v1/credentials/refresh` - Refresh credentials
- `/api/v1/usage/report` - Report usage

### Missing
- No customer registration endpoint
- No API key management endpoints
- No self-service account management
- No billing/subscription management APIs

## Database Schema

### customers table (appears twice)
```sql
-- From Customers context
- id
- name
- email  
- api_key
- monthly_limit
- current_usage
- active
- metadata
- user_id (FK)
- github_org
- plan

-- From Billing context
- id
- name
- email
- api_key
- active
- trial_fixes_used
- trial_fixes_limit
- trial_expired
- subscription_plan
- rollover_fixes
- stripe_customer_id
- metadata
```

## Credential Vending System

### How It Works
1. Customer provides API key to `/api/v1/credentials/exchange`
2. System validates API key against customer record
3. Returns temporary credentials for:
   - Anthropic
   - OpenAI
   - OpenRouter
4. Credentials expire after TTL (max 4 hours)

### Issue Found
The demo repository's GitHub secret contains an invalid/expired API key, preventing credential vending from working.

## Scripts and Tools

### Available
- `priv/repo/add_api_key.exs` - Add customer with API key (has bugs)
- `priv/repo/list_customers.exs` - List all customers
- `priv/repo/update_customer.exs` - Update customer details
- Various one-off scripts for creating demo/test customers

### Problems
- Scripts expect direct database access
- Don't work properly in production environment
- Some have syntax errors (mixing module/script syntax)

## Payment Integration

### Current State
- Stripe customer ID field exists
- No actual Stripe integration code found
- Plans are strings: "trial", "pay_as_you_go"
- Usage tracking implemented
- No billing/payment processing logic

## Legacy Module to Eliminate

### LegacyAccounts Module - SHOULD BE REMOVED
**Location**: `lib/rsolv/legacy_accounts.ex`
- Contains hardcoded test/demo accounts:
  - Environment-based keys (INTERNAL_API_KEY, DEMO_API_KEY, MASTER_API_KEY, DOGFOOD_API_KEY)
  - Hardcoded test keys (rsolv_test_abc123, etc.)
- Uses :persistent_term for in-memory storage (not production-ready)
- Falls back to direct database query (bypasses proper contexts)
- **Action**: Replace with proper test fixtures and seed data

## Consolidation Strategy

### 1. Schema Consolidation
- **Primary**: Keep `Customers.Customer` as the single source of truth
- **Merge**: Add billing fields from `Billing.Customer` to main schema
- **Eliminate**: Remove `LegacyAccounts` module entirely

### 2. Data Migration Path
- Migrate existing `Billing.Customer` records to `Customers.Customer`
- Create proper User relationships for orphaned billing customers
- Replace hardcoded test accounts with database fixtures

### 3. API Design Requirements
- Customer CRUD endpoints (admin-only initially)
- API key management endpoints
- Self-service registration (if business model allows)
- Billing/subscription management

## RFC Requirements

### Must Have
1. **Single Customer Schema** - Consolidate all customer data into `Customers.Customer`
2. **Remove Legacy Code** - Eliminate `LegacyAccounts` and `Billing.Customer`
3. **Clear Relationships** - Maintain User → Customer → ForgeAccount → ApiKey hierarchy
4. **Data Migration** - Safe path to consolidate existing records

### Should Have
5. **Admin API** - Internal endpoints for customer management
6. **Stripe Integration** - Proper billing with consolidated schema
7. **Test Fixtures** - Replace hardcoded accounts with proper test data

### Could Have
8. **Self-Service API** - Public registration (if business model permits)
9. **API Key Rotation** - Lifecycle management for security
10. **Multi-Forge Support** - Extend ForgeAccount for GitLab, Bitbucket, etc.

## Immediate Actions (Demo Fix)

### Short-term (Before RFC)
1. Create valid API key using existing Customers.Customer context
2. Update GitHub secrets with new key
3. Test credential vending end-to-end

### Medium-term (RFC Implementation)
1. Consolidate schemas into single Customer entity
2. Migrate billing data to main customer table
3. Remove LegacyAccounts module
4. Create admin API for customer management

### Long-term (Post-RFC)
1. Implement self-service if needed
2. Add comprehensive billing integration
3. Support multiple forge providers

## Key Insight

The existence of three parallel customer systems (`Customers.Customer`, `Billing.Customer`, and `LegacyAccounts`) suggests rapid iteration without proper consolidation. The RFC should establish a single, authoritative customer model that handles authentication, billing, and forge integration in a unified way.

## Test Coverage Analysis

### Current Test Coverage

#### What's Tested
- **`Rsolv.AccountsTest`** (test/rsolv/accounts_test.exs)
  - Tests the Accounts context which delegates to LegacyAccounts
  - Verifies hardcoded keys are rejected
  - Tests environment variable-based keys work
  - Validates test customer attributes
  - **All tests passing** ✅

#### What's NOT Tested
- **`Rsolv.Customers` context** - NO TESTS ❌
  - No tests for Customer CRUD operations
  - No tests for User → Customer relationships
  - No tests for ApiKey management
  - No tests for ForgeAccount integration

- **`Rsolv.Billing.Customer`** - NO TESTS ❌
  - No tests for billing-specific fields
  - No tests for trial management
  - No tests for Stripe integration
  - No tests for subscription plans

- **`Rsolv.LegacyAccounts`** - MINIMAL TESTS ⚠️
  - Only tested indirectly through Accounts context
  - No tests for database fallback behavior
  - No tests for :persistent_term storage

### Documentation Coverage
- **Accounts module**: Has @doc strings but NO doctests
- **Customers module**: Unknown (needs checking)
- **Billing module**: Unknown (needs checking)
- **LegacyAccounts**: Has @doc strings but NO doctests

### Critical Test Gaps for Consolidation

1. **No integration tests** between the three systems
2. **No migration tests** for moving data between schemas
3. **No API endpoint tests** for customer management
4. **No credential vending tests** with real customers
5. **No tests for duplicate detection** across systems