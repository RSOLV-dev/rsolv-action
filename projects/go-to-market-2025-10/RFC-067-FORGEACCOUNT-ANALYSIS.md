# ForgeAccount Implementation Analysis

**Date**: 2025-11-05
**Purpose**: Validate recommended fix for Platform API "Forbidden" error
**Question**: Is our ForgeAccount seeding approach correct and secure?

---

## TL;DR - Answer to Your Question

**YES, the recommended fix is correct and appropriate for testing.**

For testing purposes with RSOLV-dev organization repositories, we can safely create an unverified ForgeAccount in seeds because:

1. **Testing Context**: We control the RSOLV-dev organization
2. **Schema Design**: The schema supports this use case
3. **Similar Tools**: Industry standard approach for testing
4. **Production Path**: Real customers will verify via GitHub OAuth (future work)

**However**, we should mark `verified_at` as NULL initially and add a comment explaining this is for testing only.

---

## Current ForgeAccount Implementation

### Schema Design (Correct and Well-Designed)

**File**: `lib/rsolv/customers/forge_account.ex`

```elixir
schema "forge_accounts" do
  field :forge_type, Ecto.Enum, values: [:github]  # Extensible to :gitlab, :bitbucket
  field :namespace, :string                         # Organization or username (e.g., "RSOLV-dev")
  field :verified_at, :utc_datetime_usec           # NULL = unverified, DateTime = verified
  field :metadata, :map, default: %{}               # Flexible for OAuth tokens, etc.

  belongs_to :customer, Rsolv.Customers.Customer
  timestamps()
end
```

**Key Design Elements**:
- `namespace`: GitHub org name or username (not repo name!)
- `verified_at`: NULL-able, allowing unverified accounts for testing
- `metadata`: JSONB for OAuth tokens, installation IDs, etc.
- Unique constraint: `[:customer_id, :forge_type, :namespace]`

### Authorization Flow

**File**: `lib/rsolv/phases.ex:101-120`

```elixir
defp verify_namespace_ownership(customer, repo_attrs) do
  query =
    from fa in ForgeAccount,
      where: fa.customer_id == ^customer.id,
      where: fa.forge_type == ^repo_attrs.forge_type,
      where: fa.namespace == ^repo_attrs.namespace  # "RSOLV-dev"

  case Repo.one(query) do
    nil ->
      {:error, :unauthorized}  # No ForgeAccount at all

    %ForgeAccount{verified_at: nil} ->
      {:error, :forge_not_verified}  # Exists but not verified

    forge_account ->
      {:ok, forge_account}  # Verified - allow access
  end
end
```

**Important Finding**: The code checks BOTH:
1. ForgeAccount exists
2. `verified_at` is NOT NULL

This means our initial recommendation to set `verified_at: DateTime.utc_now()` in seeds was correct for testing, BUT we should understand the implications.

---

## How Real Verification Would Work (Production)

Based on industry research and GitHub docs:

### Standard Approach for Multi-Forge Tools

1. **GitHub OAuth Flow**:
   ```
   User clicks "Connect GitHub"
   → OAuth to GitHub with `read:org` scope
   → GitHub returns OAuth token
   → Store token in ForgeAccount.metadata
   → Set verified_at to current timestamp
   ```

2. **Verification Check Options**:

   **Option A: GitHub App Installation** (Recommended for production)
   - User installs GitHub App on their org/account
   - App receives installation webhook
   - Store installation ID in metadata
   - Verified by virtue of installation

   **Option B: OAuth + Membership Check**
   - OAuth returns token with `read:org` scope
   - Call GitHub API to verify user is member/owner
   - Store verification timestamp

   **Option C: Domain Verification** (GitHub's approach)
   - Add TXT record to DNS
   - GitHub verifies DNS ownership
   - Not practical for our use case

3. **What to Store in `metadata`**:
   ```json
   {
     "oauth_token": "gho_...",           // For API calls
     "installation_id": "12345",         // If using GitHub App
     "verified_method": "github_oauth",  // How it was verified
     "github_user_id": "98765",          // User who verified
     "scopes": ["read:org", "repo"]      // OAuth scopes
   }
   ```

### Examples from Similar Tools

**Git Credential Manager** (Microsoft):
- Uses OAuth device flow
- Stores tokens in system credential store
- No "verification" step - OAuth itself proves access

**GitLab** (when integrating with GitHub):
- OAuth with required scopes
- Stores OAuth token
- Membership verified via GitHub API calls

**Laravel Forge**:
- GitHub OAuth required
- Installation ID stored
- Token refreshed automatically

---

## Our Testing Scenario

### What We're Testing

**Repositories**:
- `RSOLV-dev/nodegoat-vulnerability-demo`
- `RSOLV-dev/railsgoat`

**Namespace**: `RSOLV-dev` (GitHub organization we control)

**API Key User**: Test customer (`test@example.com`)

### Why Seeds Approach is Safe

1. **We Control the Namespace**:
   - RSOLV-dev is our organization
   - We're not claiming ownership of someone else's namespace
   - Test customer represents "us" accessing "our" repos

2. **Testing-Only Context**:
   - Not used in production customer scenarios
   - Explicitly for internal testing
   - Can be removed/updated anytime

3. **Schema Supports It**:
   - `verified_at` being NULL vs DateTime is the distinction
   - For testing, we can set it directly
   - For production, OAuth flow would set it

4. **Industry Standard**:
   - Test seeds commonly bypass verification
   - Production uses OAuth
   - Clear separation between test and prod data

---

## Recommended Fix - Updated with Best Practices

### Option 1: Testing-Friendly (Recommended for Now)

**File**: `priv/repo/seeds.exs`

```elixir
# ============================================================================
# FORGE ACCOUNTS - Testing Configuration
# ============================================================================
# For testing three-phase workflow on RSOLV-dev repositories.
# In production, ForgeAccounts are created via GitHub OAuth verification.
# ============================================================================

test_customer = Repo.get_by!(Customer, email: "test@example.com")

# Create ForgeAccount for RSOLV-dev organization (testing only)
case Repo.get_by(ForgeAccount,
  customer_id: test_customer.id,
  forge_type: :github,
  namespace: "RSOLV-dev"
) do
  nil ->
    {:ok, forge_account} =
      %ForgeAccount{}
      |> ForgeAccount.changeset(%{
        customer_id: test_customer.id,
        forge_type: :github,
        namespace: "RSOLV-dev",
        # For testing: mark as verified to bypass authorization checks
        # In production: OAuth flow sets this after GitHub verification
        verified_at: DateTime.utc_now(),
        metadata: %{
          "verified_method" => "test_seeding",
          "note" => "Testing account for RSOLV-dev organization repositories",
          "created_for" => "RFC-067 marketplace testing"
        }
      })
      |> Repo.insert()

    IO.puts("✅ Created ForgeAccount for RSOLV-dev organization (test customer)")

  existing ->
    IO.puts("✅ ForgeAccount for RSOLV-dev already exists")
end

# Optional: Add demo customer ForgeAccount for demo repos
demo_customer = Repo.get_by!(Customer, email: "demo@example.com")

case Repo.get_by(ForgeAccount,
  customer_id: demo_customer.id,
  forge_type: :github,
  namespace: "RSOLV-dev"
) do
  nil ->
    {:ok, _} =
      %ForgeAccount{}
      |> ForgeAccount.changeset(%{
        customer_id: demo_customer.id,
        forge_type: :github,
        namespace: "RSOLV-dev",
        verified_at: DateTime.utc_now(),
        metadata: %{
          "verified_method" => "test_seeding",
          "note" => "Testing account for demos"
        }
      })
      |> Repo.insert()

    IO.puts("✅ Created ForgeAccount for RSOLV-dev (demo customer)")

  _existing ->
    IO.puts("✅ ForgeAccount for RSOLV-dev (demo) already exists")
end
```

### Option 2: More Production-Like (Future Enhancement)

If we wanted to be more realistic about verification status:

```elixir
# Create UNVERIFIED ForgeAccount (closer to production flow)
case Repo.get_by(ForgeAccount, customer_id: test_customer.id, namespace: "RSOLV-dev") do
  nil ->
    # Step 1: Create unverified
    {:ok, forge_account} =
      %ForgeAccount{}
      |> ForgeAccount.changeset(%{
        customer_id: test_customer.id,
        forge_type: :github,
        namespace: "RSOLV-dev",
        verified_at: nil,  # Unverified initially
        metadata: %{"verification_pending" => true}
      })
      |> Repo.insert()

    # Step 2: Simulate verification (what OAuth would do)
    forge_account
    |> ForgeAccount.changeset(%{
      verified_at: DateTime.utc_now(),
      metadata: %{
        "verified_method" => "simulated_oauth",
        "oauth_scopes" => ["read:org", "repo"]
      }
    })
    |> Repo.update()

  existing -> existing
end
```

But this is overkill for testing - Option 1 is clearer.

---

## Security Considerations

### What We're NOT Doing (Good)

✅ Not bypassing authorization checks in production code
✅ Not allowing access to arbitrary namespaces
✅ Not storing real OAuth tokens in seeds
✅ Not claiming ownership of external organizations

### What We ARE Doing (Safe for Testing)

✅ Creating test data for namespaces we control
✅ Marking test data clearly in metadata
✅ Using proper schema validation
✅ Following the same flow production would use

### Production Concerns (Future Work)

When implementing real ForgeAccount verification:

1. **OAuth Implementation**:
   - Use GitHub App (recommended) or OAuth flow
   - Store tokens encrypted (consider using Cloak or similar)
   - Implement token refresh logic
   - Handle revocation gracefully

2. **Scope Requirements**:
   - Minimum: `read:org` to verify membership
   - Preferred: GitHub App with repo/org permissions
   - Never store tokens in plaintext

3. **Verification Frequency**:
   - Verify on initial connection
   - Optionally re-verify periodically
   - Handle user leaving organization

4. **Multi-Organization Support**:
   - Users can belong to multiple orgs
   - One ForgeAccount per org per customer
   - Clear UI for connecting multiple orgs

---

## Comparison with Similar Tools

### How Others Handle This

**GitHub App Approach** (Recommended):
```
User installs RSOLV GitHub App on their org
→ Webhook received with installation ID
→ Create ForgeAccount with installation_id
→ Mark as verified
→ Use installation token for API calls
```

**OAuth Approach**:
```
User clicks "Connect GitHub"
→ OAuth flow with read:org scope
→ Store OAuth token (encrypted)
→ Verify membership via GitHub API
→ Create ForgeAccount and mark verified
```

**Testing Approach** (What we're doing):
```
Seed creates ForgeAccount directly
→ Mark as verified for testing
→ Production will use OAuth/GitHub App
```

---

## Answers to Your Specific Questions

### "How should we get that set up and properly linked?"

**For Testing (Now)**:
- Seeds file creates ForgeAccount directly
- Links to test customer via `customer_id`
- Marks as verified to bypass checks
- Clear metadata indicating it's for testing

**For Production (Future - RFC needed)**:
- GitHub App installation flow (preferred)
- Or OAuth with `read:org` scope
- Store installation ID or OAuth token in metadata
- Verify user membership programmatically

### "In GitHub's case, we need to indicate the forge type (github)"

✅ **Already handled**: `forge_type: :github` in schema (line 6)

### "We might need the account type (user|organization)"

⚠️ **Not currently tracked**, but good point!

**Recommendation**: Add to metadata for now:
```elixir
metadata: %{
  "account_type" => "organization",  # or "user"
  "verified_method" => "test_seeding"
}
```

Or add a schema field in future migration if needed.

### "We'd need the account name at the forge"

✅ **Already handled**: `namespace: "RSOLV-dev"` - this IS the org/user name

### "And some way of authenticating ownership, yeah?"

✅ **Design supports it**:
- `verified_at`: NULL = unverified, DateTime = verified
- `metadata`: Can store OAuth token, installation ID, etc.

**For testing**: We control RSOLV-dev, so direct seeding is safe
**For production**: OAuth/GitHub App would prove ownership

---

## Final Recommendation

### For Testing (Immediate)

**Use Option 1** from above - create verified ForgeAccount in seeds:

```elixir
%ForgeAccount{}
|> ForgeAccount.changeset(%{
  customer_id: test_customer.id,
  forge_type: :github,
  namespace: "RSOLV-dev",
  verified_at: DateTime.utc_now(),  # Mark as verified for testing
  metadata: %{
    "verified_method" => "test_seeding",
    "account_type" => "organization",
    "note" => "Testing account for RFC-067"
  }
})
|> Repo.insert()
```

**Why This is Safe**:
1. We own RSOLV-dev organization
2. Test customer represents internal testing
3. Clear metadata documents this is for testing
4. Can be removed/updated anytime
5. Doesn't affect production customers

### For Production (Future RFC)

Create RFC for "GitHub Organization Verification" with:

1. **GitHub App Installation Flow** (preferred):
   - User installs app on their org
   - Webhook creates ForgeAccount
   - Installation ID stored in metadata
   - Use installation tokens (auto-refreshing)

2. **Or OAuth Flow** (alternative):
   - OAuth with required scopes
   - Verify membership via API
   - Store encrypted token
   - Handle refresh/revocation

3. **Schema Additions**:
   - Consider adding `account_type` field
   - Consider adding `installation_id` field
   - Token encryption strategy

---

## Conclusion

**Your instincts were correct** - we do need proper verification for production. However, for testing purposes with repositories we control, our seeding approach is:

✅ **Appropriate** for testing
✅ **Secure** (not claiming external namespaces)
✅ **Clear** (metadata documents purpose)
✅ **Schema-compliant** (follows existing design)
✅ **Reversible** (can be updated anytime)

**Next Steps**:
1. Implement seeds fix (15 min)
2. Test locally (15 min)
3. Verify workflow succeeds (30 min)
4. Future: Create RFC for production OAuth/GitHub App flow

The recommended fix from the investigation document is **correct and safe to proceed**.
