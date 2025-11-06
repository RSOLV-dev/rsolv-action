# RFC-067: Platform Phase Data API Investigation

**Date**: 2025-11-05
**Status**: Root Cause Identified
**Severity**: CRITICAL - Blocks Marketplace Submission

## Executive Summary

**ROOT CAUSE FOUND**: The Platform phase data retrieval API (`GET /api/v1/phases/retrieve`) returns "Forbidden" because it requires **verified ForgeAccount ownership** of the repository namespace. The API key used by GitHub Actions in test repositories (RSOLV-dev/nodegoat-vulnerability-demo, RSOLV-dev/railsgoat) doesn't have a verified ForgeAccount for the "RSOLV-dev" organization.

## Investigation Timeline

### Initial Symptom
MITIGATE phase fails with:
```
Platform retrieval failed, falling back to local: warn: Platform retrieval failed: Forbidden
at retrievePhaseResults (/app/dist/index.js:2966:71215)
```

### Discovery Process
1. Checked if endpoint exists → ✅ **YES** (`lib/rsolv_web/router.ex:260`)
2. Read controller code → ✅ **Properly implemented**
3. Read Phases context → 🔍 **Found authorization check**

## Technical Analysis

### Endpoint Details

**URL**: `GET /api/v1/phases/retrieve`
**Route**: `lib/rsolv_web/router.ex:260`
**Controller**: `lib/rsolv_web/controllers/api/v1/phase_controller.ex:275`

**Required Query Parameters**:
- `repo`: Repository in "owner/name" format (e.g., "RSOLV-dev/nodegoat-vulnerability-demo")
- `issue`: GitHub issue number (integer)
- `commit`: Git commit SHA

**Authentication**: Requires valid API key via `ApiKeyAuth`

### Authorization Flow

**Code Path**: `lib/rsolv/phases.ex:235-238`

```elixir
def retrieve(repo_string, issue_number, commit_sha, %ApiKey{} = api_key) do
  with {:ok, customer} <- get_customer_from_api_key(api_key),
       {:ok, repo_attrs} <- parse_repo_string(repo_string),
       {:ok, _forge_account} <- verify_namespace_ownership(customer, repo_attrs),  # ← FAILS HERE
       {:ok, repository} <- get_repository(repo_attrs) do
    # ... retrieve phase data ...
  end
end
```

**The Critical Check**: `verify_namespace_ownership/2` (lines 101-120)

```elixir
defp verify_namespace_ownership(customer, repo_attrs) do
  import Ecto.Query

  query =
    from fa in ForgeAccount,
      where: fa.customer_id == ^customer.id,
      where: fa.forge_type == ^repo_attrs.forge_type,
      where: fa.namespace == ^repo_attrs.namespace  # ← Must match "RSOLV-dev"

  case Repo.one(query) do
    nil ->
      {:error, :unauthorized}  # ← RETURNS THIS

    %ForgeAccount{verified_at: nil} ->
      {:error, :forge_not_verified}

    forge_account ->
      {:ok, forge_account}
  end
end
```

### What's Required

For the API call to succeed, the customer associated with the API key must have:

1. **A ForgeAccount record** with:
   - `customer_id` matching the API key's customer
   - `forge_type` = `:github`
   - `namespace` = `"RSOLV-dev"` (the GitHub organization)
   - `verified_at` IS NOT NULL (must be verified)

2. **Why It Fails**:
   - Test API keys (like `rsolv_test_key_123`) are created during seeding
   - Seeding creates customers and API keys but NOT ForgeAccounts
   - Without ForgeAccount, authorization check fails with `:unauthorized`
   - Controller/plug translates this to HTTP 403 Forbidden

## Impact Analysis

### What Works
- ✅ **SCAN Phase**: Stores phase data (doesn't retrieve)
- ✅ **VALIDATE Phase**: Stores validation data (doesn't retrieve)
- ✅ **Issue Creation**: GitHub issue creation works
- ✅ **Issue Labeling**: Label updates work

### What Fails
- ❌ **MITIGATE Phase**: Cannot retrieve phase data from previous phases
- ❌ **Multi-phase Context**: Cannot access scan/validation results during mitigation
- ❌ **Test-First Workflow**: Cannot verify tests before applying fixes

### Marketplace Impact
**ABSOLUTE BLOCKER**:
- Cannot demonstrate complete three-phase workflow
- No PRs created with fixes
- Missing core product differentiator
- No screenshots for marketplace listing

## Solutions

### Option A: Remove Authorization Check for Testing (Quick Fix)

**Approach**: Add bypass for RSOLV-dev organization in testing mode

**Code Change** in `lib/rsolv/phases.ex`:

```elixir
defp verify_namespace_ownership(customer, repo_attrs) do
  # TESTING MODE: Allow RSOLV-dev organization without ForgeAccount
  # This enables testing on our demo/test repositories
  if repo_attrs.namespace == "RSOLV-dev" and testing_mode?() do
    {:ok, :testing_bypass}
  else
    # Normal authorization check
    import Ecto.Query

    query =
      from fa in ForgeAccount,
        where: fa.customer_id == ^customer.id,
        where: fa.forge_type == ^repo_attrs.forge_type,
        where: fa.namespace == ^repo_attrs.namespace

    case Repo.one(query) do
      nil -> {:error, :unauthorized}
      %ForgeAccount{verified_at: nil} -> {:error, :forge_not_verified}
      forge_account -> {:ok, forge_account}
    end
  end
end

defp testing_mode?() do
  System.get_env("RSOLV_TESTING_MODE") == "true" or
  FunWithFlags.enabled?(:testing_mode)
end
```

**Pros**:
- Fast to implement (30 minutes)
- Unblocks marketplace testing immediately
- No database changes required
- Isolated to testing scenarios

**Cons**:
- Weakens authorization for RSOLV-dev namespace
- Security concern if deployed to production with testing mode on
- Doesn't solve the underlying issue for real customers

**Risk**: LOW (if properly gated with testing mode check)

---

### Option B: Create ForgeAccount for Test API Keys (Proper Fix)

**Approach**: Seed ForgeAccounts for test customers during setup

**Code Change** in `priv/repo/seeds.exs`:

```elixir
# After creating test customer and API key...

# Create verified ForgeAccount for RSOLV-dev organization
{:ok, _forge_account} =
  %Rsolv.Customers.ForgeAccount{}
  |> Rsolv.Customers.ForgeAccount.changeset(%{
    customer_id: test_customer.id,
    forge_type: :github,
    namespace: "RSOLV-dev",
    username: "rsolv-test",  # May need to be valid GitHub username
    verified_at: DateTime.utc_now(),
    inserted_at: DateTime.utc_now(),
    updated_at: DateTime.utc_now()
  })
  |> Rsolv.Repo.insert()

IO.puts("✅ Created ForgeAccount for RSOLV-dev organization")
```

**Additional Changes**:
- Run seeds again on staging/production: `mix run priv/repo/seeds.exs`
- Or create migration to add ForgeAccounts for existing test customers
- Document ForgeAccount requirement in API setup docs

**Pros**:
- Proper solution matching production usage
- Tests authorization flow correctly
- No security compromises
- Matches real customer experience

**Cons**:
- Requires database changes
- Must reseed staging/production databases
- More complex than Option A

**Risk**: VERY LOW (standard seeding approach)

---

### Option C: Make ForgeAccount Optional for Retrieval (Design Change)

**Approach**: Only require ForgeAccount for STORAGE, not RETRIEVAL

**Rationale**:
- Customer already proved ownership when STORING phase data
- Retrieving own stored data shouldn't require re-verification
- Less restrictive authorization model

**Code Change** in `lib/rsolv/phases.ex`:

```elixir
def retrieve(repo_string, issue_number, commit_sha, %ApiKey{} = api_key) do
  with {:ok, customer} <- get_customer_from_api_key(api_key),
       {:ok, repo_attrs} <- parse_repo_string(repo_string),
       # REMOVED: verify_namespace_ownership check
       {:ok, repository} <- get_repository(repo_attrs) do

    # Additional check: Verify customer has previously stored data for this repo
    # This ensures they can only retrieve data they previously stored
    case verify_customer_stored_data(customer, repository) do
      {:ok, _} ->
        # ... retrieve phase data ...

      {:error, :no_stored_data} ->
        {:error, :unauthorized}
    end
  end
end

defp verify_customer_stored_data(customer, nil), do: {:error, :no_stored_data}

defp verify_customer_stored_data(customer, repository) do
  import Ecto.Query

  # Check if customer has stored any phase data for this repository
  has_data =
    Repo.exists?(
      from s in ScanExecution,
      join: ak in ApiKey, on: s.api_key_id == ak.id,
      where: s.repository_id == ^repository.id and ak.customer_id == ^customer.id
    ) or
    Repo.exists?(
      from v in ValidationExecution,
      join: ak in ApiKey, on: v.api_key_id == ak.id,
      where: v.repository_id == ^repository.id and ak.customer_id == ^customer.id
    )

  if has_data do
    {:ok, :authorized}
  else
    {:error, :no_stored_data}
  end
end
```

**Pros**:
- More flexible authorization model
- Allows retrieval if customer stored data
- Unblocks testing without special cases
- Makes sense from UX perspective

**Cons**:
- Design decision (may have been intentional)
- Less restrictive than current model
- Would need product/security review

**Risk**: MEDIUM (requires design approval)

## Recommendation

**Immediate (Today)**: Implement **Option B** (Create ForgeAccount in seeds)

**Reasoning**:
1. **Proper fix**: Matches production usage pattern
2. **Low risk**: Standard seeding approach
3. **Fast**: 30-60 minutes to implement and test
4. **No security concerns**: Proper authorization flow
5. **No code changes**: Only data seeding

**Timeline**:
1. Update `priv/repo/seeds.exs` (15 min)
2. Test locally (15 min)
3. Deploy to staging (15 min)
4. Verify with test workflow runs (30 min)
5. Total: **1-1.5 hours to unblock marketplace testing**

**Future (Post-Launch)**: Consider **Option C** after product review

## Implementation Steps

### Step 1: Update Seeds File

Edit `priv/repo/seeds.exs` to add ForgeAccount creation:

```elixir
# Find the section that creates test customer
test_customer = Repo.get_by!(Customer, email: "test@example.com")

# Add ForgeAccount for RSOLV-dev organization
case Repo.get_by(ForgeAccount,
  customer_id: test_customer.id,
  namespace: "RSOLV-dev"
) do
  nil ->
    {:ok, forge_account} =
      %ForgeAccount{}
      |> ForgeAccount.changeset(%{
        customer_id: test_customer.id,
        forge_type: :github,
        namespace: "RSOLV-dev",
        username: "rsolv-test",
        verified_at: DateTime.utc_now()
      })
      |> Repo.insert()

    IO.puts("✅ Created ForgeAccount for RSOLV-dev")

  existing ->
    IO.puts("✅ ForgeAccount for RSOLV-dev already exists")
end
```

### Step 2: Run Seeds Locally

```bash
cd ~/dev/rsolv
mix run priv/repo/seeds.exs
```

Expected output:
```
✅ Created ForgeAccount for RSOLV-dev
```

### Step 3: Verify in Database

```bash
psql -d rsolv_dev -c "
SELECT
  c.email,
  fa.forge_type,
  fa.namespace,
  fa.verified_at IS NOT NULL as verified
FROM forge_accounts fa
JOIN customers c ON fa.customer_id = c.id
WHERE fa.namespace = 'RSOLV-dev';
"
```

Expected:
```
      email       | forge_type | namespace  | verified
------------------+------------+------------+----------
 test@example.com | github     | RSOLV-dev  | t
```

### Step 4: Deploy to Staging

```bash
# Deploy updated seeds to staging
cd ~/dev/rsolv-infrastructure
kubectl exec -it deployment/rsolv-platform -n staging -- \
  mix run priv/repo/seeds.exs
```

### Step 5: Test Workflow

Trigger three-phase workflow on NodeGoat:

```bash
gh workflow run rsolv-three-phase-demo.yml \
  --repo RSOLV-dev/nodegoat-vulnerability-demo \
  --ref main \
  --field debug=true
```

**Expected**: MITIGATE phase succeeds, no more "Platform retrieval failed: Forbidden" errors

### Step 6: Monitor Logs

```bash
# Watch workflow execution
gh run watch --repo RSOLV-dev/nodegoat-vulnerability-demo

# Check for success indicators:
# - "Phase data retrieved successfully"
# - "Applying fixes..."
# - "Created PR #..."
```

## Verification Checklist

After implementing the fix:

- [ ] Seeds file updated with ForgeAccount creation
- [ ] Seeds run successfully locally
- [ ] ForgeAccount visible in database
- [ ] Seeds deployed to staging
- [ ] NodeGoat three-phase workflow succeeds
- [ ] MITIGATE phase retrieves phase data without errors
- [ ] Pull request created with fixes
- [ ] RailsGoat three-phase workflow succeeds
- [ ] No "Forbidden" errors in logs

## Testing Commands

```bash
# Test API directly (after fix)
curl -H "Authorization: Bearer $TEST_API_KEY" \
  "https://api-staging.rsolv.dev/api/v1/phases/retrieve?repo=RSOLV-dev/nodegoat-vulnerability-demo&issue=1079&commit=$COMMIT_SHA"

# Should return phase data, not 403 Forbidden

# Run full three-phase test
gh workflow run rsolv-three-phase-demo.yml \
  --repo RSOLV-dev/nodegoat-vulnerability-demo \
  --ref main

# Monitor results
gh run watch --repo RSOLV-dev/nodegoat-vulnerability-demo
```

## Related Issues

- **Validation API 422 Errors** (bebd855e-750c-49e7-816a-e39d48bc61ee)
  - Separate issue, also CRITICAL
  - Both must be fixed for marketplace
  - Can be fixed in parallel

## References

- **MITIGATE Ticket**: d1830202-51ad-4776-ad60-33713d70c588
- **Platform Router**: `lib/rsolv_web/router.ex:260`
- **Phase Controller**: `lib/rsolv_web/controllers/api/v1/phase_controller.ex:275`
- **Phases Context**: `lib/rsolv/phases.ex:235`
- **Authorization Logic**: `lib/rsolv/phases.ex:101-120`
- **Reevaluation Doc**: `projects/go-to-market-2025-10/RFC-067-REEVALUATION-COMPLETE.md`

## Timeline

**Estimated Fix Time**: 1-1.5 hours
**Blocking**: RFC-067 marketplace submission
**Priority**: CRITICAL
**Can Parallelize With**: Validation API 422 fix

**Today (2025-11-05)**:
- Update seeds file
- Test locally
- Deploy to staging
- Verify workflow success

**Tomorrow (2025-11-06)**:
- Rerun full marketplace testing
- Capture screenshots
- Document results

## Conclusion

**Root cause confirmed**: Missing ForgeAccount for RSOLV-dev organization blocks phase data retrieval due to authorization check at `lib/rsolv/phases.ex:238`.

**Fix is straightforward**: Add ForgeAccount creation to seeds, redeploy, test.

**Impact**: Unblocks MITIGATE phase completely, enables full three-phase workflow testing, unblocks marketplace submission.

**Status**: Ready to implement Option B (recommended solution).
