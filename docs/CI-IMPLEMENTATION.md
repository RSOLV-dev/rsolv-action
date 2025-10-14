# GitHub Actions CI - Implementation Notes

**Created:** 2025-10-14
**Workflow:** `.github/workflows/elixir-ci.yml`
**Composite Action:** `.github/actions/setup-elixir/action.yml`

## Why This CI Pipeline Exists

Before this implementation, **only** GitHub Action integration tests existed (testing `RSOLV-action`). The Elixir/Phoenix platform itself had **zero CI**, meaning:

- ❌ Broken tests could merge to `main`
- ❌ OpenAPI spec could drift from implementation
- ❌ Non-reversible migrations could break rollbacks
- ❌ Code formatting violations went uncaught
- ❌ Asset compilation failures only discovered in production

This CI pipeline closes those gaps.

## Pipeline Jobs

### 1. Test Suite (`test`)
Runs full Elixir test suite with PostgreSQL. **Why:** Catch regressions before they merge.

### 2. OpenAPI Spec Validation (`openapi-validation`) ⭐ CRITICAL
Generates and validates API documentation. **Why:** API clients depend on accurate specs. Broken spec generation = broken API docs.

**Validation checks:**
- File generated: `priv/static/openapi.json` exists
- Minimum size: ≥100KB (sanity check)
- Valid JSON: `jq` can parse it
- Endpoint count: ≥25 API paths documented

### 3. Code Quality (`code-quality`)
Checks formatting and compilation warnings. **Why:** Enforce code standards consistently.

### 4. Migration Integrity (`migrations`)
Tests migration reversibility (UP → DOWN → UP). **Why:** Broken rollbacks = production incidents.

**Test sequence:**
```bash
mix ecto.migrate              # UP
mix ecto.rollback --all       # DOWN
mix ecto.migrate              # UP again (verify idempotency)
mix run priv/repo/seeds.exs   # Seeds must work
```

### 5. Asset Compilation (`assets`)
Builds Tailwind CSS and esbuild assets. **Why:** Frontend assets must compile before deployment.

### 6. CI Success (`ci-success`)
Summary job that only runs if all jobs pass. **Why:** Single status check for branch protection.

## Design Decisions

### Composite Action for DRY
**Problem:** Elixir setup + caching repeated 5 times
**Solution:** `.github/actions/setup-elixir/action.yml` encapsulates:
- Elixir/OTP setup
- Dependency caching
- `mix deps.get`

**Usage:**
```yaml
- uses: ./.github/actions/setup-elixir
  with:
    cache-key-prefix: test  # or: openapi, quality, migrations, assets
```

**Why not YAML anchors?** GitHub Actions supports YAML anchors and aliases in most contexts, but they cannot be used in some dynamic sections (e.g., matrix values). Composite actions were chosen for broader compatibility.

### PostgreSQL Service Containers
Jobs that need a database use service containers instead of external DBs. **Why:**
- Test isolation (fresh DB per job)
- No external dependencies
- Faster startup than Docker Compose

**Limitation:** Can't use `env` context in `services` section. Must hardcode Postgres config.

### Parallel Execution
All jobs run in parallel. **Why:** Faster feedback (12-17 min vs 32-42 min sequential).

### Separate Caches Per Job
Each job has its own cache key prefix. **Why:**
- Jobs run in parallel (can't share cache writes)
- Different jobs have different build artifacts

## Troubleshooting

### "OpenAPI spec generation failed"
**Cause:** Missing route, schema error, or compilation issue

**Fix:**
```bash
MIX_ENV=dev mix rsolv.openapi priv/static/openapi.json  # See actual error
mix compile --warnings-as-errors  # Check for compilation issues
grep -r "@operation" lib/rsolv_web/controllers/  # Verify specs exist
```

### "Migration rollback failed"
**Cause:** Non-reversible migration (missing `down` function)

**Fix:**
```elixir
# ❌ Bad: Only works one direction
def change do
  execute "CREATE INDEX CONCURRENTLY ..."
end

# ✅ Good: Explicit up/down
def up do
  execute "CREATE INDEX CONCURRENTLY idx_name ..."
end

def down do
  execute "DROP INDEX CONCURRENTLY IF EXISTS idx_name"
end
```

### "Tests pass locally but fail in CI"
**Cause:** Environment differences (database state, async tests, time-dependent tests)

**Fix:**
```bash
# Use exact CI environment
export DATABASE_URL="postgres://postgres:postgres@localhost:5432/rsolv_test"
export MIX_ENV=test
mix ecto.drop && mix ecto.create && mix ecto.migrate
mix test
```

### "Cache issues / stale dependencies"
**Cause:** Cached deps out of sync with `mix.lock`

**Fix:**
- Clear cache in GitHub Actions UI (Actions → Caches)
- Or update cache key in workflow/composite action

## Branch Protection Setup

After first successful CI run, enable branch protection:

**Settings → Branches → Branch protection rules** for `main` and `develop`:

- ✅ Require status checks to pass before merging
  - ✅ `test` - Test Suite
  - ✅ `openapi-validation` - OpenAPI Spec Validation
  - ✅ `code-quality` - Code Quality
  - ✅ `migrations` - Migration Integrity
  - ✅ `assets` - Asset Compilation
  - ✅ `ci-success` - CI Success (overall gate)
- ✅ Require branches to be up to date before merging
- ✅ Require pull request reviews (recommended: 1 approval)

## Performance

**Cold start (no cache):** ~32-42 minutes
**Warm cache:** ~12-17 minutes

**Optimization opportunities:**
- ✅ Parallel jobs (already implemented)
- ✅ Dependency caching (already implemented)
- ✅ Composite actions for DRY (already implemented)
- ⏭️  Test parallelization (split suite across runners)
- ⏭️  Docker layer caching (pre-built images)

## Future Enhancements

Not in scope for initial implementation:

1. **Dialyzer** - Static type checking (requires PLT caching)
2. **Sobelow** - Elixir security scanning
3. **mix audit** - Dependency vulnerability scanning
4. **Coverage tracking** - Codecov integration
5. **Deploy previews** - Ephemeral environments per PR

## Related Docs

- [OpenAPI Implementation Summary](OPENAPI_IMPLEMENTATION_SUMMARY.md)
- [README](../README.md) - CI badge and quick reference
