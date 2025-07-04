# Duplicate Module Report for RSOLV-platform

## Summary

Found several categories of module naming issues that are causing redefinition warnings:

1. **Sync Conflict Files** - 1 duplicate file
2. **Inconsistent Module Naming** - RsolvWeb vs RSOLVWeb 
3. **Old Module Names from Previous Apps** - RsolvLanding modules still present
4. **Test Files with Wrong Module Names** - 5 test support files
5. **Migration Files with Old Names** - 2 migration files

## Detailed Findings

### 1. Sync Conflict Files (1 file)

**Duplicate Found:**
- Module: `Rsolv.Security.Patterns.Php.MissingCsrfTokenTest`
- Files:
  - ✅ Keep: `./test/rsolv/security/patterns/php/missing_csrf_token_test.exs`
  - ❌ Remove: `./test/rsolv/security/patterns/php/missing_csrf_token_test.sync-conflict-20250614-191523-YRND756.exs`

### 2. Inconsistent Module Naming (Multiple files)

**Issue:** Some files use `RsolvWeb` while others use `RSOLVWeb`. The codebase is inconsistent.

**Files using RsolvWeb (old style):**
- `lib/rsolv_web/endpoint.ex` - defines `RsolvWeb.Endpoint`
- `lib/rsolv_web/gettext.ex` - defines `RsolvWeb.Gettext`
- `lib/rsolv_web/live_hooks.ex` - defines `RsolvWeb.LiveHooks`
- `lib/rsolv_web/router.ex` - defines `RsolvWeb.Router`
- `lib/rsolv_web/telemetry.ex` - defines `RsolvWeb.Telemetry`

**Recommendation:** These should likely be `RSOLVWeb` to match the app name `RSOLV`.

### 3. Old Module Names from RsolvLanding (6 files)

These files still reference the old `RsolvLanding` app name:

**Test Support Files:**
- ❌ `test/support/feature_flag_case.ex` - defines `RsolvLanding.FeatureFlagCase`
- ❌ `test/support/feature_flags_helper.ex` - defines `RsolvLandingWeb.FeatureFlagsHelper`
- ❌ `test/support/fun_with_flags_helper.ex` - defines `RsolvLandingWeb.FunWithFlagsHelper`
- ❌ `test/support/fun_with_flags_helpers.ex` - defines `RsolvLanding.FunWithFlagsHelpers`
- ❌ `test/support/mock_plugs.ex` - defines `RsolvLandingWeb.MockPlugs`

**Migration File:**
- ⚠️ `priv/repo/migrations/20250531_create_fun_with_flags_tables.exs` - defines `RsolvLanding.Repo.Migrations.CreateFunWithFlagsTables`

### 4. Module Naming Convention Issues

The codebase uses multiple naming conventions:
- `Rsolv.*` - Used in most of the application code
- `RsolvWeb.*` - Used in some web modules
- `RSOLVWeb.*` - Expected but not found
- `RSOLV.*` - Expected for main app modules but uses `Rsolv.*` instead

### 5. API-Related Module Names

There's a test file with incorrect naming:
- `test/rsolv/security/json_regex_test.exs` - defines `RSOLVApi.Security.JsonRegexTest` (should be `Rsolv.Security.JsonRegexTest`)

## Recommended Actions

### Immediate Fixes (Remove Duplicates):

1. **Delete sync conflict file:**
   ```bash
   rm ./test/rsolv/security/patterns/php/missing_csrf_token_test.sync-conflict-20250614-191523-YRND756.exs
   ```

### Module Renaming Required:

2. **Update test support files** - Change from `RsolvLanding*` to `RSOLV*`:
   - `test/support/feature_flag_case.ex`
   - `test/support/feature_flags_helper.ex`
   - `test/support/fun_with_flags_helper.ex`
   - `test/support/fun_with_flags_helpers.ex`
   - `test/support/mock_plugs.ex`

3. **Fix inconsistent web module naming** - Decide between `RsolvWeb` or `RSOLVWeb` and standardize:
   - Recommend: Use `RSOLVWeb` to match the `RSOLV` app name
   - Update all `RsolvWeb.*` modules to `RSOLVWeb.*`

4. **Fix test file with wrong module name:**
   - `test/rsolv/security/json_regex_test.exs` - Change `RSOLVApi.Security.JsonRegexTest` to `Rsolv.Security.JsonRegexTest`

5. **Migration files** - These are trickier as they're already run:
   - Consider creating new migrations to handle any necessary updates
   - Document that these old module names exist in migrations

## Script to Fix Issues

```bash
#!/bin/bash
# fix_duplicate_modules.sh

# 1. Remove sync conflict file
echo "Removing sync conflict file..."
rm -f ./test/rsolv/security/patterns/php/missing_csrf_token_test.sync-conflict-20250614-191523-YRND756.exs

# 2. Update test support files
echo "Updating test support files..."
sed -i 's/defmodule RsolvLanding\./defmodule RSOLV./g' test/support/*.ex
sed -i 's/defmodule RsolvLandingWeb\./defmodule RSOLVWeb./g' test/support/*.ex

# 3. Fix json_regex_test.exs
echo "Fixing json_regex_test.exs..."
sed -i 's/defmodule RSOLVApi\.Security\./defmodule Rsolv.Security./g' test/rsolv/security/json_regex_test.exs

# 4. Standardize web module naming (if desired)
# echo "Standardizing web module naming to RSOLVWeb..."
# find lib/rsolv_web -name "*.ex" -exec sed -i 's/defmodule RsolvWeb\./defmodule RSOLVWeb./g' {} \;
# find test/rsolv_web -name "*.exs" -exec sed -i 's/defmodule RsolvWeb\./defmodule RSOLVWeb./g' {} \;

echo "Done! Run 'mix compile --warnings-as-errors' to verify all issues are resolved."
```

## Notes

- The migration files with old module names should be left as-is since they've already been run
- The main decision needed is whether to use `RsolvWeb` or `RSOLVWeb` for web modules
- All `RsolvLanding` references should be updated to use the new app name