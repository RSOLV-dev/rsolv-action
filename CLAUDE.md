# RSOLV Project Guidelines

## Architecture Documentation

### RFC/ADR Process

This project uses RFCs and ADRs for architectural decisions:

1. **RFCs (Request for Comments)** - Proposals for new features or changes
   - Location: `/RFCs/`
   - Index: [RFCs/RFC-INDEX.md](RFCs/RFC-INDEX.md) - 53+ RFCs tracked
   - Template: See RFC-INDEX.md for standard template
   - Process: Draft → Review → Approved → Implemented → ADR

2. **ADRs (Architecture Decision Records)** - Implemented decisions
   - Location: `/ADRs/`
   - Index: [ADRs/ADR-INDEX.md](ADRs/ADR-INDEX.md) - 24+ ADRs documented
   - Created when RFCs are implemented in production
   - Document what was built, why, and consequences

3. **Active Projects** - Working documents for in-flight work
   - Location: `/projects/`
   - See [projects/README.md](projects/README.md) for active projects
   - Each project gets its own subdirectory with tracking documents
   - Upon completion, archive to `archived_docs/` and transfer knowledge to ADRs
   - Example: `projects/billing-integration-2025-10/` contains integration checklists for RFCs 065-068

### Creating New RFCs

When proposing significant changes:
1. Create `RFCs/RFC-XXX-YOUR-TITLE.md` (next number: 054)
2. Follow the RFC template in RFC-INDEX.md
3. Update RFC-INDEX.md with your new RFC
4. Include Linear issue link if applicable

### Creating New ADRs

When documenting implemented decisions:
1. Create `ADRs/ADR-XXX-YOUR-TITLE.md` (next number: 025)
2. Reference the implementing RFC if applicable
3. Update ADR-INDEX.md with your new ADR
4. Include: Status, Context, Decision, Consequences, Impact

## Development Environment Setup

### Quick Start for Agentic LLMs

When setting up this project from scratch, follow this workflow:

```bash
# 1. Verify you're in the project root (should contain mix.exs)
pwd
ls -la mix.exs .env.example

# 2. Run the all-in-one setup command
mix setup

# 3. If prompted about missing .env, accept the wizard (y) or decline (n)
#    - Accepting runs interactive wizard (may not work for non-interactive agents)
#    - Declining continues with defaults (DATABASE_URL from config/dev.exs)

# 4. Start the server (if needed for testing)
mix phx.server
```

**📚 Complete setup documentation:** [docs/DEV_SETUP.md](docs/DEV_SETUP.md) - troubleshooting, architecture, manual steps

### What `mix setup` Does

The setup command orchestrates everything needed for development:

1. **Environment Check** - Checks for `.env` file, offers wizard if missing
2. **Pre-flight Validation** - Elixir ≥1.18, PostgreSQL running, port 4000 available
3. **Dependencies** - `mix deps.get` (73 packages)
4. **Assets** - `mix assets.setup && mix assets.build` (Tailwind, esbuild)
5. **Database** - `mix ecto.create && mix ecto.migrate && mix run priv/repo/seeds.exs`
6. **OpenAPI** - `mix rsolv.openapi` (generates API spec)
7. **Verification** - Tests database connection, tables, seeds, assets
8. **Summary** - Displays test credentials and next steps

**Flow:** `mix setup` → `Mix.Tasks.Setup` → `dev.setup` → `dev.preflight` → install tasks → `dev.verify` → `dev.summary`

### Environment Configuration for Agentic LLMs

**Critical Context:**
- `.env` file is NOT committed to git (in `.gitignore`)
- `.env.example` is the template showing all available configuration
- `.envrc` exists for `direnv` users (test/demo keys) but is NOT used for runtime config
- Runtime loads environment from `.env` via `config/runtime.exs`

**If `.env` is missing:**
- `mix setup` detects this in pre-flight and prompts: "Would you like to run the wizard now? [Y/n]"
- **For interactive use:** Accept to run `mix dev.env.setup` wizard
- **For automated/non-interactive:** Decline and setup continues with defaults from `config/dev.exs`
- **Manual alternative:** Create `.env` from `.env.example` before running setup

**Minimal .env for local development (if creating manually):**
```bash
DATABASE_URL=postgresql://postgres:postgres@localhost/rsolv_dev
DATABASE_SSL=false
SECRET_KEY_BASE=<run: mix phx.gen.secret>
```

**Environment Variables Reference:**
- **Required:** `DATABASE_URL`, `SECRET_KEY_BASE`
- **Optional:** `ANTHROPIC_API_KEY`, `OPENAI_API_KEY`, `POSTMARK_API_KEY`
- **Full list:** See `.env.example` with inline documentation
- **Sync rule:** When modifying `config/runtime.exs`, update `.env.example` to match

### Available Setup Commands

```bash
mix setup              # Full enhanced setup (recommended)
mix setup.basic        # Skip pre-flight/verification (faster, less safe)
mix dev.env.setup      # Interactive .env wizard only
mix dev.preflight      # System checks only
mix dev.verify         # Post-setup verification only
mix dev.summary        # Display test credentials
```

### Test Credentials (Available After Setup)

Seeds (`priv/repo/seeds.exs`) create these test accounts:

**Users:**
- Admin: `admin@rsolv.dev` / `AdminP@ssw0rd2025!`
- Staff: `staff@rsolv.dev` / `StaffP@ssw0rd2025!`
- Test: `test@example.com` / `TestP@ssw0rd2025!`
- Demo: `demo@example.com` / `DemoP@ssw0rd2025!`
- Enterprise: `enterprise@bigcorp.com` / `EnterpriseP@ssw0rd2025!`

**API Keys:**
- `rsolv_test_key_123` (test user)
- `rsolv_demo_key_456` (demo user)
- Admin/staff keys are randomly generated during seeding

### Troubleshooting Common Setup Issues

**PostgreSQL not running:**
```bash
# macOS
brew services start postgresql@16

# Linux
sudo systemctl start postgresql

# Docker
docker-compose up -d postgres
```

**Port 4000 in use:**
```bash
lsof -ti:4000           # Find process
kill $(lsof -ti:4000)   # Kill it
```

**Compilation errors:** Dependencies not installed
```bash
mix deps.get
mix compile
```

See [docs/DEV_SETUP.md](docs/DEV_SETUP.md) for comprehensive troubleshooting.

## Development Best Practices

### Git Worktree Workflow

**IMPORTANT**: This project frequently uses git worktrees, especially when working with Vibe Kanban task management.

**Critical Setup Step for Worktrees:**
```bash
# ALWAYS run this when entering a new worktree
mix setup  # or at minimum: mix deps.get
```

**Why This Matters:**
- Worktrees share the git repository but have independent working directories
- Dependencies in `_build/` and `deps/` are **NOT shared** between worktrees
- Tests will fail with confusing "dependencies not available" errors if you skip this step
- Vibe Kanban creates worktrees automatically for task isolation

### Migration Safety

**IMPORTANT**: Run migration safety checks before committing migrations to catch dangerous operations early.

We use the `excellent_migrations` package to detect potentially unsafe migration operations that could cause production issues. It's integrated with Credo for automatic checks during development.

#### Running Migration Checks

```bash
# Recommended: Run Credo (includes migration safety checks)
mix credo

# Check only migration files
mix credo priv/repo/migrations/*.exs

# Or run migration checks directly
mix excellent_migrations.check_safety
```

**Credo Integration:** Migration safety checks run automatically as part of `mix credo`. When running on migration files, you'll see warnings like:
- `[W] ↗ Index not concurrently`
- `[W] ↗ Column reference added`
- `[W] ↗ Raw sql executed`
- `[W] ↗ Column type changed`

**What It Detects:**
- ✅ Adding columns with defaults (causes table locks on large tables)
- ✅ Removing columns (reading from removed columns causes errors)
- ✅ Adding foreign keys without validation (blocks writes)
- ✅ Adding check constraints (blocks writes during validation)
- ✅ Setting NOT NULL on existing columns (requires full table scan)
- ✅ Changing column types (rewrites entire table)
- ✅ Adding indexes non-concurrently (locks table during creation)
- ✅ Missing reversible down/0 functions

**Best Practices:**
1. Run `mix credo` before committing (includes migration checks)
2. For large tables, use `algorithm: :concurrently` when adding indexes
3. Add columns without defaults, then backfill and add constraint separately
4. Use `validate: false` when adding foreign keys, then validate separately
5. Ensure all migrations have proper `down/0` functions for rollback

**Resources:**
- [excellent_migrations on Hex](https://hex.pm/packages/excellent_migrations)
- [excellent_migrations on GitHub](https://github.com/Artur-Sulej/excellent_migrations)

### TypeScript Validation
**IMPORTANT**: Always run `npx tsc --noEmit` after making changes to TypeScript files. This practice:
- Catches method signature mismatches (e.g., `detectInFile()` vs `detect()`)
- Identifies missing properties on interfaces
- Finds type incompatibilities before runtime
- Saves significant debugging time

Example workflow:
1. Make changes to `.ts` files
2. Run `npx tsc --noEmit` to check for type errors
3. Fix any type errors before running/testing the code
4. Only commit after TypeScript validation passes

Common issues caught by TypeScript:
- Interface changes not propagated to all implementations
- Incorrect method names or signatures
- Missing or incorrect property types
- Import/export mismatches

### Test-Driven Development (TDD)
- Use red-green-refactor-review methodology
- Write failing tests before implementation
- Implement code to make tests pass iteratively
- Refactor, changing only one of the implementation or tests at a time
- Optimize for readability and idiomaticity

### Test Suite Status
For complete test suite information, see:
- **RSOLV-action**: [RSOLV-action/TEST-SUITE-STATUS.md](RSOLV-action/TEST-SUITE-STATUS.md)
  - Current status, how to run tests, environment configuration
  - API keys, test database setup, troubleshooting
  - Test categorization and skip reasons

### Test Suite Maintenance
**Key Lessons for Running Green Test Suites:**

1. **Jest vs Vitest**: RSOLV-action uses Vitest, not Jest
   - When converting tests: `@jest/globals` → `vitest`
   - Mock functions: `jest.fn()` → `vi.fn()`, `jest.mock()` → `vi.mock()`
   - Clear mocks: `jest.clearAllMocks()` → `vi.clearAllMocks()`
   - Module-level `vi.mock()` calls must come before imports they mock

2. **Async/Await Discipline**:
   - Methods returning `Promise<T>` MUST be awaited in tests
   - Add `async` to test functions when calling async methods
   - Missing `await` causes confusing assertion failures

3. **Mock Configuration Completeness**:
   - Mocks must include ALL properties accessed by code under test
   - Check for nested property access (e.g., `this.config.aiProvider.apiKey`)
   - Use proper TypeScript types or `as ActionConfig` to ensure completeness

4. **Test Isolation in Elixir**:
   - `async: false` means tests share state (cache, database, etc.)
   - Don't assert exact values that depend on test execution order
   - Instead, record initial state and verify relative changes

5. **String Assertions**:
   - Check for markdown formatting: `**bold**` vs `bold`
   - Use `expect.stringContaining()` for flexible matching
   - Verify actual output format before writing assertions

6. **API Signature Changes**:
   - When refactoring APIs, grep for all usages across test files
   - Common pattern: method renamed or parameters changed
   - Example: `detectInFile(code, file)` → `detect(code, language, file)`

7. **Test Philosophy and RFC Intent**:
   - Cross-reference test expectations with RFC documentation
   - RFC-059 example: `RSOLV_TESTING_MODE=true` means "don't filter" not "still validate strictly"
   - Test behavior should match documented intent, not assumptions

8. **Memory Issues and Parallel Execution**:
   - Use `npm run test:memory` for memory-safe test runs
   - Tests run in 2 batches of 4 parallel shards (semi-parallel)
   - This balances speed with manageable load on external services
   - Individual test file runs: `npx vitest run path/to/test.ts`

9. **AI Provider API Constraints** (as of 2025-10-08):
   - **Critical**: Anthropic API does NOT allow both `temperature` AND `top_p` parameters
   - Error: `"temperature and top_p cannot both be specified for this model"`
   - **Solution**: Use only `temperature` (preferred) for consistency across all providers
   - **Fixed**: `src/ai/client.ts` lines 120, 253 - removed `top_p` parameter
   - **Test Coverage**: `src/ai/__tests__/client-api-parameters.test.ts` (5 tests) prevents regression
   - **OpenAI**: While OpenAI allows both, we use only `temperature` for consistency
   - **Default**: `temperature: 0.2` unless explicitly overridden

10. **Current Test Status** (as of 2025-10-08):
   - RSOLV-action: ✅ **100% GREEN** (20/20 test files, 120 passed, 2 skipped)
   - RSOLV-platform: ✅ **100% GREEN** (4097/4097 passed, 529 doctests, 83 excluded, 61 skipped)

11. **How to Run Tests**:

   **RSOLV-action** (in `/home/dylan/dev/rsolv/RSOLV-action/RSOLV-action`):
   ```bash
   npm run test:memory  # REQUIRED - memory-safe with semi-parallel sharding
   ```
   - **DO NOT** use `npm test` - causes OOM errors
   - Uses 8 shards in 2 batches (4 parallel at a time) with 4GB heap limit
   - Fast execution: ~3-4s per shard, ~30s total vs 60s for full suite
   - Semi-parallel approach prevents overwhelming external APIs
   - Test artifacts auto-generated in `.rsolv/` and `temp/` (gitignored)

   **RSOLV-platform** (in `/home/dylan/dev/rsolv`):
   ```bash
   cd ~/dev/rsolv && mix test
   ```
   - Platform code lives in rsolv root directory (no separate RSOLV-platform dir)
   - Uses PostgreSQL test database with FunWithFlags feature flags
   - Duration: ~64 seconds
   - Many tests use async/DataCase for database isolation

12. **Integration Test Setup**:
   - Integration tests excluded from default run via `vitest.config.ts`
   - Run with: `RUN_INTEGRATION=true npm test`
   - Require: Live RSOLV platform API, credentials, Git repos
   - See RFC-062 for CI setup details
   - Fresh production API key created: `rsolv_GD5KyzSXvKzaztds23HijV5HFnD7ZZs8cbF1UX5ks_8`

### Elixir Testing
- We have several Elixir apps in this project 
- Elixir and ExUnit support doctests, and I heartily encourage their use whenever practical
- When testing blog-related functionality, avoid hardcoding specific post content that may change
- Use `DataCase` instead of `ExUnit.Case` for tests that need database access (e.g., FunWithFlags)
- Remove custom HTTP mocking implementations in favor of existing Mox setup

## Tools and Infrastructure

### Static Analysis and Development Tools
- We have the tool `zizmor` for static analysis of GitHub Actions
- We have the tool `actionint` as a static checker of github actions workflow files
- Use `npx tsc --noEmit` for TypeScript type checking before running code

### Local Testing with Act (GitHub Actions Simulator)

We use `act` to test GitHub Actions locally without consuming API tokens. This utilizes your local Claude Code Max account.

#### Setup (one-time)
```bash
# Install act
curl https://raw.githubusercontent.com/nektos/act/master/install.sh | sudo bash

# Download full environment (47.2GB - provides complete GitHub Actions compatibility)
docker pull catthehacker/ubuntu:full-latest

# Configure act to use full environment
mkdir -p ~/.config/act
echo "-P ubuntu-latest=catthehacker/ubuntu:full-latest" > ~/.config/act/actrc
```

#### Running RSOLV Workflows Locally

1. **Prepare test environment:**
```bash
# Clone target repository
cd /tmp
git clone https://github.com/RSOLV-dev/nodegoat-vulnerability-demo.git
cd nodegoat-vulnerability-demo

# Get GitHub PAT for issue/PR operations
export GITHUB_TOKEN=$(gh auth token)

# Export Claude Code environment variables
export CLAUDE_CODE_API_KEY=$(cat ~/.claude/claude_code_api_key 2>/dev/null || echo "")
export ANTHROPIC_API_KEY=$(cat ~/.claude/anthropic_api_key 2>/dev/null || echo "")

# Create secrets file
cat > .secrets << EOF
GITHUB_TOKEN=$GITHUB_TOKEN
RSOLV_API_KEY=your-rsolv-api-key
ANTHROPIC_API_KEY=$ANTHROPIC_API_KEY
CLAUDE_CODE_API_KEY=$CLAUDE_CODE_API_KEY
EOF
```

2. **Run full three-phase test with act (uses Claude Code Max, no API tokens):**
```bash
act workflow_dispatch \
  -W .github/workflows/rsolv-test.yml \
  --secret-file .secrets \
  --bind \
  --pull=false \
  --container-options="-v $HOME/.claude:/root/.claude:ro" \
  --env CLAUDE_CODE_API_KEY=$CLAUDE_CODE_API_KEY \
  --env ANTHROPIC_API_KEY=$ANTHROPIC_API_KEY \
  2>&1 | tee act-test.log
```

#### What to Expect
1. **SCAN Phase**: Finds vulnerabilities, creates GitHub issues
2. **VALIDATE Phase**: Generates RED/GREEN/REFACTOR tests, commits to branch
3. **MITIGATE Phase**: Applies fixes, creates PR with changes

#### Troubleshooting
- **Git repository errors**: Fixed in RSOLV-action v3.7.46+ (uses GITHUB_SHA env var)
- **Slow setup-node**: Normal, can take 30+ minutes. Use `--pull=false` after first run
- **API auth failures**: Check .secrets file format and API key validity

#### Key Points
- **No API tokens consumed** - Uses local Claude Code Max account
- **Docker fixes included** - v3.7.46+ handles act's Docker-in-Docker environment
- **Test mode support** - Works with known vulnerable repos using `test-mode: 'true'`
- **Complete workflow** - All three phases (SCAN/VALIDATE/MITIGATE) work locally
- **See RFC-059** for complete documentation and advanced usage

## Architecture and Code Exploration

### Understanding System Capabilities
When exploring a new system or determining what capabilities exist:

1. **Start with the Router/API Surface**
   - Check `router.ex` or equivalent to understand all available endpoints
   - This reveals the system's actual capabilities vs assumptions
   
2. **Examine the Supervision Tree**
   - Check `application.ex` to see what services/workers are started
   - Presence of services like `AST.AnalysisService` indicates major subsystems
   
3. **Follow the Data Flow**
   - Trace: API Endpoint → Controller → Service → Processing → Response
   - Understand what data comes in, how it's processed, and what goes out
   
4. **Search Strategically**
   - Use domain-specific terms (e.g., `analyze|validation|ast|parser` for analysis systems)
   - Look for security terms: `encrypt|decrypt|sandbox|audit`
   - Don't just search for what you expect to find
   
5. **Read Documentation First**
   - Check RFCs/ADRs for architectural decisions
   - Module `@moduledoc` blocks often explain the purpose clearly
   
6. **Think in Capabilities, Not Binaries**
   - Instead of "does it do X or not?", ask "what does it actually do?"
   - Understand the security model and data handling before making conclusions

### RSOLV Platform Architecture
**Key Understanding**: The platform provides sophisticated vulnerability detection and AST analysis, but NOT fix generation.

**Platform Capabilities**:
- **AST Analysis**: Sandboxed parsing and pattern matching with multiple language support
- **Security**: Client-side encryption (AES-256-GCM), sandboxed execution, no code storage
- **Vulnerability Detection**: Pattern-based detection with AST validation to reduce false positives
- **Credential Vending**: Temporary AI provider credentials for GitHub Actions
- **Tracking**: Fix attempt tracking, billing, webhook handling

**Security Model**:
- Customer code is encrypted client-side
- Decrypted only in memory for analysis
- Sandboxed parser processes with resource limits
- No permanent storage of source code
- Only vulnerability metadata is returned

**Fix Generation**: Happens in GitHub Action (RSOLV-action) using Claude Code SDK, not in platform backend

### Infrastructure and Deployment
- Our infrastructure and deployment info is in rsolv-infrastructure; especially note rsolv-infrastructure/DEPLOYMENT.md
- **ALWAYS test deployments on staging first** before deploying to production
- When updating Elixir runtime.exs, remember that it's not a module - use anonymous functions instead of `defp`
- Before deploying, verify all required secrets have values (not empty strings):
  - DATABASE_URL must be a valid postgres:// connection string
  - SECRET_KEY_BASE must be exactly 64 hex characters (use `openssl rand -hex 32`)
  - kit-form-id and kit-ea-tag-id must be valid integers, not empty strings
- Check Kubernetes service selectors match pod labels exactly (case-sensitive):
  - Use `kubectl get endpoints <service-name>` to verify endpoints exist
  - Common issue: `managed-by: RSOLV-infrastructure` vs `managed-by: rsolv-infrastructure`

#### Feature Flag Deployment Strategy

We use FunWithFlags for feature flags, enabling safe deployment of code to production before features go live.

**Standard Deployment Pattern (RFC-078 Example):**

1. **Create Feature Flag Migration**:
   ```elixir
   defmodule Rsolv.Repo.Migrations.AddFeatureFlag do
     use Ecto.Migration

     def up do
       execute """
       INSERT INTO fun_with_flags_toggles (flag_name, gate_type, target, enabled) VALUES
       ('feature_name', 'boolean', NULL, false)
       ON CONFLICT (flag_name, gate_type, target)
       DO UPDATE SET enabled = false;
       """
     end

     def down do
       execute """
       DELETE FROM fun_with_flags_toggles WHERE flag_name = 'feature_name';
       """
     end
   end
   ```

2. **Wrap New Code in Feature Check**:
   ```elixir
   # In controllers/LiveViews
   def mount(_params, _session, socket) do
     if FunWithFlags.enabled?(:feature_name) do
       # New feature code
     else
       # Fallback or redirect
     end
   end

   # In router
   scope "/" do
     if FunWithFlags.enabled?(:feature_name) do
       live "/new-page", NewPageLive
     end
   end
   ```

3. **Deploy to Production (Flag OFF)**:
   - Code is deployed but inactive
   - No risk to existing functionality
   - Full production environment available for testing

4. **Test on Staging (Flag ON)**:
   ```sql
   -- Enable in staging database
   UPDATE fun_with_flags_toggles
   SET enabled = true
   WHERE flag_name = 'feature_name';
   ```

5. **Go-Live (Enable in Production)**:
   ```sql
   -- After staging validation, enable in production
   UPDATE fun_with_flags_toggles
   SET enabled = true
   WHERE flag_name = 'feature_name';
   ```

6. **Instant Rollback (Disable Flag)**:
   ```sql
   -- No code deployment needed - just disable the flag
   UPDATE fun_with_flags_toggles
   SET enabled = false
   WHERE flag_name = 'feature_name';
   ```

**Benefits:**
- Zero-downtime deployments throughout development
- Test in production environment (with flag enabled only in staging)
- Instant rollback without code deployment
- No regression risk to existing features
- Gradual rollout capability (can enable for specific users)

**Best Practices:**
- Always deploy with flags OFF by default
- Test thoroughly on staging with flag ON before production enablement
- Document flag enablement/rollback procedures in deployment plan
- Remove feature flags after feature is stable (typically 1-2 weeks post-launch)
- Use `FunWithFlags.enabled?/1` for boolean flags, `FunWithFlags.enabled?/2` for user-specific flags

### Stripe Payment Integration & PCI Compliance

**CRITICAL**: Never send raw credit card numbers to Stripe API. Always use Stripe Elements for payment collection.

#### PCI-Compliant Payment Flow

Our billing system is designed to be PCI Level 1 compliant by never touching raw card data:

1. **Frontend (Browser) - Stripe Elements**:
   ```javascript
   // Load Stripe.js from Stripe's CDN (never self-host)
   const stripe = Stripe('pk_test_xxx'); // Use publishable key
   const elements = stripe.elements();

   // Create card element (hosted by Stripe in secure iframe)
   const cardElement = elements.create('card');
   cardElement.mount('#card-element');

   // On form submit:
   const {paymentMethod, error} = await stripe.createPaymentMethod({
     type: 'card',
     card: cardElement,
   });

   if (error) {
     // Handle error
   } else {
     // Send ONLY the token to your server
     const response = await fetch('/api/v1/payment-methods', {
       method: 'POST',
       headers: {'Authorization': 'Bearer ' + apiKey},
       body: JSON.stringify({
         payment_method_id: paymentMethod.id,  // e.g., pm_card_visa
         billing_consent: true
       })
     });
   }
   ```

2. **Backend (Phoenix/Elixir)**:
   ```elixir
   # Controller receives ONLY the tokenized payment method ID
   def add_payment_method(conn, %{"payment_method_id" => pm_id, "billing_consent" => consent}) do
     customer = conn.assigns.current_customer

     case Billing.CustomerSetup.add_payment_method(customer, pm_id, consent) do
       {:ok, updated_customer} ->
         json(conn, %{success: true, customer: updated_customer})
       {:error, reason} ->
         # Handle error
     end
   end
   ```

3. **Billing Service**:
   - Calls `StripeService.attach_payment_method(stripe_customer_id, pm_id)`
   - Stripe SDK handles secure attachment
   - No raw card data ever touches our servers

#### Testing Stripe Integration

**DO NOT** use raw card numbers when testing. Use Stripe's test tokens:

**Test Payment Method IDs (already tokenized):**
- `pm_card_visa` - Visa test card
- `pm_card_mastercard` - Mastercard test card
- `pm_card_amex` - American Express test card
- `pm_card_discover` - Discover test card
- `pm_card_declined` - Card that will be declined
- `pm_card_insufficient_funds` - Insufficient funds error

**Test Cards (for Stripe Elements/Checkout):**
- `4242 4242 4242 4242` - Visa (succeeds)
- `4000 0000 0000 0002` - Visa (card declined)
- `4000 0000 0000 9995` - Visa (insufficient funds)

Use any future expiry date (e.g., 12/34) and any 3-digit CVC.

**NEVER** manually call Stripe API with raw card numbers like:
```javascript
// ❌ WRONG - PCI violation
stripe.createPaymentMethod({
  type: 'card',
  card: {
    number: '4242424242424242',  // Don't do this!
    exp_month: 12,
    exp_year: 2025,
    cvc: '123'
  }
});

// ✅ CORRECT - Use Stripe Elements
const cardElement = elements.create('card');
stripe.createPaymentMethod({type: 'card', card: cardElement});
```

#### PCI Compliance Checklist

- [ ] Stripe Elements loaded from Stripe CDN (never self-hosted)
- [ ] Card data never passes through your server
- [ ] Only payment method tokens (`pm_xxx`) stored in database
- [ ] SSL/TLS enabled for all connections (DATABASE_SSL=true in production)
- [ ] Stripe webhook signatures verified (STRIPE_WEBHOOK_SECRET configured)
- [ ] API keys stored in environment variables (never committed to git)
- [ ] Test mode (`pk_test_`, `sk_test_`) used in development/staging
- [ ] Production mode (`pk_live_`, `sk_live_`) only in production

#### Current Implementation Status

**Implemented (RFC-065, RFC-066):**
- ✅ Backend `Billing.CustomerSetup.add_payment_method/3` API
- ✅ PCI-compliant architecture (accepts only `payment_method_id`)
- ✅ Stripe webhook handling
- ✅ Credit ledger and billing tracking

**Not Yet Implemented (Future: Customer Portal):**
- ⏳ Frontend payment form with Stripe Elements
- ⏳ Customer dashboard LiveView
- ⏳ Payment method management UI

**Note**: RFC-078 (Public Site) creates signup flow but does NOT include payment collection. Payment will be added later in customer portal (RFC-070/071).

## Blog and Content Guidelines

### Mastodon/Fediverse Attribution
When creating blog posts or articles that will be shared on Mastodon/Fediverse platforms, always include the fediverse creator attribution meta tag:

```html
<meta name="fediverse:creator" content="@rsolv@infosec.exchange">
```

**Usage:**
- **RSOLV Blog Posts**: Automatically included via layout template when `page_type` is "article"
- **External Platforms** (Dev.to, Medium, etc.): Add manually to HTML head or as platform-specific metadata
- **Purpose**: Ensures proper attribution when content is shared across the fediverse

**Our Mastodon Account**: `@rsolv@infosec.exchange`

### Content Cross-Posting Strategy
- **Blog Posts**: Include UTM parameters for tracking (e.g., `?utm_source=mastodon&utm_medium=social&utm_campaign=slopsquatting`)
- **External Articles**: Link back to our blog and mention our IndieHackers journey
- **Mastodon**: Use technical threads to build authority in InfoSec community
- **Always**: Include relevant hashtags (#AISecurity, #DevSecOps, #InfoSec, #Slopsquatting)

## API Documentation Standards

### OpenAPI Specification
We use `open_api_spex` for all REST API documentation. This is the community standard for Phoenix APIs.

**Requirements:**
- OpenAPI specs are **required** for all API endpoints
- Specs must be updated **before** merging API changes
- Located in controller modules using the `@operation` macro
- Run `mix openapi.spec.json` to generate the spec file
- Validate specs in CI pipeline

**Quick Start - Adding OpenAPI Docs to a New Endpoint:**

1. **Create schema module** (if new feature):
```elixir
# lib/rsolv_web/schemas/your_feature.ex
defmodule RsolvWeb.Schemas.YourFeature do
  alias OpenApiSpex.Schema

  defmodule RequestSchema do
    @moduledoc "Description of request"
    require OpenApiSpex

    OpenApiSpex.schema(%{
      title: "RequestSchema",
      type: :object,
      properties: %{
        field_name: %Schema{type: :string, description: "Field description", example: "example value"}
      },
      required: [:field_name],
      example: %{"field_name" => "example value"}
    })
  end

  defmodule ResponseSchema do
    @moduledoc "Description of response"
    require OpenApiSpex

    OpenApiSpex.schema(%{
      title: "ResponseSchema",
      type: :object,
      properties: %{
        result: %Schema{type: :string}
      }
    })
  end
end
```

2. **Update controller**:
```elixir
defmodule YourController do
  use RsolvWeb, :controller
  use OpenApiSpex.ControllerSpecs  # Add this

  alias RsolvWeb.Schemas.YourFeature.{RequestSchema, ResponseSchema}
  alias RsolvWeb.Schemas.Error.{ErrorResponse, RateLimitError}

  plug OpenApiSpex.Plug.CastAndValidate, json_render_error_v2: true  # Add this
  tags ["YourFeature"]  # Add this - used for grouping in Swagger UI

  operation(:your_action,
    summary: "Brief summary of what this does",
    description: """
    Detailed description with markdown support.

    **Key Points:**
    - Important detail 1
    - Important detail 2

    **Rate Limiting:** 100 requests per minute
    """,
    parameters: [
      param_name: [
        in: :query,  # or :path, :header, :cookie
        description: "What this parameter does",
        type: :string,
        required: true,
        example: "example-value"
      ]
    ],
    request_body: {"Request description", "application/json", RequestSchema},
    responses: [
      ok: {"Success message", "application/json", ResponseSchema},
      bad_request: {"Invalid request", "application/json", ErrorResponse},
      unauthorized: {"Invalid API key", "application/json", ErrorResponse},
      too_many_requests: {"Rate limit exceeded", "application/json", RateLimitError}
    ],
    security: [%{"ApiKeyAuth" => []}]  # or [%{}, %{"ApiKeyAuth" => []}] for optional auth
  )

  def your_action(conn, params) do
    # implementation
  end
end
```

3. **Generate and view spec**:
```bash
# Generate OpenAPI JSON spec
mix openapi.spec.json

# Start server and view interactive docs
mix phx.server
# Then visit: http://localhost:4000/api/docs
```

**Required for Each Endpoint:**
- Summary and description (with markdown for complex endpoints)
- Complete request/response schemas with examples
- All error responses documented (400, 401, 403, 404, 429, 500)
- Example values for complex types
- Security requirements (authentication, rate limits)
- Parameter descriptions with types and constraints

**Schema Organization:**
- Schemas live in `lib/rsolv_web/schemas/`
- One file per feature area (e.g., `pattern.ex`, `ast.ex`, `credential.ex`)
- Use nested modules for request/response pairs
- Reuse common schemas (ErrorResponse, RateLimitError) from `error.ex`

**Common Patterns:**
```elixir
# Optional field
field_name: %Schema{type: :string, nullable: true, description: "..."}

# Array of objects
items: %Schema{type: :array, items: SomeSchema, minItems: 1, maxItems: 10}

# Enum values
status: %Schema{type: :string, enum: ["pending", "completed", "failed"]}

# Nested object
metadata: %Schema{
  type: :object,
  properties: %{
    created_at: %Schema{type: :string, format: :"date-time"}
  }
}

# Union/anyOf (not directly supported, use oneOf or additionalProperties)
```

**Maintenance:**
- Breaking changes require API version bump (e.g., /api/v2)
- Test mode endpoints must clearly indicate test-only status in description
- Keep schemas DRY by using shared components
- Document rate limits and quotas in operation descriptions
- Update `OPENAPI_IMPLEMENTATION_SUMMARY.md` when adding new endpoints
- Regenerate spec after changes: `mix openapi.spec.json`

**Validation:**
```bash
# Generate spec (validates structure)
mix openapi.spec.json

# Check compilation (validates references)
mix compile

# View in Swagger UI (validates usability)
mix phx.server
open http://localhost:4000/api/docs
```

**Current Status:** As of 2025-10-14, 13/18+ core API endpoints documented (65% complete).
See `OPENAPI_IMPLEMENTATION_SUMMARY.md` for detailed progress.

## UI and Styling

### Dark Mode Implementation
The site uses a unified dark mode system that works across both LiveView and non-LiveView pages:

1. **CSS Architecture**:
   - Uses Tailwind CSS with semantic color variables
   - Dark mode styles use Tailwind's `dark:` prefix
   - Typography plugin configured for prose content
   - Custom CSS variables for semantic colors (see `assets/css/app.css`)

2. **Theme Toggle**:
   - Single mechanism using data attributes (`data-theme-toggle`)
   - Inline JavaScript in `root.html.heex` for universal compatibility
   - Theme persists in localStorage
   - No LiveView hooks required - works everywhere

3. **Key Files**:
   - `assets/css/app.css` - Main styles with dark mode overrides
   - `lib/rsolv_web/components/theme_toggle.ex` - Toggle component
   - `lib/rsolv_web/components/layouts/root.html.heex` - Theme initialization

4. **Color Scheme**:
   - Light mode: Soft white background (#F5F5F5)
   - Dark mode: Deep slate backgrounds (#020617, #0f172a)
   - Hero sections: Blue gradient that works in both modes
   - High contrast text for accessibility

5. **Development Notes**:
   - If CSS changes don't appear, restart the Docker container
   - Watcher config in `config/dev.exs` must use proper module syntax
   - Test both blog pages and main site when making theme changes
- ALWAYS use actual Ecto migrations when modifying the PostgreSQL database backing RSOLV-platform. Don't just use raw SQL on the psql command line.