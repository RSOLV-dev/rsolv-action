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

## Development Best Practices

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

9. **Current Test Status** (as of 2025-10-07):
   - RSOLV-action: ✅ **100% GREEN** (19/19 test files, 115 passed, 2 skipped)
   - RSOLV-platform: ✅ **100% GREEN** (4097/4097 passed, 529 doctests, 83 excluded, 61 skipped)

10. **How to Run Tests**:

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

11. **Integration Test Setup**:
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

**Documentation Structure:**
```elixir
@operation :endpoint_name
@parameters [
  api_key: [in: :header, required: true, description: "API key"],
  # ... other parameters
]
@responses [
  200: {"Success", "application/json", ResponseSchema},
  401: {"Unauthorized", "application/json", ErrorSchema}
]
def endpoint_name(conn, params) do
  # implementation
end
```

**Required for Each Endpoint:**
- Summary and description
- Complete request/response schemas
- All error responses documented
- Example values for complex types
- Security requirements (authentication, rate limits)

**Maintenance:**
- Breaking changes require API version bump
- Test mode endpoints must clearly indicate test-only status
- Keep schemas DRY by using shared components
- Document rate limits and quotas in operation descriptions

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