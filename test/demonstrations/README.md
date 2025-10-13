# Test Integration Scoring Demonstrations

This directory contains executable demonstrations of the test integration scoring algorithm from RFC-060-AMENDMENT-001 Phase 1-Backend.

## Scripts

### 1. `test_scorer_demo.exs`
**Interactive demonstration** with 6 real-world scenarios showing:
- Ruby/Elixir strongly-paired prefixes (`lib/test`, `spec/test`)
- JavaScript/TypeScript directory structures
- Python test organization patterns
- Edge cases and low-scoring mismatches

**Run it:**
```bash
mix run test/demonstrations/test_scorer_demo.exs
```

**Output:** Colored, formatted results with scoring breakdowns and key insights for each scenario.

---

### 2. `scoring_walkthrough.exs`
**Step-by-step algorithm walkthrough** showing:
- Path normalization
- File similarity calculation (Jaccard)
- Directory similarity calculation
- Bonus application (module +0.3, directory +0.2)
- Prefix penalty logic (strongly-paired vs different prefixes)

**Run it:**
```bash
mix run test/demonstrations/scoring_walkthrough.exs
```

**Output:** Detailed breakdown of internal scoring mechanics with verification at each step.

---

### 3. `api_demo.sh`
**HTTP API testing** with curl examples for:
- Valid requests with multiple candidates
- Empty candidate lists
- Missing/invalid parameters
- Unsupported frameworks
- Rate limiting behavior

**Run it:**
```bash
# Start server first
iex -S mix phx.server

# In another terminal
cd test/demonstrations
chmod +x api_demo.sh
./api_demo.sh
```

**Output:** HTTP request/response pairs showing JSON API behavior.

---

## Quick Reference

**Scoring Range:** 0.0 - 1.5
- Base: 0.0 - 1.0 (path similarity using Jaccard)
- Module bonus: +0.3 (same normalized module name)
- Directory bonus: +0.2 (same directory structure)
- Penalty: -0.01 (different prefixes when directories match)

**Strongly-Paired Prefixes:** `lib/test`, `test/lib`, `spec/test`, `test/spec`
- These are idiomatic Ruby/Elixir conventions and get **no penalty**

**Example Scores:**
- `lib/app/services/auth.ex` ↔ `test/app/services/auth_test.exs` = **1.5** (perfect match)
- `src/api/users.js` ↔ `test/api/users.test.js` = **1.49** (0.01 penalty for src/test)
- `app/models/user.rb` ↔ `spec/controllers/admin_spec.rb` = **0.18** (different paths)

---

## Implementation

**Core Module:** `lib/rsolv/ast/test_scorer.ex`
**API Endpoint:** `POST /api/v1/test-integration/analyze`
**Test Suite:** `test/rsolv/ast/test_scorer_test.exs` (18 tests, 100% passing)
