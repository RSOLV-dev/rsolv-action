# ADR-031: AST-Based Test Integration Architecture

**Status**: Implemented
**Date**: 2025-10-15
**Related RFC**: [RFC-060-AMENDMENT-001](../RFCs/RFC-060-AMENDMENT-001-TEST-INTEGRATION.md)
**Supersedes**: N/A
**Impact**: Critical - Enables framework-native test integration

## Context

RFC-060 successfully implemented RED-only test generation and git-based validation (v3.7.54), but tests were written to `.rsolv/tests/validation.test.js` instead of being integrated into existing framework test directories (e.g., `spec/`, `__tests__/`, `test/`).

**Problem**: Developers could not run `npm test`, `bundle exec rspec`, or `pytest` to execute RSOLV-generated security tests alongside their existing test suite. This reduced adoption and violated the principle of integrating seamlessly into developer workflows.

**Constraints**:
- Backend cannot access customer repositories (security/privacy)
- Frontend (GitHub Action) must generate and run tests immediately (validation requirement)
- AST manipulation required to preserve formatting and maintain idiomatic code
- Must support multiple languages (Ruby, JavaScript/TypeScript, Python) and frameworks (RSpec, Jest, Vitest, pytest)

## Decision

We implemented a **backend-led AST integration architecture** where:

1. **Backend provides**:
   - Test file scoring algorithm (path similarity + bonuses)
   - AST-based test integration (parse → traverse → insert → serialize)
   - Framework detection helpers
   - 2 core API endpoints: `/api/v1/test-integration/{analyze,generate}`

2. **Frontend provides**:
   - Test generation with AI (including retry loop with error feedback)
   - Test execution and validation (syntax check + RED test verification)
   - File operations (read target file, write integrated content)
   - Git operations (commit and push)

### Architecture

```
Frontend (GitHub Action) Flow:
1. Scan test files → ["spec/foo_spec.rb", "test/bar_test.js"]

2. Backend: Analyze
   POST /api/v1/test-integration/analyze
   {
     "vulnerableFile": "app/controllers/users_controller.rb",
     "vulnerabilityType": "SQL injection",
     "candidateTestFiles": ["spec/controllers/users_controller_spec.rb"],
     "framework": "rspec"
   }
   Response: { "recommendations": [{ "path": "...", "score": 1.45, "reason": "..." }] }

3. Read target file content (local filesystem)

4. Generate test with AI (includes 3-attempt retry loop):
   - LLM receives target file content for context
   - Generate test code
   - Validate syntax
   - Run test (must FAIL on vulnerable code)
   - Check regressions (existing tests must still pass)
   - If any validation fails → RETRY with error feedback
   - After 3 failures → Tag issue "not-validated", exit

5. Backend: Integrate using AST
   POST /api/v1/test-integration/generate
   {
     "targetFileContent": "...",
     "testSuite": { "redTests": [...] },
     "framework": "rspec",
     "language": "ruby"
   }
   Response: {
     "integratedContent": "...",
     "method": "ast",
     "insertionPoint": { "line": 5, "strategy": "after_last_it_block" }
   }

6. Write integrated file to filesystem

7. Final validation:
   - Syntax check (ensures AST serialization didn't break code)
   - Test execution (RED test must FAIL on vulnerable code)
   - Regression check (existing tests must still PASS)

8. Commit and push to Git
```

### Backend Implementation (Elixir)

**Modules**:
- `Rsolv.AST.TestScorer` - Scores test files based on path similarity
- `Rsolv.AST.TestIntegrator` - AST-based test integration
- `RsolvWeb.API.TestIntegrationController` - API endpoints

**Scoring Algorithm**:
```elixir
def score_test_file(vulnerable_file, test_file) do
  base = path_similarity_score(vulnerable_file, test_file)  # 0.0-1.0
  module_bonus = if same_module?(vulnerable_file, test_file), do: 0.3, else: 0.0
  directory_bonus = if same_directory_structure?(vulnerable_file, test_file), do: 0.2, else: 0.0

  base + module_bonus + directory_bonus  # Range: 0.0-1.5
end
```

**AST Integration**:
```elixir
def generate_integration(target_content, test_suite, language, framework) do
  target_content
  |> parse_ast(language)
  |> find_insertion_point(framework)
  |> insert_test(test_suite)
  |> serialize_to_code()
  |> case do
    {:ok, integrated, point} -> {:ok, integrated, point, :ast}
    {:error, _} -> {:ok, fallback_append(target_content, test_suite), nil, :append}
  end
end
```

### Frontend Implementation (TypeScript)

**Class**: `TestIntegrationClient` (validation-mode.ts:546-640)

**API Client**:
```typescript
export class TestIntegrationClient {
  constructor(private apiKey: string, private apiUrl: string) {}

  async analyze(request: AnalyzeRequest): Promise<AnalyzeResponse> {
    return this.post('/api/v1/test-integration/analyze', request);
  }

  async generate(request: GenerateRequest): Promise<GenerateResponse> {
    return this.post('/api/v1/test-integration/generate', request);
  }

  private async post<TRequest, TResponse>(
    endpoint: string,
    data: TRequest
  ): Promise<TResponse> {
    const response = await fetch(`${this.apiUrl}${endpoint}`, {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${this.apiKey}`,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify(data)
    });

    if (!response.ok) {
      if (response.status >= 500) {
        // Retry on 5xx errors with exponential backoff
        throw new RetryableError(`Server error: ${response.statusText}`);
      }
      throw new Error(`Backend API failed: ${response.statusText}`);
    }

    return response.json();
  }
}
```

**Retry Logic**: 3 attempts with exponential backoff (1s, 2s, 4s) for 5xx errors only

### Framework Support

| Language | Framework | Status | AST Support | Score Range |
|----------|-----------|--------|-------------|-------------|
| Ruby | RSpec | ✅ Production | Yes | 0.8 - 1.5 |
| JavaScript | Vitest | ✅ Production | Yes | 1.0 - 1.7 |
| JavaScript | Jest | ✅ Production | Yes | 1.0 - 1.7 |
| TypeScript | Vitest | ✅ Production | Yes | 1.0 - 1.7 |
| Python | pytest | ✅ Production | Yes | 0.7 - 1.2 |

## Consequences

### Positive

1. **Developer Experience**: Tests can be run with standard framework commands (`npm test`, `bundle exec rspec`, `pytest`)
2. **Framework Integration**: Tests follow repository-specific conventions and directory structures
3. **Code Quality**: AST-based integration preserves formatting and maintains idiomatic code
4. **Scalability**: Backend logic is 100% reusable across Git forges (GitHub, GitLab, Bitbucket)
5. **Flexibility**: Graceful degradation with fallback strategies (append, new file creation)
6. **Robustness**: Retry logic with error feedback improves test generation success rate

### Negative

1. **Complexity**: AST parsing/serialization adds complexity vs simple file append
2. **Language Support**: Each new language requires AST parser integration
3. **Maintenance**: Framework-specific insertion strategies must be maintained
4. **Testing**: More extensive testing required (unit tests + E2E tests for each language)

### Neutral

1. **API Dependency**: Frontend depends on backend API availability (mitigated with fallbacks)
2. **Performance**: AST operations add latency (500-1300ms vs <100ms for append), but acceptable for quality gain

## Implementation

**Deployment**:
- **Date**: 2025-10-15
- **Version**: Included in commit `b49e8a70`
- **Image**: `ghcr.io/rsolv-dev/rsolv-platform:production-b49e8a70`
- **Strategy**: Zero-downtime Kubernetes rolling update
- **Verification**: 6/6 E2E tests passing in production

**Test Coverage**:
- Backend unit tests: 8/8 passing (100%)
- E2E integration tests: 6/6 passing (100%)
  - Ruby/RSpec analyze + generate
  - JavaScript/Vitest analyze + generate
  - Python/pytest analyze + generate

**Production Metrics** (Measured 2025-10-15):
- Analyze endpoint: ~21-103ms response time
- Generate endpoint: ~109-1296ms response time
- Health check: <50ms response time
- Uptime: 100% (2/2 pods healthy)

**Production Verification**:
```
✓ Ruby/RSpec: score 1.45, 19 lines generated via AST
✓ JavaScript/Vitest: score 1.69, 20 lines generated via AST
✓ Python/pytest: score 0.8, 17 lines generated via AST
```

## Alternatives Considered

### 1. Frontend-Only AST Integration
**Rejected**: Would require bundling AST parsers for all languages in GitHub Action (large bundle size, slow startup, difficult to maintain)

### 2. LLM-Based Integration Without AST
**Rejected**: LLMs are inconsistent at preserving formatting and may introduce syntax errors (tested in early prototypes, 30% failure rate)

### 3. Simple File Append
**Rejected**: Doesn't integrate into existing test structure, tests appear disconnected from existing suite

### 4. New Test File Creation Only
**Rejected**: Doesn't meet goal of framework integration, tests remain segregated

**Decision**: Backend-led AST with frontend orchestration provides best balance of:
- Security (no backend repo access)
- Quality (AST ensures valid code)
- Flexibility (fallback strategies)
- Reusability (backend logic portable)

## Git Forge Portability

**Backend Reuse**: 100% of backend logic (scoring + AST integration) is portable to any Git forge

**Per-Forge Implementation**: Only file operations and Git operations need to be reimplemented:
```typescript
// GitLab CI integration (16-24 hours implementation)
class GitLabIntegration {
  async commitTests(testSuite, branch, issue) {
    const testFiles = await this.scanTestFiles();       // GitLab-specific
    const analysis = await backend.analyze({...});      // REUSED ✓
    const content = await this.readFile(...);           // GitLab-specific
    const integration = await backend.generate({...});  // REUSED ✓
    await this.writeFile(...);                          // GitLab-specific
    await this.gitCommit(...);                          // GitLab-specific
  }
}
```

## Migration Path

**Backward Compatibility**: Tests generated before ADR-031 (in `.rsolv/tests/`) continue to work. New tests are integrated into framework directories.

**Forward Compatibility**: All test generation uses AST integration by default, with fallback strategies for edge cases.

## Success Metrics

**Measured** (Week 1 baseline - 2025-10-15):
- Test integration success rate: TBD (target: ≥90%)
- AST method usage: TBD (target: ≥80% vs append fallback)
- Fallback to .rsolv/tests/: TBD (target: <10%)
- Backend API uptime: 100% (target: ≥99.5%)
- Issues tagged "not-validated": TBD (target: <5%)

**To Be Tracked** (6-week monitoring period):
- Integration rate improvements over time
- Framework distribution across customer repos
- Average integration time (target: <10s end-to-end)
- Test generation retry attempts

## References

- **RFC-060**: Executable Validation Test Integration
- **RFC-060-AMENDMENT-001**: Backend-Led Test Integration (this ADR's implementation)
- **RFC-060 Completion Report**: Production validation results
- **Implementation Files**:
  - Backend: `lib/rsolv/ast/test_scorer.ex`, `lib/rsolv/ast/test_integrator.ex`
  - Frontend: `src/modes/test-integration-client.ts`, `src/modes/validation-mode.ts`
  - Tests: `test/rsolv/ast/*_test.exs`, `src/modes/__tests__/backend-api-integration.test.ts`
- **Deployment**: Kubernetes manifest in `rsolv-infrastructure`, image `production-b49e8a70`

## Future Enhancements

1. **Additional Languages**:
   - Java/JUnit5 (RFC-060-AMENDMENT-002 planned)
   - PHP/PHPUnit
   - Go/testing package

2. **Additional Ruby Frameworks**:
   - Minitest support

3. **Additional Python Frameworks**:
   - unittest support

4. **Enhanced Error Recovery**:
   - Smarter retry strategies based on error type
   - LLM-powered error diagnosis and correction

5. **Multi-Language Projects**:
   - Support for monorepos with multiple languages
   - Framework detection per directory

---

**Document Version**: 1.0
**Last Updated**: 2025-10-15
**Next Review**: 2025-11-01 (after 6-week monitoring period)
