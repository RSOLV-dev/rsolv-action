# Test Integration - Implementation Guide

This guide covers the test integration feature: automatically integrating security tests into existing test files using AST-based manipulation.

## 📁 Test Files

### Core Test Suites

1. **`test-integration-client.test.ts`** (10 API client tests)
   - Tests the `TestIntegrationClient` backend API client
   - Covers: analyze(), generate(), retry logic, authentication
   - Status: 🔴 **RED** (implementation pending)

2. **`validation-mode-test-integration.test.ts`** (8 workflow tests)
   - Tests the `ValidationMode.generateTestWithRetry()` workflow
   - Covers: LLM retry loop, error feedback, issue tagging
   - Status: 🔴 **RED** (implementation pending)

### Reference Documentation

3. **`REALISTIC-VULNERABILITY-EXAMPLES.md`** ⚠️ **READ THIS FIRST**
   - Real-world vulnerability patterns from NodeGoat & RailsGoat
   - Actual attack vectors (SQL injection, XSS, NoSQL injection, etc.)
   - Expected RED test behavior
   - CWE classifications
   - **Use this as your source of truth for vulnerability examples**

## 🎯 Implementation Checklist

When implementing the Test Integration feature, follow this order:

### Step 1: Read the Documentation
- [ ] Read `REALISTIC-VULNERABILITY-EXAMPLES.md` thoroughly
- [ ] Understand the 6 vulnerability patterns (NoSQL injection, SQL injection, XSS, etc.)
- [ ] Note the actual attack vectors used (they're from real exploits!)
- [ ] Review the CWE numbers for each vulnerability type

### Step 2: Implement TestIntegrationClient
- [ ] Create `src/modes/test-integration-client.ts`
- [ ] Implement `analyze()` method with retry logic
- [ ] Implement `generate()` method with retry logic
- [ ] Use `x-api-key` header authentication (NOT Bearer token!)
- [ ] Support `RSOLV_API_URL` environment variable
- [ ] Run tests: `bun test src/modes/__tests__/test-integration-client.test.ts`
- [ ] All tests should turn 🟢 **GREEN**

### Step 3: Implement generateTestWithRetry() in ValidationMode
- [ ] Add `generateTestWithRetry()` method to `ValidationMode` class
- [ ] Implement 3-attempt retry loop
- [ ] Add error feedback to LLM prompts (syntax errors, test passed, regressions)
- [ ] Tag issues with "not-validated" after 3 failures
- [ ] Add GitHub comment with attempt history
- [ ] Run tests: `bun test src/modes/__tests__/validation-mode-test-integration.test.ts`
- [ ] All tests should turn 🟢 **GREEN**

### Step 4: LLM Prompt Engineering
When generating LLM prompts for test generation:

**MUST include:**
- Vulnerability pattern from `REALISTIC-VULNERABILITY-EXAMPLES.md`
- Actual attack vector (e.g., `"5') OR admin = 't' --'"` for SQL injection)
- Target file content (so LLM can see existing setup blocks)
- CWE number (e.g., "CWE-89: SQL Injection")
- Expected behavior: "Test MUST FAIL on vulnerable code"

**Example LLM prompt structure:**
```typescript
const prompt = `
You are generating a RED test for a security vulnerability.

VULNERABILITY: SQL Injection (CWE-89)
PATTERN: User.where("id = '#{params[:user][:id]}'")
ATTACK VECTOR: 5') OR admin = 't' --'
SOURCE: RailsGoat

TARGET TEST FILE:
${targetFileContent}  // Shows existing setup blocks

YOUR TASK:
Generate RSpec test code that:
1. Sends the attack vector to the vulnerable endpoint
2. FAILS on vulnerable code (proves exploit works)
3. PASSES after fix is applied
4. Reuses existing setup from target file

${previousAttempts.length > 0 ? `
PREVIOUS ATTEMPTS:
${previousAttempts.map(a => `Attempt ${a.number}: ${a.error}`).join('\n')}
` : ''}
`;
```

### Step 5: Integration Testing
- [ ] Test end-to-end flow:
  1. Scan test files
  2. Backend analyzes and scores files
  3. Read target file content
  4. Generate test with retry (up to 3 attempts)
  5. Backend AST integration
  6. Write integrated file
  7. Validate syntax and execution
  8. Commit and push
- [ ] Verify tests use realistic attack vectors
- [ ] Ensure tests actually FAIL on vulnerable code
- [ ] Check GitHub issue tagging works

## 🚨 Common Pitfalls to Avoid

### ❌ Don't Do This:
1. **Don't make up attack vectors** - Use the ones from `REALISTIC-VULNERABILITY-EXAMPLES.md`
2. **Don't use Bearer token auth** - Use `x-api-key` header (project convention)
3. **Don't skip target file content** - LLM needs to see existing setup blocks
4. **Don't forget CWE numbers** - Include them in test names
5. **Don't hardcode API URL** - Support `RSOLV_API_URL` env variable

### ✅ Do This:
1. **Use real vulnerability patterns** from NodeGoat/RailsGoat
2. **Pass target file content to LLM** for context
3. **Include error feedback in retry prompts** (syntax errors, test passed, regressions)
4. **Tag issues after 3 failures** with attempt history
5. **Test against realistic attack vectors** that actually exploit vulnerabilities

## 📊 Test Status

```
Test Writing ✅ COMPLETE
  - 25 tests written (17 client + 8 workflow)
  - 10 tests RED (awaiting implementation)
  - 15 tests GREEN (configuration & validation)
  - Realistic vulnerability examples documented
  - API URL configuration added

Implementation 🔴 TODO
  - TestIntegrationClient class
  - generateTestWithRetry() method
  - LLM prompt engineering
  - Integration testing

Future Enhancements 🔴 TODO
  - Performance optimization
  - Additional vulnerability patterns
  - Cross-framework support
```

## 🔗 Related Files

- **Implementation**: `src/modes/test-integration-client.ts` (to be created)
- **Integration point**: `src/modes/validation-mode.ts` (enhance `commitTestsToBranch()`)
- **Backend API**: https://api.rsolv.dev/api/v1/test-integration/*
- **Design docs**: See project RFCs directory for detailed specifications

## 🤝 How Other Workstreams Should Use This

### Backend Team (Elixir)
- Read `REALISTIC-VULNERABILITY-EXAMPLES.md` to understand expected inputs
- API spec is in test file headers (AnalyzeRequest, GenerateRequest types)
- Authentication: `x-api-key` header
- Endpoints: `/api/v1/test-integration/analyze` and `/generate`

### Frontend Team (TypeScript)
- Start with `test-integration-client.test.ts` to understand client API
- Use `REALISTIC-VULNERABILITY-EXAMPLES.md` for LLM prompts
- Reference `validation-mode-test-integration.test.ts` for retry loop behavior

### QA Team
- Use `REALISTIC-VULNERABILITY-EXAMPLES.md` as test case reference
- All 6 vulnerability patterns must be testable
- Attack vectors are the actual exploits to test against

### Documentation Team
- `REALISTIC-VULNERABILITY-EXAMPLES.md` can be published as-is
- Shows real-world vulnerability patterns we detect
- Includes CWE numbers for compliance documentation

## 💡 Tips for Success

1. **Start with the examples doc** - Don't skip `REALISTIC-VULNERABILITY-EXAMPLES.md`
2. **TDD approach** - Tests are already RED, make them GREEN
3. **Use real attack vectors** - They're proven exploits from OWASP projects
4. **Pass context to LLM** - Include target file content in prompts
5. **Handle retries gracefully** - LLM won't always generate perfect tests on first try

---

**Questions?** Check the design docs in the RFCs directory or ping the team!

**Last Updated**: October 2025
