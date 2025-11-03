# Operator Guide: Troubleshooting Validation Failures

**Purpose**: Help operators diagnose and resolve validation failures in the RSOLV three-phase workflow.

**Audience**: DevOps engineers, SREs, and platform operators running RSOLV workflows.

**Last Updated**: 2025-10-15

---

## Table of Contents

1. [Quick Diagnostic Checklist](#quick-diagnostic-checklist)
2. [Common Failure Patterns](#common-failure-patterns)
3. [Backend API Issues](#backend-api-issues)
4. [Test Generation Failures](#test-generation-failures)
5. [AST Integration Failures](#ast-integration-failures)
6. [Validation Logic Issues](#validation-logic-issues)
7. [Phase Data Storage Issues](#phase-data-storage-issues)
8. [Emergency Response](#emergency-response)
9. [Monitoring and Metrics](#monitoring-and-metrics)

---

## Quick Diagnostic Checklist

When a validation failure occurs, run through this checklist:

- [ ] **Backend Health**: Is the backend API responding? `curl https://api.rsolv.dev/health`
- [ ] **API Authentication**: Is the API key valid and has proper permissions?
- [ ] **Repository State**: Is the repository in a clean state? Check `git status`
- [ ] **Test Framework**: Is a supported test framework installed? (RSpec, Vitest, Jest, pytest)
- [ ] **File Permissions**: Can the action write to test directories?
- [ ] **Rate Limits**: Check GitHub API rate limits and backend quotas
- [ ] **Logs**: Review GitHub Actions logs for error messages and stack traces

---

## Common Failure Patterns

### Pattern 1: Tests Marked as "not-validated"

**Symptom**: Issue tagged with `not-validated` label after VALIDATE phase completes.

**Root Causes**:

1. **Tests passing on vulnerable code** (most common)
   - Tests generated don't actually detect the vulnerability
   - Test assertions are too permissive or incorrect
   - Vulnerability doesn't exist (false positive from SCAN)

2. **Test generation retry exhaustion**
   - Claude Code SDK hit maximum iterations (default: 5)
   - Syntax errors persist across retry attempts
   - Test framework not properly detected

3. **Test execution failures**
   - Missing dependencies (test framework not installed)
   - Wrong test command for framework
   - Environment issues (missing env vars, wrong Node/Ruby/Python version)

**Diagnostic Steps**:

```bash
# 1. Check the issue body for validation details
gh issue view <issue_number> --json body -q .body

# 2. Review validation branch for generated tests
git fetch origin rsolv/validate/issue-<number>
git checkout rsolv/validate/issue-<number>
cat .rsolv/tests/validation.test.* # or check spec/, __tests__/, test/

# 3. Manually run the test to see why it passes
npm test                  # JavaScript/TypeScript
bundle exec rspec         # Ruby
pytest                    # Python

# 4. Check validation results JSON
cat .rsolv/validation/issue-<number>.json
```

**Resolution Strategies**:

1. **Increase retry limit**: Add `claude_max_turns: 10` to workflow config
2. **Manual test refinement**: Edit tests to properly detect vulnerability
3. **Check vulnerability legitimacy**: Verify with manual code review
4. **Framework detection override**: Specify framework explicitly in config

**Example Fix**:
```yaml
- uses: RSOLV-dev/rsolv-action@v2
  with:
    api_key: ${{ secrets.RSOLV_API_KEY }}
    mode: validate
    issue_number: ${{ github.event.issue.number }}
    claude_max_turns: 10  # Increased from 5
    test_framework: rspec  # Override detection
```

---

### Pattern 2: Syntax Errors in Generated Tests

**Symptom**: Tests fail to parse or run due to syntax errors.

**Root Causes**:
- AST serialization introduced formatting issues
- Framework-specific syntax not properly generated
- Escape sequence handling errors
- Template string / heredoc issues

**Diagnostic Steps**:

```bash
# Check syntax with language-specific linter
npx eslint test/file.test.js    # JavaScript
rubocop spec/file_spec.rb       # Ruby
flake8 test/file_test.py        # Python

# Run test file directly to see parser errors
node --check test/file.test.js
ruby -c spec/file_spec.rb
python -m py_compile test/file_test.py
```

**Resolution Strategies**:

1. **Backend fallback**: If AST method fails, fallback to append method
2. **Manual syntax fix**: Edit test file to correct syntax errors
3. **Report to RSOLV team**: If recurring, may be AST serializer bug
4. **Disable AST temporarily**: Use `RSOLV_USE_AST_INTEGRATION=false` (not recommended)

**Prevention**:
- Backend automatically validates syntax before returning integrated content
- Action validates syntax after receiving content
- If both fail, issue is tagged for manual review

---

### Pattern 3: Tests Not Integrated into Existing Suite

**Symptom**: Tests written to `.rsolv/tests/` instead of `spec/`, `__tests__/`, or `test/`.

**Root Causes**:
- No existing test files found in repository
- Test directory not matching expected patterns
- Backend analyze endpoint returned no recommendations (score < threshold)
- AST integration failed and fallback to new file creation

**Diagnostic Steps**:

```bash
# 1. Check if test directories exist
ls -la spec/ __tests__/ test/ 2>/dev/null

# 2. Check test files that exist
find . -name "*_spec.rb" -o -name "*.test.js" -o -name "*_test.py" | head -20

# 3. Check backend analyze response (from action logs)
grep "Test file recommendations" $GITHUB_WORKFLOW_LOGS

# 4. Verify backend API is accessible
curl -H "Authorization: Bearer $RSOLV_API_KEY" \
  https://api.rsolv.dev/health
```

**Resolution Strategies**:

1. **Create test directory structure**:
```bash
# For Ruby/RSpec
mkdir -p spec/controllers spec/models spec/services

# For JavaScript/Vitest
mkdir -p __tests__/unit __tests__/integration

# For Python/pytest
mkdir -p tests/unit tests/integration
```

2. **Add example test files** to help backend scoring:
```bash
# Ruby
touch spec/example_spec.rb

# JavaScript
touch __tests__/example.test.js

# Python
touch tests/test_example.py
```

3. **Check backend connectivity** and retry validation

**Expected Behavior**:
- Backend analyze endpoint should return recommendations with scores 0.0-1.5
- Highest-scoring file location is selected for integration
- If no candidates found (empty array), creates new file in `.rsolv/tests/`

---

### Pattern 4: Regression - Existing Tests Broken

**Symptom**: After test integration, existing tests fail that passed before.

**Root Causes**:
- AST insertion at wrong location (e.g., inside existing test block)
- Import statements added in wrong place
- Indentation/formatting broke code structure
- Variable naming conflicts

**Diagnostic Steps**:

```bash
# 1. Compare file before and after integration
git diff HEAD~1 spec/file_spec.rb

# 2. Run existing tests in isolation
npm test -- --testNamePattern="original test"
bundle exec rspec spec/file_spec.rb:15  # Run specific line
pytest tests/file_test.py::test_original -v

# 3. Check AST insertion point
grep -A5 -B5 "RSOLV generated test" spec/file_spec.rb
```

**Resolution Strategies**:

1. **Manual fix**: Adjust test location/indentation
2. **Revert and retry**: Delete test, re-run validation with different parameters
3. **Report bug**: If AST insertion logic is incorrect, report to RSOLV team
4. **Temporary fallback**: Use append strategy instead of AST

**Prevention**:
- Action runs regression check: existing tests must still pass after integration
- If regression detected, action should roll back changes (not yet implemented - future enhancement)

---

## Backend API Issues

### Symptom: 401 Unauthorized

**Diagnostic**:
```bash
# Test API key directly
curl -i -H "Authorization: Bearer $RSOLV_API_KEY" \
  https://api.rsolv.dev/health

# Expected: 200 OK
# If 401: Invalid API key or expired
```

**Resolution**:
1. Verify API key in GitHub Secrets: `RSOLV_API_KEY`
2. Check API key status in RSOLV dashboard
3. Generate new API key if needed
4. Ensure key format: `rsolv_<alphanumeric>`

### Symptom: 429 Rate Limit Exceeded

**Diagnostic**:
```bash
# Check rate limit headers
curl -i -H "Authorization: Bearer $RSOLV_API_KEY" \
  https://api.rsolv.dev/api/v1/test-integration/analyze

# Look for headers:
# X-RateLimit-Limit: 100
# X-RateLimit-Remaining: 0
# X-RateLimit-Reset: 1697500000
```

**Resolution**:
1. Wait for rate limit reset (check `X-RateLimit-Reset` header)
2. Contact RSOLV support to increase quota
3. Reduce parallel workflows (process fewer issues at once)
4. Add backoff delays between API calls

### Symptom: 500 Internal Server Error

**Diagnostic**:
```bash
# Check backend health
curl https://api.rsolv.dev/health

# Check backend status page
# https://status.rsolv.dev (if available)

# Test specific endpoint
curl -i -X POST \
  -H "Authorization: Bearer $RSOLV_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"vulnerableFile":"app/test.rb","vulnerabilityType":"SQL injection","candidateTestFiles":["spec/test_spec.rb"],"framework":"rspec"}' \
  https://api.rsolv.dev/api/v1/test-integration/analyze
```

**Resolution**:
1. **Automatic retry**: Action retries 5xx errors automatically with exponential backoff (1s, 2s, 4s)
2. **Check backend logs**: Contact RSOLV support with workflow ID
3. **Temporary mitigation**: Switch to staging API (`api_url: https://api.rsolv-staging.com`)
4. **Wait and retry**: Backend may be experiencing temporary issues

**Escalation**:
- If 5xx persists after 3 retries, alert RSOLV on-call
- Provide workflow run ID and timestamps
- Include request payload that caused error

### Symptom: 503 Service Unavailable

**Diagnostic**:
```bash
# Check Kubernetes pods
kubectl get pods -n rsolv-production

# Expected: 2/2 Running
# If 0/2 or 1/2: Backend is down or degraded
```

**Resolution**:
1. **For RSOLV operators**: Check pod logs
```bash
kubectl logs -n rsolv-production -l app=rsolv-api --tail=100
```

2. **For external users**: Wait for service recovery, monitor status page
3. **Temporary mitigation**: Use staging environment if production is down

---

## Test Generation Failures

### Symptom: Claude Code SDK Timeout

**Error Message**: `Error: Claude Code generation timed out after 300000ms`

**Diagnostic**:
- Check action logs for Claude Code API calls
- Look for retry attempts and their outcomes
- Check if issue is particularly complex (large file, many vulnerabilities)

**Resolution**:
1. **Increase timeout** (if workflow allows):
```yaml
- uses: RSOLV-dev/rsolv-action@v2
  with:
    api_key: ${{ secrets.RSOLV_API_KEY }}
    claude_max_turns: 10  # More iterations = longer timeout needed
  timeout-minutes: 30  # Job-level timeout
```

2. **Simplify issue**: Break large issues into smaller chunks
3. **Reduce context**: Limit file size sent to Claude Code
4. **Check Claude Code API status**: May be experiencing rate limits

### Symptom: Tests Don't Detect Vulnerability

**Diagnostic**:
```bash
# 1. Read generated test
cat spec/file_spec.rb  # or appropriate path

# 2. Manually verify test logic
# - Does test exercise vulnerable code path?
# - Does test provide malicious input?
# - Does test check for vulnerability symptoms?

# 3. Run test with debug output
DEBUG=1 npm test
bundle exec rspec --format documentation
pytest -vv
```

**Common Issues**:
- Test uses benign input instead of attack payload
- Test doesn't call vulnerable function
- Test checks wrong assertion (false negative)
- Vulnerability is false positive (not real)

**Resolution**:
1. **Manual test refinement**: Edit test to properly detect vulnerability
2. **Increase iterations**: Give Claude Code more attempts to get it right
3. **Provide better context**: Ensure vulnerable file content is accurate
4. **Report false positive**: If vulnerability doesn't exist, tag issue and close

---

## AST Integration Failures

### Symptom: AST Parsing Failed

**Error Message**: `Warning: AST parsing failed, falling back to append method`

**Diagnostic**:
- Check file encoding (UTF-8 expected)
- Check for syntax errors in target file
- Check language detection (Ruby vs JavaScript vs Python)
- Review backend logs for parser errors

**Resolution**:
1. **Verify target file is valid code**:
```bash
ruby -c spec/file_spec.rb
npx eslint --fix test/file.test.js
flake8 tests/file_test.py
```

2. **Accept fallback**: Append method is acceptable alternative
3. **Report bug**: If valid code fails to parse, report to RSOLV team

**Prevention**:
- Backend uses robust parsers (TreeSitter, Babel, ast)
- Fallback strategies ensure tests are always generated
- Most common cause is invalid syntax in target file

### Symptom: AST Serialization Errors

**Error Message**: Tests integrated but syntax errors when running

**Diagnostic**:
```bash
# Check integrated file syntax
ruby -c spec/file_spec.rb
npx eslint test/file.test.js
python -m py_compile tests/file_test.py
```

**Resolution**:
1. **Manual syntax fix**: Usually indentation or quote escaping
2. **Report bug**: Include input file and output file for debugging
3. **Temporary mitigation**: Use append method instead

**Known Issues**:
- Escape sequences in strings (e.g., `\"`, `\n`)
- Nested template strings in JavaScript
- Heredocs in Ruby
- Triple-quoted strings in Python

---

## Validation Logic Issues

### Symptom: Tests Pass on Vulnerable Code (False Negative)

**Diagnostic**:
```bash
# 1. Checkout vulnerable commit
git checkout $(cat .rsolv/validation/issue-<number>.json | jq -r .vulnerableCommit)

# 2. Run tests - should FAIL
npm test
bundle exec rspec
pytest

# 3. If tests PASS, validation logic is incorrect
```

**Resolution**:
1. **Rewrite tests**: Tests must fail on vulnerable code
2. **Check vulnerability**: May be false positive from SCAN phase
3. **Report issue**: If vulnerability is real but tests pass, needs investigation

**Expected Behavior**:
- RED tests should **fail** on vulnerable code (proving vulnerability exists)
- RED tests should **pass** on fixed code (proving fix works)

### Symptom: Tests Fail on Fixed Code (False Positive)

**Diagnostic**:
```bash
# 1. Checkout fixed commit
git checkout $(cat .rsolv/validation/issue-<number>.json | jq -r .fixedCommit)

# 2. Run tests - should PASS
npm test
bundle exec rspec
pytest

# 3. If tests FAIL, fix is incomplete or tests are too strict
```

**Resolution**:
1. **Review fix**: Ensure fix actually addresses vulnerability
2. **Review tests**: Tests may be testing wrong behavior
3. **Iterate**: Re-run MITIGATE phase with feedback

---

## Phase Data Storage Issues

### Symptom: "No validate data found for issue N"

**Error Message**: `Error: No validate data found for issue 123`

**Root Cause**: PhaseDataClient key mismatch between VALIDATE and MITIGATE phases

**Diagnostic**:
```bash
# 1. Check validation branch for stored data
git fetch origin rsolv/validate/issue-<number>
git checkout rsolv/validate/issue-<number>
ls -la .rsolv/validation/

# 2. Check validation result JSON
cat .rsolv/validation/issue-<number>.json

# 3. Check phase data storage format
# Correct: { "validate": { "123": {...} } }
# Wrong: { "validation": { "issue-123": {...} } }
```

**Resolution**:
1. **Update to v3.7.54+**: Key format fixed in this version
2. **Manual migration**: Convert legacy keys to numeric format
3. **Re-run VALIDATE**: Regenerate validation data with correct keys

**Prevention**:
- v3.7.54+ uses correct key format: `validate` phase, numeric keys
- Legacy fallback supports old `issue-N` format for backward compatibility

---

## Emergency Response

### Critical: Production Workflow Completely Broken

**Immediate Actions**:

1. **Stop all workflows**:
```bash
gh workflow disable "RSOLV AutoFix" --repo $OWNER/$REPO
```

2. **Switch to last known good version**:
```yaml
- uses: RSOLV-dev/rsolv-action@v3.7.53  # Or last working version
```

3. **Check backend status**:
```bash
curl https://api.rsolv.dev/health
```

4. **Alert team**: Post in #rsolv-incidents Slack channel

5. **Document issue**: Create incident report with:
   - Workflow run ID
   - Error messages and stack traces
   - Affected repositories
   - Timeline of events

**Rollback Procedure**:

```bash
# 1. Revert to previous workflow version
git checkout HEAD~1 .github/workflows/rsolv-autofix.yml
git commit -m "Rollback: Revert RSOLV workflow to last known good version"
git push

# 2. Re-enable workflows
gh workflow enable "RSOLV AutoFix"

# 3. Test with single issue
gh workflow run "RSOLV AutoFix" -f issue_number=123
```

### Degraded Performance: High Failure Rate

**Symptoms**:
- >20% of validations failing
- Increased "not-validated" issues
- Longer execution times

**Diagnostic**:
```bash
# Check failure rate across recent workflows
gh run list --workflow="RSOLV AutoFix" --limit=50 --json conclusion \
  | jq '[.[] | select(.conclusion=="failure")] | length'

# Check average duration
gh run list --workflow="RSOLV AutoFix" --limit=20 --json durationMs \
  | jq '[.[].durationMs] | add / length / 1000 / 60'  # Minutes
```

**Resolution**:
1. **Identify pattern**: Are failures specific to language/framework?
2. **Check backend metrics**: Contact RSOLV support for API performance data
3. **Reduce load**: Process fewer issues concurrently
4. **Increase timeouts**: Give workflows more time to complete

---

## Monitoring and Metrics

### Key Metrics to Track

**Validation Success Rate**:
```bash
# Calculate success rate
TOTAL=$(gh issue list --label rsolv:automate --state all --limit 1000 --json number | jq length)
NOT_VALIDATED=$(gh issue list --label not-validated --state all --limit 1000 --json number | jq length)
SUCCESS_RATE=$(echo "scale=2; (1 - $NOT_VALIDATED / $TOTAL) * 100" | bc)
echo "Validation success rate: $SUCCESS_RATE%"
```

**Target**: ≥85% success rate

**Backend API Performance**:
- Analyze endpoint: Target <100ms p95
- Generate endpoint: Target <2000ms p95
- Health check: Target <50ms p95

**Test Integration Metrics**:
- AST method usage: Target ≥80% (vs fallback methods)
- Regression rate: Target <5% (existing tests broken)
- Framework detection accuracy: Target ≥95%

### Dashboards

**GitHub Actions Dashboard**:
- Workflow success rate by week
- Average execution time trend
- Failure reasons breakdown
- Issues processed per day

**Backend API Dashboard** (RSOLV operators):
- API endpoint latency (p50, p95, p99)
- Error rate by endpoint
- Active API keys and usage
- Rate limit violations

### Alerts

**Critical Alerts**:
- Backend API down (0/2 pods healthy)
- Validation success rate <70% (1 hour window)
- Backend API latency >5s (p95, 5 minute window)
- Error rate >10% (5 minute window)

**Warning Alerts**:
- Validation success rate <85% (24 hour window)
- Backend API latency >2s (p95, 15 minute window)
- Single pod unhealthy (degraded performance)
- Rate limit violations increasing

---

## Getting Help

### Internal Escalation (RSOLV Team)

1. **Slack**: #rsolv-engineering (general), #rsolv-incidents (critical)
2. **On-Call**: PagerDuty "RSOLV Platform" escalation policy
3. **Email**: engineering@rsolv.dev (monitored 24/7)

### External Support (Customers)

1. **Email**: support@rsolv.dev
2. **GitHub Issues**: https://github.com/RSOLV-dev/rsolv-action/issues
3. **Documentation**: https://docs.rsolv.dev
4. **Status Page**: https://status.rsolv.dev (coming soon)

### Issue Report Template

```markdown
**Issue Summary**: [Brief description]

**Workflow Run ID**: [GitHub Actions run ID]

**Repository**: [Owner/repo]

**Issue Number**: [GitHub issue #]

**Error Message**:
```
[Paste full error message and stack trace]
```

**Steps to Reproduce**:
1. [Step 1]
2. [Step 2]
3. [Step 3]

**Expected Behavior**: [What should happen]

**Actual Behavior**: [What actually happened]

**Logs**:
- Attach: GitHub Actions workflow logs
- Attach: Validation result JSON (if available)
- Attach: Generated test files (if available)

**Environment**:
- RSOLV Action Version: v2.5.2
- Backend API URL: https://api.rsolv.dev
- Test Framework: [RSpec/Vitest/Jest/pytest]
- Language: [Ruby/JavaScript/TypeScript/Python]

**Additional Context**: [Any other relevant information]
```

---

## Version History

- **v1.0** (2025-10-15): Initial version covering RFC-060 v3.7.54 + Amendment 001
- **Next review**: 2025-11-01 (after 6-week monitoring period)

---

**Related Documents**:
- [RFC-060 Completion Report](../../RFCs/RFC-060-COMPLETION-REPORT.md)
- [ADR-031: AST Integration Architecture](../../ADRs/ADR-031-AST-TEST-INTEGRATION.md)
- [Three-Phase Architecture Documentation](THREE-PHASE-ARCHITECTURE.md)
- [Common Integration Patterns](INTEGRATION-PATTERNS.md) (coming soon)
- [Not-Validated Runbook](NOT-VALIDATED-RUNBOOK.md) (coming soon)
