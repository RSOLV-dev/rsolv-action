# Runbook: "not-validated" Issue Resolution

**Purpose**: Systematic playbook for resolving issues tagged with `not-validated` label.

**Audience**: DevOps engineers, SREs, and security engineers managing RSOLV workflows.

**SLA**: Issues tagged `not-validated` should be triaged within 24 hours, resolved within 7 days.

**Last Updated**: 2025-10-15

---

## Table of Contents

1. [Overview](#overview)
2. [Quick Start](#quick-start)
3. [Diagnostic Decision Tree](#diagnostic-decision-tree)
4. [Resolution Procedures](#resolution-procedures)
5. [Escalation Paths](#escalation-paths)
6. [Metrics and Reporting](#metrics-and-reporting)

---

## Overview

### What is "not-validated"?

The `not-validated` label is applied to issues when the VALIDATE phase cannot prove a vulnerability exists. This happens in three scenarios:

1. **False Positive**: Vulnerability does not actually exist (SCAN phase error)
2. **Test Generation Failure**: RED tests could not be generated (AI/tooling issue)
3. **Test Validation Failure**: Tests were generated but don't detect the vulnerability (test quality issue)

### Why This Matters

- **Security Risk**: Real vulnerabilities may go unaddressed if dismissed as false positives
- **Developer Trust**: High false positive rate erodes confidence in RSOLV
- **Resource Waste**: Developer time spent triaging invalid issues
- **Compliance**: Unvalidated security findings may fail audit requirements

### Success Criteria

**Target Metrics**:
- <15% of scanned issues marked `not-validated` (target: <10%)
- 100% of `not-validated` issues triaged within 24 hours
- >80% resolution rate within 7 days
- <5% false negatives (real vulnerabilities missed)

---

## Quick Start

### 1. Identify Not-Validated Issues

```bash
# List all not-validated issues
gh issue list --label not-validated --state open --json number,title,createdAt

# Get count by week
gh issue list --label not-validated --state all --limit 1000 --json createdAt \
  | jq 'group_by(.createdAt[0:10]) | map({date: .[0].createdAt[0:10], count: length})'
```

### 2. Check Issue Details

```bash
# View issue with full context
gh issue view <ISSUE_NUMBER>

# Key information to extract:
# - Vulnerability type (SQL injection, XSS, etc.)
# - File path and line number
# - Why validation failed (check comments from RSOLV bot)
# - Workflow run ID (for logs)
```

### 3. Review Workflow Logs

```bash
# Get latest workflow run for this issue
gh run list --workflow="RSOLV AutoFix" --json databaseId,conclusion,createdAt --limit 10

# View logs for specific run
gh run view <RUN_ID> --log

# Search logs for validation failure
gh run view <RUN_ID> --log | grep -A20 "not-validated"
```

### 4. Classify Issue Type

Use the [Diagnostic Decision Tree](#diagnostic-decision-tree) below to determine:
- **False Positive** → Close issue with explanation
- **Test Generation Failure** → Retry with different parameters or manual test
- **Test Validation Failure** → Refine test and retry

---

## Diagnostic Decision Tree

```
Issue tagged "not-validated"
│
├─ Does vulnerability exist? (Manual code review)
│  │
│  ├─ NO → [FALSE POSITIVE]
│  │      └─ Close issue, tag "false-positive"
│  │      └─ Document pattern in scan exclusion list
│  │
│  └─ YES → Continue to next step
│
├─ Were tests generated? (Check validation branch)
│  │
│  ├─ NO → [TEST GENERATION FAILURE]
│  │      ├─ Check Claude Code SDK logs
│  │      ├─ Check retry count (default: 5)
│  │      └─ Resolution: Retry with higher claude_max_turns
│  │
│  └─ YES → Continue to next step
│
├─ Do tests have syntax errors? (Check validation logs)
│  │
│  ├─ YES → [SYNTAX ERROR]
│  │      ├─ Check AST integration logs
│  │      ├─ Check test framework detection
│  │      └─ Resolution: Manual fix or retry with append fallback
│  │
│  └─ NO → Continue to next step
│
└─ Do tests pass on vulnerable code? (Key diagnostic)
   │
   ├─ YES → [TEST VALIDATION FAILURE]
   │      ├─ Tests are too permissive (weak assertions)
   │      ├─ Tests don't exercise vulnerable code path
   │      ├─ Tests use wrong attack vector
   │      └─ Resolution: Refine test logic, retry validation
   │
   └─ NO (tests fail on vulnerable code)
          → [UNEXPECTED - SHOULD HAVE VALIDATED]
          └─ This is a bug in validation logic
          └─ Escalate to RSOLV engineering team
```

---

## Resolution Procedures

### Procedure 1: False Positive Resolution

**When to Use**: Vulnerability does not actually exist (confirmed by manual review)

**Steps**:

1. **Manual Code Review**:
```bash
# Checkout the vulnerable code
gh issue view <ISSUE_NUMBER> --json body -q .body | grep "File:"
# Note the file path and line number

# Review the code
code <FILE_PATH>:<LINE_NUMBER>

# Ask:
# - Is there actual user input reaching this code?
# - Are there proper sanitization/validation checks?
# - Is the pattern a false match (e.g., in comments, test code)?
```

2. **Document Findings**:
```bash
# Add comment to issue explaining why it's a false positive
gh issue comment <ISSUE_NUMBER> --body "## False Positive Analysis

**Reviewed by**: @username
**Date**: $(date +%Y-%m-%d)

**Why this is a false positive**:
- [Explain reason, e.g., \"Input is validated by X middleware before reaching this code\"]
- [Provide code evidence]

**Pattern to exclude**:
- [If pattern is consistently false, document for exclusion]

**Resolution**: Closing as false positive. No security risk."
```

3. **Close Issue**:
```bash
# Add labels
gh issue edit <ISSUE_NUMBER> --add-label "false-positive,security-reviewed"
gh issue edit <ISSUE_NUMBER> --remove-label "not-validated"

# Close with comment
gh issue close <ISSUE_NUMBER> --comment "Confirmed false positive through manual security review. See previous comment for details."
```

4. **Update Exclusion List** (if pattern is recurring):
```bash
# Add to .rsolv-exclusions.yml (create if doesn't exist)
cat >> .rsolv-exclusions.yml << EOF
exclusions:
  - pattern: "SQL injection in test helper methods"
    reason: "Test helpers intentionally construct SQL for fixture setup"
    files:
      - "test/support/**"
      - "spec/support/**"
    reviewer: "@username"
    date: $(date +%Y-%m-%d)
EOF

# Commit and push
git add .rsolv-exclusions.yml
git commit -m "docs: Add false positive exclusion pattern"
git push
```

**Metrics**: Track false positive rate by vulnerability type and file pattern

---

### Procedure 2: Test Generation Failure Resolution

**When to Use**: No tests were generated (Claude Code SDK failed)

**Steps**:

1. **Check Retry Count**:
```bash
# Review workflow logs
gh run view <RUN_ID> --log | grep "claude_max_turns"

# Typical output: "Using claude_max_turns: 5"
```

2. **Increase Retry Limit and Re-run**:
```bash
# Trigger workflow with higher retry limit
gh workflow run "RSOLV AutoFix" \
  -f issue_number=<ISSUE_NUMBER> \
  -f claude_max_turns=10

# Or edit workflow file
# .github/workflows/rsolv-autofix.yml:
# with:
#   claude_max_turns: 10  # Increased from 5
```

3. **If Still Failing, Manual Test Creation**:

Create test manually based on vulnerability details:

```bash
# Example: SQL injection in Ruby
cat > spec/security/issue_<NUMBER>_spec.rb << 'EOF'
# Tests for Issue #<NUMBER>: SQL injection in User.find_by_username
RSpec.describe 'SQL Injection Security Test' do
  it 'should detect SQL injection in username lookup' do
    malicious_input = "admin' OR '1'='1"

    # Test should FAIL on vulnerable code
    expect {
      User.find_by_username(malicious_input)
    }.to raise_error(ActiveRecord::StatementInvalid)
  end
end
EOF

# Run test to verify it fails on vulnerable code
bundle exec rspec spec/security/issue_<NUMBER>_spec.rb

# Should output: FAILED (this is correct - proves vulnerability exists)
```

4. **Commit Test and Tag Issue as Validated**:
```bash
# Create validation branch
git checkout -b rsolv/validate/issue-<NUMBER>

# Commit test
git add spec/security/issue_<NUMBER>_spec.rb
git commit -m "test: Add manual RED test for issue #<NUMBER> SQL injection"
git push origin rsolv/validate/issue-<NUMBER>

# Update issue
gh issue edit <ISSUE_NUMBER> --remove-label "not-validated"
gh issue edit <ISSUE_NUMBER> --add-label "validated-manually"
gh issue comment <ISSUE_NUMBER> --body "Manual test created. Ready for mitigation phase."
```

5. **Proceed to Mitigation**:
```bash
# Trigger MITIGATE phase
gh workflow run "RSOLV AutoFix" \
  -f mode=mitigate \
  -f issue_number=<ISSUE_NUMBER>
```

**Metrics**: Track test generation failure rate by language and vulnerability type

---

### Procedure 3: Test Validation Failure Resolution

**When to Use**: Tests generated but don't detect vulnerability (tests pass on vulnerable code)

**Steps**:

1. **Retrieve Generated Tests**:
```bash
# Checkout validation branch
git fetch origin rsolv/validate/issue-<NUMBER>
git checkout rsolv/validate/issue-<NUMBER>

# Find generated test
find . -name "*.test.js" -o -name "*_spec.rb" -o -name "*_test.py" | grep -v node_modules

# Review test
cat <TEST_FILE_PATH>
```

2. **Run Test on Vulnerable Code** (should FAIL but passes):
```bash
# JavaScript
npm test <TEST_FILE_PATH>

# Ruby
bundle exec rspec <TEST_FILE_PATH>

# Python
pytest <TEST_FILE_PATH> -v

# Expected: FAIL (but seeing PASS - this is the problem)
```

3. **Diagnose Why Test Passes**:

Common issues:
- **Weak assertion**: `expect(result).toBeDefined()` instead of `expect(result).not.toContain('<script>')`
- **Wrong input**: Using benign input instead of attack payload
- **Wrong code path**: Not calling vulnerable function
- **Missing setup**: Vulnerability requires specific state/configuration

Example diagnosis:
```javascript
// Generated test (WRONG)
it('should detect XSS', () => {
  const result = sanitize('hello world');  // Benign input!
  expect(result).toBeDefined();            // Weak assertion!
});

// Should be (RIGHT)
it('should detect XSS', () => {
  const maliciousInput = '<script>alert(1)</script>';  // Attack payload
  const result = sanitize(maliciousInput);
  expect(result).not.toContain('<script>');            // Strong assertion
  expect(result).not.toContain('alert');
});
```

4. **Fix Test**:
```bash
# Edit test file
code <TEST_FILE_PATH>

# Make corrections:
# - Add attack payload as input
# - Strengthen assertions
# - Ensure vulnerable code path is exercised

# Example fix:
sed -i "s/'hello world'/'<script>alert(1)<\/script>'/g" <TEST_FILE_PATH>
sed -i "s/expect(result).toBeDefined()/expect(result).not.toContain('<script>')/g" <TEST_FILE_PATH>
```

5. **Re-run Test** (should now FAIL on vulnerable code):
```bash
npm test <TEST_FILE_PATH>
# Expected: FAIL ✅ (proves vulnerability exists)
```

6. **Commit Fixed Test**:
```bash
git add <TEST_FILE_PATH>
git commit -m "fix: Strengthen RED test assertions for issue #<NUMBER>"
git push origin rsolv/validate/issue-<NUMBER>
```

7. **Update Issue and Proceed to Mitigation**:
```bash
gh issue edit <ISSUE_NUMBER> --remove-label "not-validated"
gh issue edit <ISSUE_NUMBER> --add-label "validated-manually"
gh issue comment <ISSUE_NUMBER> --body "Test refined and validated. Proceeding to mitigation."

# Trigger MITIGATE phase
gh workflow run "RSOLV AutoFix" \
  -f mode=mitigate \
  -f issue_number=<ISSUE_NUMBER>
```

**Metrics**: Track test validation failure rate by vulnerability type and test framework

---

### Procedure 4: Unexpected Validation Logic Bug

**When to Use**: Tests fail on vulnerable code (correct) but still tagged `not-validated` (bug)

**Steps**:

1. **Confirm Bug**:
```bash
# Check validation result JSON
cat .rsolv/validation/issue-<NUMBER>.json | jq .

# Look for:
# {
#   "vulnerableCommit": {
#     "allPassed": false,  // Tests failed (correct)
#     "redTestsPassed": [false, false]
#   },
#   "isValidFix": false  // Should be TRUE but is FALSE (bug!)
# }
```

2. **Gather Debug Information**:
```bash
# Collect:
# - Workflow run ID
# - Validation result JSON
# - Test file content
# - Backend API response (if available in logs)

# Create debug tarball
tar czf not-validated-debug-issue-<NUMBER>.tar.gz \
  .rsolv/validation/issue-<NUMBER>.json \
  <TEST_FILE_PATH> \
  workflow-logs.txt
```

3. **Immediate Workaround**:
```bash
# Manually override validation result
gh issue edit <ISSUE_NUMBER> --remove-label "not-validated"
gh issue edit <ISSUE_NUMBER> --add-label "validated-override"
gh issue comment <ISSUE_NUMBER> --body "Validation logic bug detected. Tests correctly fail on vulnerable code but marked as not-validated. Manually overriding. Bug report filed: [link]"

# Proceed to mitigation
gh workflow run "RSOLV AutoFix" -f mode=mitigate -f issue_number=<ISSUE_NUMBER>
```

4. **Report Bug to RSOLV Engineering**:
```bash
# Create bug report
gh issue create --repo RSOLV-dev/rsolv-action \
  --title "Validation logic bug: Tests fail on vulnerable code but marked not-validated (Issue #<NUMBER>)" \
  --label bug,validation \
  --body "## Bug Description

Tests correctly detect vulnerability (fail on vulnerable code) but issue is still tagged 'not-validated'.

## Reproduction

**Issue**: <REPO>#<NUMBER>
**Workflow Run**: <RUN_ID>

## Evidence

\`\`\`json
$(cat .rsolv/validation/issue-<NUMBER>.json | jq .)
\`\`\`

## Expected Behavior

Issue should be validated (not-validated label should NOT be applied).

## Actual Behavior

Issue tagged with not-validated despite correct test behavior.

## Attachments

See debug tarball: [link to upload]
"

# Upload debug tarball as attachment
# (Manual step - attach to GitHub issue)
```

**Metrics**: Track validation logic bugs (should be rare, <1% of validations)

---

## Escalation Paths

### Level 1: Self-Service (Target: 80% resolution)

**Handles**: False positives, test generation failures with retry, simple test fixes

**Timeframe**: 0-24 hours

**Required Skills**: Basic understanding of security vulnerabilities, test frameworks

**Actions**: Follow Procedures 1-3 above

---

### Level 2: Development Team (Target: 15% escalation)

**Handles**: Complex test failures, framework-specific issues, recurring patterns

**Timeframe**: 24-72 hours

**Escalation Criteria**:
- Test generation fails after retry with `claude_max_turns=10`
- Test validation failure in complex codebase (requires deep code review)
- Recurring pattern of failures in specific file/module

**Escalation Process**:
```bash
# Tag issue for dev team review
gh issue edit <ISSUE_NUMBER> --add-label "needs-dev-review"
gh issue comment <ISSUE_NUMBER> --body "@dev-team This not-validated issue needs expert review. See analysis in previous comments."

# Post in Slack
# Channel: #rsolv-dev-triage
# Message: "Issue #<NUMBER> needs dev review - [link]"
```

**SLA**: Dev team triages within 24 hours, resolves within 72 hours

---

### Level 3: RSOLV Engineering (Target: 5% escalation)

**Handles**: Bugs in RSOLV platform, missing framework support, API issues

**Timeframe**: 72 hours - 7 days

**Escalation Criteria**:
- Validation logic bug (Procedure 4)
- Backend API errors (5xx responses, timeouts)
- Unsupported test framework needed
- AST integration failures in supported framework

**Escalation Process**:
```bash
# Create bug report in rsolv-action repo
gh issue create --repo RSOLV-dev/rsolv-action \
  --title "not-validated issue requiring platform fix: [brief description]" \
  --label bug \
  --body "[Use template from Procedure 4]"

# Tag for on-call if urgent
gh issue edit <ISSUE_NUMBER> --add-label "urgent,platform-bug"

# Email
# To: engineering@rsolv.dev
# Subject: Urgent: Validation failure requiring platform fix (Issue #<NUMBER>)
```

**SLA**: On-call acknowledges within 4 hours, initial response within 24 hours

---

## Metrics and Reporting

### Weekly Not-Validated Report

Run every Monday:

```bash
#!/bin/bash
# weekly-not-validated-report.sh

echo "# Not-Validated Report - Week of $(date +%Y-%m-%d)"
echo ""

echo "## Summary"
TOTAL=$(gh issue list --label rsolv:automate --state all --created ">=7 days ago" --json number | jq length)
NOT_VALIDATED=$(gh issue list --label not-validated --state all --created ">=7 days ago" --json number | jq length)
RATE=$(echo "scale=2; $NOT_VALIDATED / $TOTAL * 100" | bc)

echo "- Total issues scanned (last 7 days): $TOTAL"
echo "- Not-validated issues: $NOT_VALIDATED"
echo "- Not-validated rate: ${RATE}% (target: <15%)"
echo ""

echo "## Breakdown by Type"
FALSE_POSITIVE=$(gh issue list --label "not-validated,false-positive" --state all --created ">=7 days ago" --json number | jq length)
TEST_GEN_FAIL=$(gh issue list --label "not-validated" --state open --json body -q '.[] | select(.body | contains("test generation failed"))' | wc -l)
TEST_VAL_FAIL=$(expr $NOT_VALIDATED - $FALSE_POSITIVE - $TEST_GEN_FAIL)

echo "- False positives: $FALSE_POSITIVE ($(echo "scale=1; $FALSE_POSITIVE / $NOT_VALIDATED * 100" | bc)%)"
echo "- Test generation failures: $TEST_GEN_FAIL ($(echo "scale=1; $TEST_GEN_FAIL / $NOT_VALIDATED * 100" | bc)%)"
echo "- Test validation failures: $TEST_VAL_FAIL ($(echo "scale=1; $TEST_VAL_FAIL / $NOT_VALIDATED * 100" | bc)%)"
echo ""

echo "## Resolution Status"
RESOLVED=$(gh issue list --label not-validated --state closed --closed ">=7 days ago" --json number | jq length)
OPEN=$(gh issue list --label not-validated --state open --created ">=7 days ago" --json number | jq length)

echo "- Resolved: $RESOLVED"
echo "- Still open: $OPEN"
echo "- Resolution rate: $(echo "scale=1; $RESOLVED / ($RESOLVED + $OPEN) * 100" | bc)% (target: >80%)"
echo ""

echo "## Action Items"
if (( $(echo "$RATE > 15" | bc -l) )); then
  echo "⚠️  Not-validated rate is above target (15%). Investigation needed."
fi

if (( $(echo "$RESOLVED / ($RESOLVED + $OPEN) < 0.8" | bc -l) )); then
  echo "⚠️  Resolution rate is below target (80%). Increase triage efforts."
fi

echo ""
echo "## Top Issues (Open, Not-Validated)"
gh issue list --label not-validated --state open --limit 10 --json number,title,createdAt \
  | jq -r '.[] | "- #\(.number): \(.title) (created: \(.createdAt[0:10]))"'
```

**Distribution**: Email to security team, post in #rsolv-metrics Slack channel

---

### Monthly Trends Dashboard

Track over time:

1. **Not-Validated Rate Trend**:
```bash
# Generate data for last 12 months
for i in {0..11}; do
  START=$(date -d "$i months ago" +%Y-%m-01)
  END=$(date -d "$((i-1)) months ago" +%Y-%m-01)

  TOTAL=$(gh issue list --label rsolv:automate --state all --created "$START..$END" --json number | jq length)
  NOT_VAL=$(gh issue list --label not-validated --state all --created "$START..$END" --json number | jq length)

  echo "$START,$TOTAL,$NOT_VAL"
done > not-validated-trend.csv

# Import into Excel/Google Sheets for visualization
```

2. **Resolution Time Distribution**:
```bash
# Calculate time from not-validated tag to resolution
gh issue list --label not-validated --state closed --limit 100 --json number,createdAt,closedAt \
  | jq -r '.[] | "\(.number),\(.createdAt),\(.closedAt)"' \
  | while IFS=, read -r num created closed; do
      CREATED_TS=$(date -d "$created" +%s)
      CLOSED_TS=$(date -d "$closed" +%s)
      HOURS=$(( (CLOSED_TS - CREATED_TS) / 3600 ))
      echo "$num,$HOURS"
    done > resolution-times.csv

# Calculate p50, p95, p99
```

3. **False Positive Rate by Vulnerability Type**:
```bash
# Group false positives by vulnerability type
gh issue list --label "not-validated,false-positive" --state all --limit 500 --json title \
  | jq -r '.[].title' \
  | grep -oP '(SQL injection|XSS|CSRF|Path traversal|Command injection)' \
  | sort | uniq -c | sort -rn
```

---

## Related Documents

- [Validation Troubleshooting Guide](VALIDATION-TROUBLESHOOTING.md) - Detailed diagnostic procedures
- [Integration Patterns](INTEGRATION-PATTERNS.md) - Common patterns and edge cases
- [RFC-060 Completion Report](../../RFCs/RFC-060-COMPLETION-REPORT.md) - Architecture details
- [ADR-031: AST Integration Architecture](../../ADRs/ADR-031-AST-TEST-INTEGRATION.md) - Implementation details

---

## Version History

- **v1.0** (2025-10-15): Initial runbook for RFC-060 v3.7.54 + Amendment 001
- **Next review**: 2025-11-01 (after 6-week monitoring period)

---

## Contact

**Questions or feedback on this runbook?**

- **Slack**: #rsolv-engineering
- **Email**: engineering@rsolv.dev
- **Docs**: https://docs.rsolv.dev
