# RFC-043: Enhanced Three-Phase Architecture with Validation Enrichment

**Status**: Implemented  
**Created**: 2025-08-08  
**Author**: Dylan Fitzgerald  
**Related RFCs**: RFC-041 (Three-Phase Architecture)

## Executive Summary

This RFC proposes enhancements to the three-phase architecture (SCAN → VALIDATE → MITIGATE) to improve issue quality, prevent automatic triggering of all detected vulnerabilities, and provide richer context for AI-powered fix generation. The key changes include removing auto-labeling from SCAN, enhancing VALIDATE to enrich issues with detailed vulnerability information, and updating MITIGATE to leverage validated data.

## Motivation

Current implementation issues:
1. SCAN phase auto-adds `rsolv:automate` label, triggering fixes for ALL detected issues
2. Scan-created issues lack sufficient detail for effective AI-powered mitigation
3. VALIDATE phase exists but doesn't enrich issues with specific vulnerability details
4. No clear separation between detection, validation, and mitigation concerns

## Detailed Design

### Phase 1: SCAN (Detection)

**Current Behavior**: Creates grouped issues with `rsolv:automate` label
**New Behavior**: Creates grouped issues with `rsolv:detected` label only

```typescript
// issue-creator.ts changes
interface ScanConfig {
  // Remove autoTrigger flag - never auto-label with automation trigger
  scanLabel: string;        // default: 'rsolv:detected'
  validateLabel: string;    // default: 'rsolv:validated'  
  automateLabel: string;    // default: 'rsolv:automate'
}

// Line 50 modification
labels: [
  config.scanLabel,  // Always use scan label, never automate
  'security',
  group.severity,
  'automated-scan'
]
```

### Phase 2: VALIDATE (Enrichment)

**Current Behavior**: Minimal implementation
**New Behavior**: Deep analysis with issue enrichment

```typescript
interface ValidationResult {
  issueNumber: number;
  originalIssue: IssueContext;
  validationTimestamp: Date;
  vulnerabilities: DetailedVulnerability[];
}

interface DetailedVulnerability {
  file: string;
  startLine: number;
  endLine: number;
  column?: number;
  codeSnippet: string;
  pattern: string;
  confidence: 'high' | 'medium' | 'low';
  astValidation: boolean;
  proofOfConcept?: string;
  suggestedFix?: string;
  cweId?: string;
  owasp?: string;
}
```

**Issue Update Strategy**:
- If single vulnerability: Update issue body with detailed information
- If multiple vulnerabilities: Create child issues for each, link to parent

**Workflow**:
1. Parse scan issue for file references
2. Run AST analysis on specific files
3. Validate each potential vulnerability
4. Update issue(s) with detailed findings
5. Store validation data via PhaseDataClient
6. Add `rsolv:validated` label

### Phase 3: MITIGATE (Fix Generation)

**Current Behavior**: Parses issue content directly
**New Behavior**: Uses validated data when available

```typescript
async executeMitigate(options: ExecuteOptions): Promise<ExecuteResult> {
  const { issueNumber } = options;
  
  // Check for validation data
  let validationData = await this.phaseDataClient.getValidation(issueNumber);
  
  // If no validation data but rsolv:automate was added, run validation first
  if (!validationData && !hasLabel(issue, 'rsolv:validated')) {
    logger.info('No validation found, running VALIDATE phase first');
    const validateResult = await this.executeValidate({ issueNumber });
    validationData = validateResult.data;
  }
  
  // Generate fix using validated data
  const analysis = {
    vulnerabilities: validationData.vulnerabilities,
    confidence: validationData.vulnerabilities[0]?.confidence || 'medium',
    hasAstValidation: true
  };
  
  const fix = await this.aiAdapter.generateFix(analysis);
  const pr = await createPullRequest(fix);
  
  return { success: true, data: { pr, validationUsed: true } };
}
```

### Label Strategy

| Label | Added By | Purpose |
|-------|----------|---------|
| `rsolv:detected` | SCAN | Marks issues found by scanning |
| `rsolv:validated` | VALIDATE | Marks issues with detailed validation |
| `rsolv:automate` | Manual/VALIDATE | Triggers mitigation |

### Backwards Compatibility

When `rsolv:automate` is added to an unvalidated issue:
1. System automatically runs VALIDATE first
2. Then proceeds with MITIGATE using validated data
3. This maintains the single-label workflow while improving quality

## Implementation Plan

### Phase 1: Remove Auto-labeling (Week 1)

**Day 1-2: Test Development**
- [ ] Write tests for label configuration in `issue-creator.test.ts`
- [ ] Write tests for scan workflow without auto-triggering
- [ ] Write integration tests for label behavior

**Day 3-4: Implementation**
- [ ] Update `IssueCreator` to use `scanLabel` instead of `automateLabel`
- [ ] Update default configuration in `config/index.ts`
- [ ] Update workflow files to handle new label

**Day 5: Testing & Documentation**
- [ ] Run full test suite
- [ ] Update documentation for new label behavior
- [ ] Test in demo repository

### Phase 2: Enhance VALIDATE (Week 2)

**Day 1-2: Test Development**
- [ ] Write tests for issue enrichment in `phase-executor.test.ts`
- [ ] Write tests for AST validation integration
- [ ] Write tests for multi-vulnerability handling
- [ ] Write tests for PhaseDataClient storage

**Day 3-4: Core Implementation**
- [ ] Create `ValidationEnricher` class
- [ ] Implement `executeValidate` with enrichment logic
- [ ] Add issue parsing for file extraction
- [ ] Integrate AST validator for specific analysis

**Day 5: Issue Management**
- [ ] Implement single vs multiple vulnerability logic
- [ ] Create issue update formatter
- [ ] Add child issue creation for multiple vulnerabilities
- [ ] Implement issue linking

**Day 6-7: Integration**
- [ ] Connect to PhaseDataClient for storage
- [ ] Add label management
- [ ] Integration testing
- [ ] Demo repository testing

### Phase 3: Update MITIGATE (Week 3, Days 1-2)

**Day 1: Test Development**
- [ ] Write tests for validation-aware mitigation
- [ ] Write tests for automatic validation trigger
- [ ] Write tests for backwards compatibility

**Day 2: Implementation**
- [ ] Update `executeMitigate` to check for validation
- [ ] Implement automatic validation when needed
- [ ] Update AI context with validated data
- [ ] Testing and verification

### Phase 4: Integration & Demo (Week 3, Days 3-5)

**Day 3: End-to-End Testing**
- [ ] Full three-phase flow testing
- [ ] Demo repository validation
- [ ] Performance testing
- [ ] Error case handling

**Day 4: Demo Updates**
- [ ] Update demo scripts for new flow
- [ ] Update demo documentation
- [ ] Create demo video script sections
- [ ] Test both automatic and manual flows

**Day 5: Documentation & Rollout**
- [ ] Update all documentation
- [ ] Update GitHub Action workflows
- [ ] Deploy to demo repository
- [ ] Final validation

## Testing Strategy

### Phase-Specific Testing

#### Testing SCAN Phase
```bash
# 1. Trigger scan via GitHub Actions
gh workflow run "RSOLV Security Scan" --repo <test-repo>

# 2. Verify issues created (should take ~1-2 minutes)
gh issue list --repo <test-repo> --label "rsolv:detected"

# Expected Results:
# - Multiple issues created with "rsolv:detected" label
# - NO issues have "rsolv:automate" label
# - Issues contain summary information but not detailed code

# 3. Verify issue content structure
gh issue view <issue-number> --json body | jq -r '.body'
# Should contain: Type, Severity, Total Instances, Affected Files
# Should NOT contain: Specific code snippets, line-by-line analysis
```

#### Testing VALIDATE Phase
```bash
# 1. Select a scan-created issue
ISSUE_NUM=$(gh issue list --repo <test-repo> --label "rsolv:detected" --limit 1 --json number -q '.[0].number')

# 2. Trigger validation
gh issue edit $ISSUE_NUM --repo <test-repo> --add-label "rsolv:validate"

# 3. Monitor validation workflow (should take ~2-3 minutes)
gh run watch --repo <test-repo>

# 4. Verify issue enrichment
gh issue view $ISSUE_NUM --json body,labels | jq '.'

# Expected Results:
# - Issue body updated with "## Validation Results" section
# - Specific vulnerabilities with line numbers and code snippets
# - "rsolv:validated" label added
# - If multiple vulnerabilities, child issues created

# 5. Verify PhaseDataClient storage
curl -H "Authorization: Bearer $RSOLV_API_KEY" \
  https://api.rsolv.dev/phase-data/validation/$ISSUE_NUM

# Should return validation data with specificVulnerabilities array
```

#### Testing MITIGATE Phase
```bash
# 1. Test with validated issue
VALIDATED_ISSUE=$(gh issue list --repo <test-repo> --label "rsolv:validated" --limit 1 --json number -q '.[0].number')
gh issue edit $VALIDATED_ISSUE --repo <test-repo> --add-label "rsolv:automate"

# 2. Monitor mitigation (should take ~10-15 minutes)
gh run watch --repo <test-repo>

# 3. Verify PR creation
gh pr list --repo <test-repo> --json number,title,body | jq '.[] | select(.title | contains("'$VALIDATED_ISSUE'"))'

# Expected Results:
# - PR created with reference to issue number
# - PR body mentions "Based on validated analysis"
# - Fix targets specific vulnerabilities from validation

# 4. Test auto-validation path (backwards compatibility)
UNVALIDATED_ISSUE=$(gh issue list --repo <test-repo> --label "rsolv:detected" --limit 1 --json number -q '.[0].number')
gh issue edit $UNVALIDATED_ISSUE --repo <test-repo> --add-label "rsolv:automate"

# Should automatically run VALIDATE then MITIGATE
# Check logs for "No validation found, running VALIDATE phase first"
```

### End-to-End Testing

#### Full Three-Phase Flow Test
```bash
#!/bin/bash
# e2e-three-phase-test.sh

set -e
REPO="RSOLV-dev/test-three-phase"
echo "🧪 Three-Phase Architecture E2E Test"

# Setup
echo "📋 Phase 0: Cleanup"
gh issue list --repo $REPO --state open --json number | \
  jq -r '.[].number' | \
  xargs -I {} gh issue close {} --repo $REPO 2>/dev/null || true

# SCAN Phase
echo "📋 Phase 1: SCAN"
gh workflow run "RSOLV Security Scan" --repo $REPO
echo "Waiting for scan completion..."
sleep 90

SCAN_ISSUES=$(gh issue list --repo $REPO --label "rsolv:detected" --json number,title)
echo "Created $(echo $SCAN_ISSUES | jq '. | length') issues"

# Verify no auto-labeling
AUTO_LABELED=$(gh issue list --repo $REPO --label "rsolv:automate" --json number | jq '. | length')
if [ "$AUTO_LABELED" -ne 0 ]; then
  echo "❌ ERROR: Found $AUTO_LABELED auto-labeled issues"
  exit 1
fi
echo "✅ No auto-labeling detected"

# VALIDATE Phase
echo "📋 Phase 2: VALIDATE"
ISSUE_TO_VALIDATE=$(echo $SCAN_ISSUES | jq -r '.[0].number')
echo "Validating issue #$ISSUE_TO_VALIDATE"
gh issue edit $ISSUE_TO_VALIDATE --repo $REPO --add-label "rsolv:validate"
sleep 120

# Check enrichment
VALIDATION_BODY=$(gh issue view $ISSUE_TO_VALIDATE --repo $REPO --json body -q '.body')
if [[ ! "$VALIDATION_BODY" == *"## Validation Results"* ]]; then
  echo "❌ ERROR: Issue not enriched with validation"
  exit 1
fi
echo "✅ Issue enriched with validation data"

# MITIGATE Phase
echo "📋 Phase 3: MITIGATE"
gh issue edit $ISSUE_TO_VALIDATE --repo $REPO --add-label "rsolv:automate"
echo "Waiting for PR generation (this takes 10-15 minutes)..."
sleep 600

# Check PR
PR_COUNT=$(gh pr list --repo $REPO --json number | jq '. | length')
if [ "$PR_COUNT" -eq 0 ]; then
  echo "❌ ERROR: No PR created"
  exit 1
fi
echo "✅ PR created successfully"

# Test backwards compatibility
echo "📋 Phase 4: Backwards Compatibility Test"
UNVALIDATED_ISSUE=$(echo $SCAN_ISSUES | jq -r '.[1].number')
echo "Testing direct mitigation of issue #$UNVALIDATED_ISSUE"
gh issue edit $UNVALIDATED_ISSUE --repo $REPO --add-label "rsolv:automate"
sleep 600

# Verify it got validated
if ! gh issue view $UNVALIDATED_ISSUE --repo $REPO --json labels | jq -r '.labels[].name' | grep -q "rsolv:validated"; then
  echo "❌ ERROR: Auto-validation didn't occur"
  exit 1
fi
echo "✅ Auto-validation worked"

echo "🎉 All tests passed!"
```

#### Performance Testing
```bash
# Measure phase timings
time gh workflow run "RSOLV Security Scan" --repo $REPO
# Expected: < 2 minutes for medium repo

time gh issue edit $ISSUE --repo $REPO --add-label "rsolv:validate"  
# Expected: < 3 minutes for validation

time gh issue edit $ISSUE --repo $REPO --add-label "rsolv:automate"
# Expected: < 15 minutes for mitigation
```

### Unit Tests
```typescript
// issue-creator.test.ts
describe('IssueCreator', () => {
  test('creates issues with scan label only');
  test('does not add automate label');
  test('includes proper security labels');
});

// phase-executor.test.ts  
describe('ValidationPhase', () => {
  test('enriches issue with AST analysis');
  test('creates child issues for multiple vulnerabilities');
  test('stores validation in PhaseDataClient');
  test('adds validated label');
});

describe('MitigationPhase', () => {
  test('uses validation data when available');
  test('auto-validates if needed');
  test('handles missing validation gracefully');
});
```

### Integration Tests
```typescript
describe('Three-Phase Flow', () => {
  test('scan → validate → mitigate flow');
  test('scan → direct mitigate (auto-validates)');
  test('multiple vulnerability handling');
  test('cross-platform data persistence');
});
```

### Continuous Integration Testing
```yaml
# .github/workflows/three-phase-test.yml
name: Three-Phase Architecture Test
on:
  pull_request:
    paths:
      - 'src/scanner/**'
      - 'src/modes/phase-executor/**'
  schedule:
    - cron: '0 0 * * *'  # Daily test

jobs:
  test-three-phase:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Run unit tests
        run: npm test -- --testPathPattern="phase|scan|validate|mitigate"
      
      - name: Run integration test
        run: ./scripts/e2e-three-phase-test.sh
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
          RSOLV_API_KEY: ${{ secrets.RSOLV_API_KEY }}
      
      - name: Check performance metrics
        run: |
          if [ $SCAN_TIME -gt 120 ]; then exit 1; fi
          if [ $VALIDATE_TIME -gt 180 ]; then exit 1; fi
          if [ $MITIGATE_TIME -gt 900 ]; then exit 1; fi
```

## Success Metrics

1. **Reduced False Positives**: AST validation in VALIDATE phase reduces false positives by >50%
2. **Fix Quality**: Validated issues produce successful PRs >80% of the time
3. **User Control**: No automatic fix generation for all issues
4. **Performance**: VALIDATE phase completes in <2 minutes for typical repositories
5. **Adoption**: Users adopt three-phase flow without configuration changes

## Security Considerations

1. **AST Validation**: Runs in sandboxed environment
2. **Issue Updates**: Audit trail via GitHub issue history
3. **Data Storage**: Validation data encrypted in PhaseDataClient
4. **Rate Limiting**: Respect GitHub API rate limits

## Alternatives Considered

1. **Keep Auto-labeling with Config Flag**: Rejected - too dangerous as default
2. **Store Validation in GitHub Comments**: Rejected - not cross-platform
3. **Create New Issues Instead of Updating**: Rejected - creates issue proliferation
4. **Skip Validation for Simple Vulnerabilities**: Rejected - consistency is important

## Future Enhancements

1. **Batch Validation**: Validate multiple issues in one workflow
2. **Validation Caching**: Cache AST analysis results
3. **Custom Validation Rules**: User-defined validation patterns
4. **Cross-Reference Detection**: Find related vulnerabilities across files
5. **Machine Learning**: Improve validation accuracy over time

## Migration Strategy

Since we have no existing users, we can:
1. Deploy changes directly to main branch
2. Update demo repository immediately  
3. Update all documentation simultaneously
4. No backwards compatibility maintenance needed

## Timeline

- **Week 1**: Phase 1 (Remove auto-labeling)
- **Week 2**: Phase 2 (Enhance VALIDATE)  
- **Week 3**: Phase 3 & 4 (Update MITIGATE, Integration)
- **Total**: 3 weeks

## Open Questions

None - all questions resolved during RFC discussion.

## Decision Record

- **2025-08-08**: RFC proposed and approved for implementation
- **Design Decisions**:
  - Update issue body vs comments: UPDATE BODY
  - Multiple vulnerabilities: CREATE CHILD ISSUES
  - Backwards compatibility: AUTO-VALIDATE WHEN NEEDED
  - Demo approach: SHOW BOTH FLOWS
  - Default behavior: NEW THREE-PHASE IS DEFAULT
  - Storage mechanism: USE PHASEDATACLIENT