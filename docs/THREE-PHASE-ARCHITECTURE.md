# Three-Phase Architecture Documentation

## Overview

The RSOLV action now implements a three-phase architecture that separates vulnerability processing into distinct, reusable phases:

1. **SCAN** - Analyze issues and determine fixability
2. **VALIDATE** - Generate tests to prove vulnerabilities exist
3. **MITIGATE** - Apply fixes and create pull requests

Each phase can run independently or as part of a complete pipeline.

## Architecture Benefits

- **Modularity**: Each phase is independent and reusable
- **Flexibility**: Run only the phases you need
- **Persistence**: Phase data is stored and can be retrieved later
- **Testability**: Clear separation makes testing easier
- **Scalability**: Process multiple issues efficiently

## Usage Examples

### GitHub Action Usage

The three-phase architecture can be used in GitHub Actions with the `mode` input:

```yaml
name: RSOLV Security Fix
on:
  issues:
    types: [opened, labeled]

jobs:
  security-fix:
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v4
    - uses: rsolv-dev/RSOLV-action@v2
      with:
        api_key: ${{ secrets.RSOLV_API_KEY }}
        mode: 'full'  # Run all phases: scan, validate, mitigate
        issue_number: ${{ github.event.issue.number }}
```

#### Individual Phase Examples

**Scan Only** - Find vulnerabilities and create issues:
```yaml
- uses: rsolv-dev/RSOLV-action@v2
  with:
    mode: 'scan'
    api_key: ${{ secrets.RSOLV_API_KEY }}
```

**Validate Only** - Generate tests for existing issues:
```yaml
- uses: rsolv-dev/RSOLV-action@v2
  with:
    mode: 'validate'
    issue_number: ${{ github.event.issue.number }}
    api_key: ${{ secrets.RSOLV_API_KEY }}
```

**Mitigate Only** - Apply fixes using existing validation data:
```yaml
- uses: rsolv-dev/RSOLV-action@v2
  with:
    mode: 'mitigate'
    issue_number: ${{ github.event.issue.number }}
    api_key: ${{ secrets.RSOLV_API_KEY }}
```

### CLI Usage

The action also supports direct CLI invocation with mode flags:

```bash
# Run full pipeline
node dist/index.js --mode full

# Run individual phases
node dist/index.js --mode scan
node dist/index.js --mode validate --issue 123
node dist/index.js --mode mitigate --issue 123

# Alternative syntax
node dist/index.js --mode=scan
```

Environment variables are also supported:

```bash
export RSOLV_MODE=scan
export RSOLV_ISSUE_NUMBER=123
export RSOLV_API_KEY=your_key_here
node dist/index.js
```

### Programmatic Usage

### Full Pipeline Mode

Run all three phases sequentially:

```typescript
const executor = new PhaseExecutor(config);
const result = await executor.executeThreePhaseForIssue(issue);

// Result contains data from all phases
console.log(result.data.scan);      // Scan analysis
console.log(result.data.validation); // Generated tests
console.log(result.data.mitigation); // Fix and PR details
```

### Individual Phase Execution

#### Scan Phase Only

```typescript
const scanResult = await executor.executeScanForIssue(issue);

if (scanResult.data.canBeFixed) {
  console.log('Issue can be automatically fixed');
  console.log('Files to modify:', scanResult.data.analysisData.filesToModify);
}
```

#### Validate Phase Only

```typescript
// Option 1: Validate after scan
const validateResult = await executor.executeValidateForIssue(issue, scanData);

// Option 2: Standalone validation
const result = await executor.execute('validate', {
  issues: [issue1, issue2],
  runTests: true,
  postComment: true,
  format: 'markdown'
});
```

#### Mitigate Phase Only

```typescript
// Requires scan and validation data
const mitigateResult = await executor.executeMitigateForIssue(
  issue,
  scanData,
  validationData
);

console.log('PR created:', mitigateResult.data.pullRequestUrl);
```

## Mode Selection

The `execute()` method provides a unified interface for all modes:

```typescript
// Scan mode
await executor.execute('scan', { issue });

// Validate mode with multiple issues
await executor.execute('validate', {
  issues: [issue1, issue2],
  format: 'json'
});

// Mitigate mode
await executor.execute('mitigate', {
  issue,
  validationData
});

// Three-phase pipeline
await executor.execute('three-phase', { issue });
```

## Phase Data Persistence

Phase results are automatically stored using the PhaseDataClient:

```typescript
// Data is stored with a unique key
const key = `${repo}-${issueNumber}-${phase}`;

// Retrieve previous results
const phaseData = await phaseDataClient.retrievePhaseResults(
  repo,
  issueNumber,
  commitSha
);
```

## Output Formats

### Validation Reports

Validation mode supports multiple output formats:

- **Markdown**: Human-readable report with test details
- **JSON**: Structured data for programmatic processing
- **GitHub Actions**: Annotations for CI/CD integration

```typescript
// Markdown format
const result = await executor.execute('validate', {
  issues,
  format: 'markdown'
});

// JSON format for API responses
const result = await executor.execute('validate', {
  issues,
  format: 'json'
});
```

## Error Handling

Each phase includes comprehensive error handling:

```typescript
const result = await executor.executeScanForIssue(issue);

if (!result.success) {
  console.error('Scan failed:', result.error);
  
  // Check for specific error conditions
  if (result.error?.includes('Uncommitted changes')) {
    console.log('Please commit your changes first');
  }
}
```

## GitHub Action Integration

Use the three-phase architecture in GitHub Actions:

```yaml
- name: Run RSOLV Three-Phase
  uses: rsolv/action@v1
  with:
    mode: 'three-phase'
    github-token: ${{ secrets.GITHUB_TOKEN }}
    anthropic-api-key: ${{ secrets.ANTHROPIC_API_KEY }}
```

Or run specific phases:

```yaml
- name: Validate Only
  uses: rsolv/action@v1
  with:
    mode: 'validate'
    issues: '1,2,3'
    format: 'github-actions'
```

## Configuration

### Phase-Specific Configuration

```typescript
const config: ActionConfig = {
  // Scan phase config
  enableSecurityAnalysis: true,
  
  // Validate phase config
  testGeneration: {
    enabled: true,
    framework: 'jest',
    validateFixes: true
  },
  
  // Mitigate phase config
  fixValidation: {
    enabled: true,
    maxIterations: 3,
    timeout: 600000
  }
};
```

## Best Practices

1. **Always scan first**: The scan phase determines if an issue can be fixed
2. **Validate before mitigating**: Tests ensure fixes actually work
3. **Use phase data**: Leverage stored results to avoid redundant processing
4. **Handle partial failures**: Some issues may not be fixable
5. **Monitor timeouts**: Set appropriate timeouts for long-running operations

## Troubleshooting

### Common Issues

**Issue**: "Uncommitted changes detected"
- **Solution**: Commit or stash changes before running scan

**Issue**: "Test generation failed"
- **Solution**: Check AI provider configuration and API limits

**Issue**: "Fix validation failed after max iterations"
- **Solution**: Increase `maxIterations` or review issue complexity

## Migration from Legacy Mode

If you're migrating from the legacy `fix` mode:

```typescript
// Old way (deprecated)
await processIssueWithGit(issue, config);

// New way
const executor = new PhaseExecutor(config);
await executor.executeThreePhaseForIssue(issue);
```

## Performance Considerations

- **Batch processing**: Validate multiple issues together
- **Phase caching**: Reuse scan results when possible
- **Timeout configuration**: Adjust based on repository size
- **Parallel execution**: Process independent issues concurrently

## Observability & Debugging

### Observability Data Storage

Phase execution automatically stores observability data in `.rsolv/observability/`:

```bash
.rsolv/observability/
├── failures/      # Validation/mitigation failures with metadata
├── retries/       # Retry attempt logs with error details
├── trust-scores/  # Trust score calculations and metadata
└── timelines/     # Execution timelines with phase transitions
```

### Trust Score Interpretation

Trust scores indicate fix confidence:

- **100**: Perfect fix (pre-test failed → post-test passed)
- **50**: Test issue or false positive (both tests passed)
- **0**: Fix failed or broke functionality (post-test failed)

### Quick Debugging

Check recent phase activity:
```bash
# View observability data
ls -lh .rsolv/observability/*/

# Check trust scores
find .rsolv/observability/trust-scores -name "*.json" -exec jq '{issue: .issueNumber, score: .trustScore}' {} \;

# View execution timelines
find .rsolv/observability/timelines -name "*.json" -exec jq '.totalDurationMs' {} \;
```

### Common Troubleshooting

**Phase data not stored?**
```bash
# Check if platform storage is disabled
echo $USE_PLATFORM_STORAGE  # Should be 'false' for local storage

# Verify observability directories exist
ls -la .rsolv/observability/
```

**Tests pass on vulnerable code?**
```bash
# Check validation results
cat .rsolv/validation/issue-*.json | jq '.validated'

# Review false positive reason
cat .rsolv/phase-data/*-validation.json | jq '.data.validate | to_entries[] | .value.falsePositiveReason'
```

**Validation branch missing?**
```bash
# List validation branches
git branch -a | grep rsolv/validate

# Check phase data for branch name
cat .rsolv/phase-data/*-validation.json | jq '.data.validate | to_entries[] | .value.branchName'
```

### SQL Queries (Platform Storage)

When using platform storage (PostgreSQL), query phase data:

```sql
-- Get all validations for a repository
SELECT issue_number, data->'validate' as validation_data, timestamp
FROM phase_data
WHERE repo = 'owner/repo' AND phase = 'validation'
ORDER BY timestamp DESC;

-- Find failed validations
SELECT repo, issue_number, data->'validate'->issue_number::text->>'falsePositiveReason'
FROM phase_data
WHERE phase = 'validation'
  AND (data->'validate'->issue_number::text->>'validated')::boolean = false;

-- Calculate trust score statistics
SELECT repo, AVG((data->'validate'->issue_number::text->'testExecutionResult'->>'passed')::int * 100)
FROM phase_data
WHERE phase = 'validation'
GROUP BY repo;
```

### Structured Logging

Logs include structured metadata for filtering:

```bash
# View phase execution logs
grep "\[PHASE:" logs/rsolv-action.log

# View test execution
grep "\[TEST\]" logs/rsolv-action.log

# View trust scores
grep "\[TRUST-SCORE\]" logs/rsolv-action.log

# Filter by issue
grep "Issue #123" logs/rsolv-action.log
```

### Performance Analysis

Identify bottlenecks:
```bash
# Find slowest phases
find .rsolv/observability/timelines -name "*.json" -exec jq '.phases | max_by(.durationMs)' {} \;

# Calculate average execution time
find .rsolv/observability/timelines -name "*.json" -exec jq '.totalDurationMs' {} \; | \
  awk '{sum+=$1; count++} END {print "Avg: " sum/count "ms"}'
```

## Future Enhancements

- Platform API integration for centralized storage
- Advanced analytics and reporting
- Machine learning for pattern detection
- Cross-repository vulnerability tracking