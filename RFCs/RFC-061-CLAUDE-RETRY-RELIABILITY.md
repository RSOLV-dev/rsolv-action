# RFC-061: Claude CLI Retry Reliability

**Status:** Draft
**Created:** 2025-09-30
**Updated:** 2025-09-30
**Author:** RSOLV Team
**Related:** RFC-060 (Executable Validation Test Integration)

## Abstract

RFC-060 proposes letting Claude Code CLI autonomously handle test execution and retry logic for security vulnerability fixes. This RFC analyzes the reliability concerns discovered during testing and proposes a phased approach to ensure reproducible, observable, and trustworthy automated fix generation.

## Problem Statement

RFC-060 proposes letting Claude Code CLI autonomously handle test execution and retry logic. Programmatic testing revealed concerns:

**Test Results**:
- ✅ Claude **successfully fixed** the vulnerability
- ⚠️ Claude **claimed** to run tests but bash log showed 0 executions
- ⚠️ Claude's tool use is **non-deterministic**
- ❌ Cannot reliably **observe retry attempts** from output
- ❌ No way to **verify** Claude followed instructions

**Core Issue**: We're trusting an LLM to follow a process we can't observe or control.

## Options Analysis

### Option 1: Full External Orchestration (Maximum Control)

**Implementation**:
```typescript
class MitigationMode {
  async processIssue(issue) {
    const { files, commands } = await this.getTestMetadata();

    // WE control the loop
    for (let attempt = 1; attempt <= 3; attempt++) {
      // WE run tests before
      const beforeResults = await this.runTests(commands);
      if (!beforeResults.allFailed) {
        throw new Error('RED tests must fail initially');
      }

      // Call Claude WITHOUT retry instructions (single-shot)
      const prompt = `Fix this vulnerability. Code is in ${files.join(', ')}`;
      await this.callClaude(prompt, { maxTurns: 1 });

      // WE run tests after
      const afterResults = await this.runTests(commands);

      if (afterResults.allPassed) {
        return { success: true, attempts: attempt };
      }

      // WE decide to retry with specific feedback
      if (attempt < 3) {
        await this.addTestOutputToPrompt(afterResults);
      }
    }

    return { success: false, attempts: 3 };
  }
}
```

**Pros**:
- ✅ **100% observable** - we see every test execution
- ✅ **100% reproducible** - deterministic control flow
- ✅ **100% verifiable** - we know exactly what happened
- ✅ **Accurate metrics** - real attempt counts, timing
- ✅ **Granular control** - can adjust strategy per vulnerability type
- ✅ **Easier debugging** - clear failure points

**Cons**:
- ❌ **More complex code** - we build retry orchestration
- ❌ **Higher latency** - network roundtrips between attempts
- ❌ **Less leverage of Claude** - not using its autonomous capabilities
- ❌ **Prompt engineering burden** - need to structure feedback carefully
- ❌ **Test environment coupling** - we need test runner infrastructure

**Risk Level**: LOW - Proven approach, full control

---

### Option 2: Hybrid Verification (Recommended)

**Implementation**:
```typescript
class MitigationMode {
  async processIssue(issue) {
    const { files, commands, branch } = await this.getTestMetadata();
    await this.checkoutBranch(branch);

    // Run tests BEFORE Claude (verification)
    const beforeResults = await this.runTests(commands);
    if (!beforeResults.allFailed) {
      throw new Error('RED tests must fail - vulnerability may not exist');
    }

    // Build test-aware prompt with clear success criteria
    const prompt = `
Fix vulnerability in issue #${issue.number}

VALIDATION TESTS:
${testContents}

REQUIREMENTS (respond with structured output):
1. Run tests FIRST: ${commands.join('; ')}
2. Tests MUST fail initially
3. Apply fix
4. Re-run tests until they pass
5. Max 3 attempts

RESPOND WITH:
\`\`\`json
{
  "attempts": <number>,
  "finalStatus": "PASS|FAIL",
  "testOutputs": [<outputs from each attempt>]
}
\`\`\`
`;

    // Let Claude iterate autonomously
    const claudeResult = await this.callClaude(prompt, {
      maxTurns: 3,
      outputFormat: 'json'  // Structured output mode
    });

    // VERIFY Claude's claims
    const verificationResults = await this.runTests(commands);
    const verified = verificationResults.allPassed;

    // Store BOTH Claude's report AND our verification
    await this.storeResults({
      claudeReported: {
        attempts: claudeResult.attempts,
        status: claudeResult.finalStatus,
        testOutputs: claudeResult.testOutputs
      },
      verifiedResults: {
        testsPassed: verified,
        timestamp: new Date()
      },
      trustScore: (claudeResult.finalStatus === 'PASS') === verified ? 1.0 : 0.0
    });

    return { success: verified, attempts: claudeResult.attempts };
  }
}
```

**Pros**:
- ✅ **Leverages Claude** - uses autonomous iteration capabilities
- ✅ **Verifiable** - we confirm final state independently
- ✅ **Observable** - structured output gives visibility
- ✅ **Trust but verify** - best of both worlds
- ✅ **Adaptable** - can tune based on trust scores over time
- ✅ **Simpler than Option 1** - Claude handles retry complexity

**Cons**:
- ⚠️ **Partial observability** - can't see intermediate attempts clearly
- ⚠️ **Trust dependency** - rely on Claude's reported attempt count
- ⚠️ **Structured output** - requires Claude Code CLI to support JSON mode
- ⚠️ **Hallucination risk** - Claude may report incorrect attempt counts

**Risk Level**: MEDIUM - Balances control with leverage

---

### Option 3: Observability Hooks (Advanced Hybrid)

**Implementation**:
```typescript
// Use Claude Code CLI hooks to observe tool use
const hookScript = `
#!/bin/bash
# .claude/hooks/post-tool-use.sh
# Called after every tool use by Claude

TOOL_NAME=$1
TOOL_INPUT=$2
TOOL_OUTPUT=$3

if [[ "$TOOL_NAME" == "Bash" ]]; then
  # Log bash executions
  echo "$(date): Bash executed: $TOOL_INPUT" >> /tmp/claude-tool-log.txt

  # Detect test executions
  if [[ "$TOOL_INPUT" =~ (npm test|bundle exec rspec|pytest) ]]; then
    echo "TEST_EXECUTION:$TOOL_OUTPUT" >> /tmp/test-executions.log
  fi
fi
`;

class MitigationMode {
  async processIssue(issue) {
    // Set up hook
    await fs.writeFile('.claude/hooks/post-tool-use.sh', hookScript, { mode: 0o755 });

    const { files, commands } = await this.getTestMetadata();

    // Clear logs
    await fs.writeFile('/tmp/test-executions.log', '');

    // Let Claude iterate
    const claudeResult = await this.callClaude(testAwarePrompt, { maxTurns: 3 });

    // Parse hook logs to reconstruct what Claude did
    const toolLog = await fs.readFile('/tmp/claude-tool-log.txt', 'utf-8');
    const testExecutions = await fs.readFile('/tmp/test-executions.log', 'utf-8');

    const attempts = (testExecutions.match(/TEST_EXECUTION:/g) || []).length;

    // Verify final state
    const verified = await this.runTests(commands);

    return {
      success: verified.allPassed,
      attempts: Math.ceil(attempts / 2), // Each retry = run before + run after
      observed: true
    };
  }
}
```

**Pros**:
- ✅ **Full observability** - hooks capture all tool use
- ✅ **Leverages Claude** - still autonomous
- ✅ **Verifiable** - independent final check
- ✅ **Accurate metrics** - real tool usage data
- ✅ **Debugging** - complete audit trail

**Cons**:
- ❌ **Complex** - requires hook infrastructure
- ❌ **Brittle** - hooks could break with Claude updates
- ❌ **Platform-specific** - hooks may not work in all environments
- ❌ **Parsing complexity** - need to interpret hook outputs

**Risk Level**: MEDIUM-HIGH - Clever but complex

---

### Option 4: Prompt Engineering + Trust (Minimal Changes)

**Implementation**:
```typescript
const prompt = `
${basePrompt}

CRITICAL INSTRUCTIONS (failure = task marked incomplete):
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
1. MUST run tests BEFORE making changes
2. MUST run tests AFTER making changes
3. MUST iterate if tests fail (max 3 times)
4. MUST verify tests pass before claiming success

AT THE END, respond with exactly:
VERIFICATION COMPLETE
Attempts: [1|2|3]
Status: [PASS|FAIL]
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
`;

const result = await callClaude(prompt, { maxTurns: 3 });

// Parse structured response
const match = result.match(/Attempts: (\d+)[\s\S]*Status: (PASS|FAIL)/);
const attempts = match ? parseInt(match[1]) : 'unknown';
const claimedStatus = match?.[2];

// Verify
const verified = await this.runTests(commands);

// If mismatch, log for analysis
if ((claimedStatus === 'PASS') !== verified.allPassed) {
  logger.warn('Claude hallucinated', {
    claimed: claimedStatus,
    verified: verified.allPassed
  });
}
```

**Pros**:
- ✅ **Minimal code changes**
- ✅ **Leverages Claude fully**
- ✅ **Simple implementation**
- ✅ **Verifies final state**

**Cons**:
- ❌ **Relies on Claude following instructions** (proven unreliable in tests)
- ❌ **No visibility into intermediate steps**
- ❌ **Hallucination risk**
- ❌ **Can't trust attempt counts**

**Risk Level**: HIGH - Too dependent on Claude reliability

---

## Comparison Matrix

| Criterion | Option 1: External | Option 2: Hybrid | Option 3: Hooks | Option 4: Trust |
|-----------|-------------------|------------------|-----------------|-----------------|
| **Observability** | ⭐⭐⭐⭐⭐ | ⭐⭐⭐⭐☆ | ⭐⭐⭐⭐⭐ | ⭐⭐☆☆☆ |
| **Reproducibility** | ⭐⭐⭐⭐⭐ | ⭐⭐⭐⭐☆ | ⭐⭐⭐⭐☆ | ⭐⭐☆☆☆ |
| **Simplicity** | ⭐⭐☆☆☆ | ⭐⭐⭐⭐☆ | ⭐⭐☆☆☆ | ⭐⭐⭐⭐⭐ |
| **Claude Leverage** | ⭐☆☆☆☆ | ⭐⭐⭐⭐☆ | ⭐⭐⭐⭐☆ | ⭐⭐⭐⭐⭐ |
| **Metrics Quality** | ⭐⭐⭐⭐⭐ | ⭐⭐⭐⭐☆ | ⭐⭐⭐⭐⭐ | ⭐⭐☆☆☆ |
| **Debugging** | ⭐⭐⭐⭐⭐ | ⭐⭐⭐⭐☆ | ⭐⭐⭐⭐⭐ | ⭐⭐☆☆☆ |
| **Reliability** | ⭐⭐⭐⭐⭐ | ⭐⭐⭐⭐☆ | ⭐⭐⭐⭐☆ | ⭐⭐☆☆☆ |
| **Implementation Time** | 2-3 days | 1 day | 2-3 days | 2 hours |

---

## Recommendation: Phased Approach

### Phase 1: Hybrid Verification (Option 2) - IMMEDIATE
**Timeline**: Sprint 1 (1 week)

**Implementation**:
1. Add structured output to Claude prompts
2. Run verification tests after Claude completes
3. Store both Claude's report and our verification
4. Track trust score (agreement between Claude and verification)

**Rationale**: Balances control with Claude's capabilities, deployable quickly

### Phase 2: Add Observability Hooks (Option 3) - IF NEEDED
**Timeline**: Sprint 2-3 (if trust scores < 80%)

**Trigger**: If Phase 1 shows >20% mismatch between Claude's claims and verification

**Implementation**:
1. Add `.claude/hooks/post-tool-use.sh`
2. Parse tool execution logs
3. Reconstruct exact test execution sequence
4. Compare to Claude's reported sequence

### Phase 3: Consider Full Orchestration (Option 1) - LAST RESORT
**Timeline**: Only if Phase 2 shows systemic issues

**Trigger**: If we can't trust Claude's iteration even with hooks

## Implementation Plan (Phase 1)

### 1. Update MITIGATE Prompt Template

```typescript
// RSOLV-action/src/ai/adapters/claude-code-git.ts
const testAwarePrompt = `
Fix the security vulnerability in issue #${issue.number}

${issue.body}

VALIDATION TESTS:
${testFiles.map(f => `
File: ${f}
${fs.readFileSync(f, 'utf-8')}
`).join('\n')}

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
PROCESS (you MUST follow this exact sequence):
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

1. Run tests FIRST using Bash tool: ${testCommands.join(' && ')}
2. Verify all tests FAIL (they should - it's a vulnerability)
3. Analyze the failure output
4. Apply your fix
5. Run tests AGAIN
6. If tests fail, analyze and retry (max 2 more times)
7. Verify tests PASS before completing

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
REQUIRED RESPONSE FORMAT:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

When you're done, respond with this exact structure:

\`\`\`json
{
  "taskComplete": true,
  "attempts": <number of fix attempts: 1-3>,
  "finalStatus": "<PASS or FAIL>",
  "testExecutions": [
    {"attempt": 1, "before": "<test output>", "after": "<test output>"},
    ...
  ]
}
\`\`\`

DO NOT claim success unless tests actually pass.
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
`;
```

### 2. Update MitigationMode Handler

```typescript
// RSOLV-action/src/modes/mitigation-mode.ts
async processIssue(issue: IssueContext) {
  const metadata = await this.phaseClient.retrievePhaseResults(...);
  const { files, commands, branch } = metadata.validate[`issue-${issue.number}`].redTests;

  await this.checkoutBranch(branch);

  // Pre-verification: ensure tests fail
  logger.info('[Mitigation] Running pre-verification tests');
  const preVerification = await this.runTests(commands);

  if (!preVerification.allFailed) {
    logger.error('[Mitigation] Tests passed before fix - vulnerability may not exist');
    await this.storeResults({ success: false, reason: 'pre_verification_failed' });
    return;
  }

  // Call Claude with test-aware prompt
  logger.info('[Mitigation] Invoking Claude Code CLI');
  const claudeResult = await this.callClaudeCodeCLI(testAwarePrompt, {
    maxTurns: 3,
    parseJson: true  // Parse the JSON response
  });

  // Post-verification: run tests ourselves
  logger.info('[Mitigation] Running post-verification tests');
  const postVerification = await this.runTests(commands);

  // Calculate trust score
  const claudeClaimed = claudeResult.finalStatus === 'PASS';
  const actuallyPassed = postVerification.allPassed;
  const trustScore = claudeClaimed === actuallyPassed ? 1.0 : 0.0;

  // Store comprehensive results
  await this.phaseClient.storePhaseResults('mitigate', {
    mitigate: {
      [`issue-${issue.number}`]: {
        success: actuallyPassed,
        verificationComplete: true,
        claude: {
          reportedAttempts: claudeResult.attempts,
          reportedStatus: claudeResult.finalStatus,
          testExecutions: claudeResult.testExecutions
        },
        verification: {
          testsPassed: actuallyPassed,
          testOutputs: postVerification.outputs
        },
        trustScore,
        timestamp: new Date().toISOString()
      }
    }
  }, metadata);

  // Log trust score for monitoring
  logger.info('[Mitigation] Trust score', {
    trustScore,
    claudeClaimed,
    actuallyPassed
  });

  return { success: actuallyPassed, trustScore };
}
```

### 3. Add Trust Score Tracking

```elixir
# lib/rsolv/phases/mitigation_execution.ex
defmodule Rsolv.Phases.MitigationExecution do
  use Ecto.Schema

  schema "mitigation_executions" do
    # ... existing fields
    field :trust_score, :float  # Add this
    timestamps()
  end
end
```

### 4. Monitor Trust Scores

Add to Grafana dashboard:
```promql
# Trust score over time
avg(rsolv_mitigation_trust_score)

# Alert if trust score drops below 0.8
avg(rsolv_mitigation_trust_score) < 0.8
```

## Success Criteria

**Phase 1 Success Metrics**:
- [ ] Trust score > 80% (Claude's claims match verification)
- [ ] Test execution successful in 95% of attempts
- [ ] Clear observability in logs and metrics
- [ ] Can debug failures from stored data

**If Phase 1 succeeds**: Ship it, monitor trust scores

**If Phase 1 fails**: Implement Phase 2 (hooks) or Phase 3 (full control)

## Risk Mitigation

**For Phase 1**:
- Keep maxTurns low (3) to limit unpredictability
- Always verify final state independently
- Store Claude's full response for debugging
- Alert on low trust scores
- Manual review of failures

**Fallback Plan**:
If trust scores < 70% for 2 weeks:
- Implement Option 1 (full orchestration)
- Use Claude only for fix generation, not iteration

---

## Final Recommendation Summary

**START WITH**: Option 2 (Hybrid Verification)

**REASONING**:
1. Provides verification (addresses your concerns)
2. Leverages Claude's capabilities (simpler than full orchestration)
3. Measurable (trust scores tell us if it's working)
4. Adaptable (can move to Options 1 or 3 if needed)
5. Quick to implement (1 week)

**DECISION POINT**: After 2 weeks, review trust scores
- If >80%: Keep Phase 1
- If 70-80%: Add hooks (Phase 2)
- If <70%: Switch to full orchestration (Phase 3)
