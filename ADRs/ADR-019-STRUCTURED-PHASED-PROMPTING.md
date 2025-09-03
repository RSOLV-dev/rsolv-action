# ADR-019: Structured Phased Prompting for Claude Code SDK

## Status
**Accepted** - 2025-08-03

## Context

During the RSOLV demo customer journey testing, we discovered that Claude Code SDK was consistently generating JSON solutions without actually editing files first. Analysis of workflow runs showed patterns like:

```
Solution found with 1 file(s) to change
No files were modified
```

This indicated Claude was providing theoretical fixes in JSON format but not using the Edit/MultiEdit tools to make actual file changes, defeating the purpose of our git-based editing approach (ADR-012).

### Root Cause Analysis

Investigation revealed that Claude was following the path of least resistance - when asked to both edit files AND provide JSON, it would skip directly to JSON generation because:

1. The prompt allowed both actions without enforcing order
2. JSON generation was simpler than locating and editing files
3. No validation occurred between editing and JSON generation phases

### SDK Limitations

The Claude Code SDK's `query()` function doesn't support interactive back-and-forth conversations. The `maxTurns` parameter allows Claude to take multiple autonomous turns, but we cannot inject new prompts mid-conversation to guide behavior.

## Decision

We will implement **Structured Phased Prompting** - a single-query approach that guides Claude through distinct, sequential phases with explicit completion markers.

### Implementation Details

1. **Two-Phase Structure**:
   - **Phase 1: File Editing (Mandatory)** - Claude must use Edit/MultiEdit tools to fix vulnerabilities
   - **Phase 2: JSON Summary (Only After Phase 1)** - Claude provides JSON only after confirming Phase 1 completion

2. **Phase Completion Markers**:
   - Claude must explicitly state "PHASE 1 COMPLETE: Files have been edited"
   - This marker serves as a checkpoint before proceeding to Phase 2

3. **Validation Logic**:
   - Parse Claude's messages to detect:
     - Tool usage (Edit/MultiEdit)
     - Phase completion markers
     - JSON generation
   - Return specific errors if phases aren't completed correctly

4. **Configuration**:
   - New option: `useStructuredPhases` (default: true as of v2.2.1)
   - Can be disabled via workflow: `use_structured_phases: 'false'` (not recommended)
   - Default changed to true after validating effectiveness in production

### Example Prompt Structure

```
You MUST complete this task in TWO distinct phases:

## PHASE 1: FILE EDITING (MANDATORY - DO THIS FIRST)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
1. Locate the vulnerability
2. Use Edit or MultiEdit tools to fix the code
3. Verify changes with Read tool
4. Say "PHASE 1 COMPLETE: Files have been edited"

⚠️ You MUST complete Phase 1 before proceeding to Phase 2.

## PHASE 2: JSON SUMMARY (ONLY AFTER PHASE 1)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Only after confirming Phase 1, provide the JSON summary.
```

## Consequences

### Positive

1. **Enforces Correct Behavior**: Files are actually edited before JSON generation
2. **Clear Success Criteria**: Phase markers provide unambiguous completion signals
3. **Better Error Messages**: Can identify exactly which phase failed
4. **Production Ready**: Set as default behavior after validation
5. **Single Query**: Works within SDK limitations without requiring multiple calls
6. **Measurable**: Can track phase completion rates for metrics
7. **Proven Effectiveness**: Solves the "JSON without editing" problem consistently

### Negative

1. **Increased Prompt Complexity**: More detailed instructions may use more tokens
2. **Rigid Structure**: Less flexibility in how Claude approaches the problem
3. **Potential for False Positives**: Claude might state completion without actually editing
4. **Learning Curve**: Requires Claude to adapt to new structured format

### Neutral

1. **Verbose Output**: Claude will generate phase completion messages
2. **Additional Parsing**: Need to parse messages for phase markers
3. **Configuration Option**: Another setting to document and maintain

## Implementation

### Test-Driven Development

Following TDD methodology:
1. **RED**: Written 17 tests documenting expected behavior
2. **GREEN**: Implemented phase detection and validation
3. **REFACTOR**: Cleaned up TypeScript types and accessibility

### Key Components

1. **PhaseStatus Interface**: Tracks phase1Complete, filesEdited, jsonProvided, success
2. **constructStructuredPhasedPrompt()**: Builds the two-phase prompt
3. **parsePhaseCompletion()**: Detects phase markers and tool usage
4. **Integration**: In generateSolutionWithGit() when useStructuredPhases is enabled

### Metrics to Track

- Phase 1 completion rate
- Phase 2 completion rate  
- Files edited vs files in JSON
- Time to phase completion
- Success rate improvement

## Alternatives Considered

1. **Two Separate Query Calls**: Would lose context between calls
2. **Checkpoint-Based Approach**: More complex with multiple checkpoints
3. **Tool Restriction**: Disable JSON generation until files edited (not possible with SDK)
4. **Post-Processing Validation**: Reject JSON if files weren't edited (doesn't fix root cause)

## Related ADRs

- ADR-012: Git-Based Solution Generation - This enhances git-based editing
- ADR-017: Service Consolidation Architecture - Aligns with unified processing
- ADR-018: AST Analysis Deferred Decision - Complementary validation approach

## References

- [Claude Code SDK Documentation](https://github.com/anthropics/claude-code)
- [Original Issue Analysis](../docs/REVISED-TWO-PHASE-PLAN.md)
- [Test Suite](../src/ai/adapters/__tests__/structured-phases.test.ts)