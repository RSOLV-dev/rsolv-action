#!/bin/bash
# Quick script to identify and help fix claude-code adapter test issues

echo "=== Claude Code Adapter Test Fix ==="
echo
echo "The issue: Tests are calling adapter methods with wrong signatures"
echo "The fix: Update tests to match actual implementation"
echo

# Run test and capture detailed output
NODE_OPTIONS="--max-old-space-size=4096" npx vitest run \
  src/ai/adapters/__tests__/claude-code.test.ts \
  --reporter=verbose 2>&1 | grep -E "FAIL|PASS|should" | head -20

echo
echo "Summary of issues:"
echo "- Test calls: adapter.generateSolution(issue, files, {})"
echo "- Actual signature: generateSolution(issueContext, analysis, enhancedPrompt?)"
echo
echo "All tests need to be updated to use proper IssueContext and IssueAnalysis objects"