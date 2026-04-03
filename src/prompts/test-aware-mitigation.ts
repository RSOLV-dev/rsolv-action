/**
 * Test-Aware Mitigation Prompt Templates
 * RFC-060 Phase 3.2: Templates for Claude prompts with test context
 */

export interface TestContext {
  testPath: string;
  testContent: string;
  testFramework?: string;
  testCommand?: string;
}

export interface IssueContext {
  issueId: string;
  title: string;
  description: string;
}

/**
 * Build a test-aware prompt for Claude with RED test context
 */
export function buildTestAwarePrompt(
  issue: IssueContext,
  testContext: TestContext,
  basePrompt?: string
): string {
  const prompt = basePrompt || `Fix the security vulnerability for issue ${issue.issueId}: "${issue.title}"

Issue Description:
${issue.description}`;

  return `${prompt}

The following test validates the expected behavior:
Test file: ${testContext.testPath}
${testContext.testFramework ? `Framework: ${testContext.testFramework}` : ''}
${testContext.testCommand ? `Run command: ${testContext.testCommand}` : ''}

\`\`\`javascript
${testContext.testContent}
\`\`\`

This test currently FAILS (RED phase) and must PASS after your fix.

Requirements:
1. Your fix must make this test pass
2. Preserve all existing behavioral contracts
3. Make minimal, incremental changes
4. The fix should address the root cause, not just the symptoms
`;
}

/**
 * Build trust score explanation
 */
export function getTrustScoreExplanation(preTestPassed: boolean, postTestPassed: boolean, score: number): string {
  if (!preTestPassed && postTestPassed) {
    return `Trust Score: ${score}/100 - Perfect fix! Test failed before fix and passes after.`;
  } else if (preTestPassed && postTestPassed) {
    return `Trust Score: ${score}/100 - Warning: Test was already passing. Possible false positive.`;
  } else if (!preTestPassed && !postTestPassed) {
    return `Trust Score: ${score}/100 - Fix did not work. Test still failing.`;
  } else {
    return `Trust Score: ${score}/100 - Critical: Fix broke the test that was passing.`;
  }
}