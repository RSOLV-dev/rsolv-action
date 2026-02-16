/**
 * Test: executeValidateStandalone must NOT call analyzeIssue()
 *
 * Root cause: analyzeIssue() triggers credential exchange via getAiClient(),
 * which fails with INVALID_API_KEY for some repos. In the backend-orchestrated
 * pipeline, AI calls happen server-side — the Action only needs RSOLV API key.
 *
 * This test verifies the fix: inline scan data construction from issue body,
 * same pattern used by executeMitigate and executeMitigateStandalone.
 */

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { PhaseExecutor, ExecuteOptions } from '../index.js';
import type { ActionConfig, IssueContext } from '../../../types/index.js';

// Mock dependencies
vi.mock('../../../ai/analyzer.js', () => ({
  analyzeIssue: vi.fn().mockRejectedValue(new Error('analyzeIssue should NOT be called in backend-orchestrated path')),
}));

vi.mock('../../../pipeline/validation-client.js', () => ({
  ValidationClient: vi.fn().mockImplementation(() => ({
    runValidation: vi.fn().mockResolvedValue({
      validated: true,
      test_path: 'test/security_test.js',
      test_code: 'describe("test", () => {})',
      framework: 'mocha',
      cwe_id: 'CWE-79',
      classification: 'validated',
      test_type: 'behavioral',
      retry_count: 3,
    }),
  })),
}));

vi.mock('../../../github/api.js', () => ({
  getIssuesByLabel: vi.fn(),
  addLabels: vi.fn().mockResolvedValue(undefined),
  removeLabel: vi.fn().mockResolvedValue(undefined),
}));

vi.mock('../utils/label-manager.js', () => ({
  applyValidationLabels: vi.fn().mockResolvedValue(undefined),
}));

vi.mock('fs', () => ({
  existsSync: vi.fn().mockReturnValue(false),
  readFileSync: vi.fn().mockReturnValue('{}'),
  writeFileSync: vi.fn(),
}));

vi.mock('child_process', () => ({
  execSync: vi.fn().mockImplementation((cmd: string) => {
    if (typeof cmd === 'string' && cmd.includes('git rev-parse HEAD')) return 'abc123def456';
    if (typeof cmd === 'string' && cmd.includes('git config user.name')) return 'test';
    if (typeof cmd === 'string' && cmd.includes('git add')) return '';
    if (typeof cmd === 'string' && cmd.includes('git commit')) return '';
    return '';
  }),
}));

// Import the mocked module at module scope (Vitest hoists vi.mock)
const analyzerModule = await vi.importMock<typeof import('../../../ai/analyzer.js')>('../../../ai/analyzer.js');

describe('PhaseExecutor - No Credential Exchange in Backend Pipeline', () => {
  let executor: PhaseExecutor;
  let mockConfig: ActionConfig;
  let mockIssue: IssueContext;

  beforeEach(() => {
    vi.clearAllMocks();

    mockConfig = {
      apiKey: 'test-key',
      rsolvApiKey: 'test-rsolv-key',
      githubToken: 'test-token',
      mode: 'validate',
      aiProvider: {
        apiKey: 'test-ai-key',
        model: 'claude-3',
        maxTokens: 4000,
        useVendedCredentials: false,
      },
    } as ActionConfig;

    mockIssue = {
      id: 'issue-123',
      number: 123,
      title: 'CWE-79: XSS vulnerability in login.js',
      body: `## Security Vulnerability\n\nCWE-79 Cross-Site Scripting in #### \`app/login.js\`\n\nUser input is not sanitized.`,
      labels: ['rsolv:detected'],
      assignees: [],
      repository: {
        owner: 'RSOLV-dev',
        name: 'nodegoat-vulnerability-demo',
        fullName: 'RSOLV-dev/nodegoat-vulnerability-demo',
        defaultBranch: 'main',
      },
      source: 'github',
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
      metadata: {},
    };

    executor = new PhaseExecutor(mockConfig);
  });

  afterEach(() => {
    vi.clearAllMocks();
  });

  it('should NOT call analyzeIssue when no prior scan data exists', async () => {
    const options: ExecuteOptions = {
      issues: [mockIssue],
      usePriorScan: false,
    };

    const result = await executor.executeValidateStandalone(options);

    // The critical assertion: analyzeIssue must NOT be called
    // because it triggers credential exchange which fails
    expect(analyzerModule.analyzeIssue).not.toHaveBeenCalled();

    // Should still succeed using inline scan data
    expect(result.phase).toBe('validate');
  });

  it('should extract CWE from issue title/body for inline scan data', async () => {
    const options: ExecuteOptions = {
      issues: [mockIssue],
      usePriorScan: false,
    };

    const result = await executor.executeValidateStandalone(options);

    // Verify analyzeIssue was not called
    expect(analyzerModule.analyzeIssue).not.toHaveBeenCalled();

    // Verify the result includes CWE extracted from issue
    // For single issue, data.validation is the entry directly (not nested under issue key)
    expect(result.success).toBe(true);
    const validationData = result.data?.validation as Record<string, unknown>;
    expect(validationData).toBeDefined();

    // Check that CWE was extracted (from title: "CWE-79: XSS vulnerability")
    expect(validationData?.cwe_id).toBe('CWE-79');
    expect(validationData?.backendOrchestrated).toBe(true);
  });

  it('should set canBeFixed to true for inline scan data (backend decides)', async () => {
    // Issue with no CWE in title — should still default to canBeFixed=true
    const issueWithoutCwe: IssueContext = {
      ...mockIssue,
      title: 'Security bug in auth module',
      body: 'Found a vulnerability in the auth module',
    };

    const options: ExecuteOptions = {
      issues: [issueWithoutCwe],
      usePriorScan: false,
    };

    const result = await executor.executeValidateStandalone(options);

    // Should NOT call analyzeIssue
    expect(analyzerModule.analyzeIssue).not.toHaveBeenCalled();

    // Should still proceed (canBeFixed=true by default, backend will classify)
    expect(result.phase).toBe('validate');
  });
});
