/**
 * Integration test for executeAllPhases orchestration
 * Tests scan phase behavior (issue limiting, error handling).
 *
 * Backend validation/mitigation orchestration is tested in:
 * - vulnerabilities-handoff.test.ts (VALIDATE storage)
 * - mitigate-for-issue-storage.test.ts (MITIGATE storage)
 */

import { describe, test, expect, beforeEach, afterEach, vi } from 'vitest';
import { PhaseExecutor } from '../index.js';
import type { ActionConfig } from '../../../types/index.js';

// Mock GitHub API
vi.mock('../../../github/api.js', () => ({
  getIssue: vi.fn(),
  getIssues: vi.fn(),
  addLabels: vi.fn(),
  removeLabel: vi.fn()
}));

// Mock scanner
vi.mock('../../../scanner/index.js', () => ({
  ScanOrchestrator: vi.fn().mockImplementation(() => ({
    performScan: vi.fn()
  }))
}));

describe('PhaseExecutor - executeAllPhases Integration', () => {
  let executor: PhaseExecutor;
  let mockConfig: ActionConfig;
  let mockGetIssue: ReturnType<typeof vi.fn>;
  let mockScanOrchestrator: { performScan: ReturnType<typeof vi.fn> };

  beforeEach(async () => {
    vi.clearAllMocks();
    process.env.RSOLV_TESTING_MODE = 'true';

    const githubApi = await import('../../../github/api.js');
    mockGetIssue = githubApi.getIssue as ReturnType<typeof vi.fn>;

    const { ScanOrchestrator } = await import('../../../scanner/index.js');
    mockScanOrchestrator = new (ScanOrchestrator as any)();

    mockConfig = {
      githubToken: 'test-token',
      repository: {
        owner: 'RSOLV-dev',
        name: 'nodegoat-vulnerability-demo'
      },
      issueLabel: 'rsolv:detected',
      rsolvApiKey: 'test-api-key',
      maxIssues: 2,
      aiProvider: {
        name: 'claude-code',
        useVendedCredentials: true
      },
      fixValidation: {
        enabled: false
      }
    } as ActionConfig;

    executor = new PhaseExecutor(mockConfig);
  });

  afterEach(() => {
    delete process.env.RSOLV_TESTING_MODE;
  });

  test('should respect maxIssues configuration', async () => {
    mockConfig.maxIssues = 2;
    executor = new PhaseExecutor(mockConfig);

    mockScanOrchestrator.performScan.mockResolvedValue({
      vulnerabilities: Array(10).fill({ file: 'test.js', line: 1, type: 'xss' }),
      createdIssues: [
        { number: 301, url: 'https://github.com/RSOLV-dev/nodegoat/issues/301' },
        { number: 302, url: 'https://github.com/RSOLV-dev/nodegoat/issues/302' }
      ],
      summary: '10 vulnerabilities found, 2 issues created (limited by max_issues)'
    });

    executor._setTestDependencies({ scanner: mockScanOrchestrator });

    await executor.executeAllPhases({
      repository: mockConfig.repository
    });

    expect(mockScanOrchestrator.performScan).toHaveBeenCalledWith(
      expect.objectContaining({
        maxIssues: 2
      })
    );
    expect(mockGetIssue).toHaveBeenCalledTimes(2);
  });

  test('should handle scan phase failure gracefully', async () => {
    mockScanOrchestrator.performScan.mockRejectedValue(new Error('Scan failed'));
    executor._setTestDependencies({ scanner: mockScanOrchestrator });

    const result = await executor.executeAllPhases({
      repository: mockConfig.repository
    });

    expect(result.success).toBe(false);
    expect(result.phase).toBe('scan');
    expect(result.error).toContain('Scan failed');
    expect(mockGetIssue).not.toHaveBeenCalled();
  });
});
