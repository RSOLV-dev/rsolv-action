/**
 * TDD test: Verify rsolvApiKey is passed correctly to scanner during scan phase.
 *
 * Bug: phase-executor/index.ts line 348 passed `this.config.apiKey` (backwards-compat
 * alias, never populated by config loader) instead of `this.config.rsolvApiKey`.
 * This caused AST validation to silently skip on every scan.
 */

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { PhaseExecutor } from '../index.js';
import type { ActionConfig } from '../../../types/index.js';

// Mock GitHub API
vi.mock('../../../github/api.js', () => ({
  getIssue: vi.fn(),
  getIssues: vi.fn(),
  addLabels: vi.fn(),
  removeLabel: vi.fn()
}));

// Mock scanner - capture the config passed to performScan
vi.mock('../../../scanner/index.js', () => ({
  ScanOrchestrator: vi.fn().mockImplementation(() => ({
    performScan: vi.fn()
  }))
}));

describe('PhaseExecutor scan phase rsolvApiKey passing', () => {
  let executor: PhaseExecutor;
  let mockConfig: ActionConfig;
  let mockScanOrchestrator: { performScan: ReturnType<typeof vi.fn> };

  beforeEach(async () => {
    vi.clearAllMocks();
    process.env.RSOLV_TESTING_MODE = 'true';
    process.env.USE_PLATFORM_STORAGE = 'false';

    const { ScanOrchestrator } = await import('../../../scanner/index.js');
    mockScanOrchestrator = new (ScanOrchestrator as any)();

    mockConfig = {
      githubToken: 'test-token',
      rsolvApiKey: 'rsolv_test_key_123',
      // apiKey is intentionally NOT set — this mirrors real config loader behavior
      repository: {
        owner: 'test-owner',
        name: 'test-repo'
      },
      issueLabel: 'rsolv:detected',
      aiProvider: {
        provider: 'claude-code',
        model: 'test-model',
        useVendedCredentials: false,
        temperature: 0.2,
        maxTokens: 4000,
        contextLimit: 100000,
        timeout: 3600000
      },
      createIssues: false,
      useGitBasedEditing: true,
      maxIssues: 10
    } as ActionConfig;

    executor = new PhaseExecutor(mockConfig);
  });

  afterEach(() => {
    delete process.env.RSOLV_TESTING_MODE;
    delete process.env.USE_PLATFORM_STORAGE;
  });

  it('should pass rsolvApiKey (not apiKey) to performScan config', async () => {
    // Mock performScan to return valid result and capture the config
    mockScanOrchestrator.performScan.mockResolvedValue({
      vulnerabilities: [],
      createdIssues: [],
      totalFilesScanned: 0,
      summary: 'No vulnerabilities found'
    });

    // Inject the mock scanner
    executor.scanner = mockScanOrchestrator as any;

    await executor.executeScan({
      repository: mockConfig.repository
    });

    // Verify performScan was called
    expect(mockScanOrchestrator.performScan).toHaveBeenCalledTimes(1);

    // Extract the config that was passed to performScan
    const scanConfig = mockScanOrchestrator.performScan.mock.calls[0][0];

    // The key assertion: rsolvApiKey should be the actual key, NOT undefined
    expect(scanConfig.rsolvApiKey).toBe('rsolv_test_key_123');
    expect(scanConfig.rsolvApiKey).not.toBeUndefined();
  });

  it('should not pass undefined rsolvApiKey when apiKey is absent', async () => {
    // Config explicitly has no apiKey field (matching real Zod-parsed config)
    const configWithoutApiKey = {
      ...mockConfig,
      apiKey: undefined
    } as ActionConfig;

    const executorNoApiKey = new PhaseExecutor(configWithoutApiKey);

    mockScanOrchestrator.performScan.mockResolvedValue({
      vulnerabilities: [],
      createdIssues: [],
      totalFilesScanned: 0,
      summary: 'No vulnerabilities found'
    });

    executorNoApiKey.scanner = mockScanOrchestrator as any;

    await executorNoApiKey.executeScan({
      repository: configWithoutApiKey.repository
    });

    const scanConfig = mockScanOrchestrator.performScan.mock.calls[0][0];

    // rsolvApiKey must be truthy (the actual key), not undefined
    expect(scanConfig.rsolvApiKey).toBeTruthy();
    expect(scanConfig.rsolvApiKey).toBe('rsolv_test_key_123');
  });
});
