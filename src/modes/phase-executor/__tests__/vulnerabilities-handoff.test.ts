/**
 * Test for the MITIGATE "0 validated vulnerabilities" bug fix.
 *
 * Root cause: executeAllPhases previously used `issue.specificVulnerabilities || []`
 * instead of validation result data, causing incorrect phase data storage.
 *
 * RFC-096 Phase F.2: executeAllPhases now delegates to executeValidateForIssue
 * which uses the backend-orchestrated pipeline. This test verifies that
 * storePhaseData is called with the backend validation result, not issue properties.
 */

import { describe, test, expect, beforeEach, afterEach, vi } from 'vitest';
import { PhaseExecutor } from '../index.js';
import type { ActionConfig, IssueContext } from '../../../types/index.js';

// Mock TestRunner to prevent ensureRuntime from hanging
vi.mock('../../../ai/test-runner.js', () => ({
  TestRunner: vi.fn().mockImplementation(() => ({
    ensureRuntime: vi.fn().mockResolvedValue(undefined),
    runTests: vi.fn(),
  })),
}));

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

// Mock the validation client to return backend results
vi.mock('../../../pipeline/validation-client.js', () => ({
  ValidationClient: vi.fn().mockImplementation(() => ({
    runValidation: vi.fn().mockResolvedValue({
      validated: true,
      test_path: 'test/test_secrets.py',
      test_code: 'def test_no_hardcoded_secrets(): ...',
      framework: 'pytest',
      cwe_id: 'CWE-798',
      classification: 'validated',
      test_type: 'behavioral',
      retry_count: 2,
    }),
  })),
}));

// Mock child_process for git operations
vi.mock('child_process', () => ({
  exec: vi.fn(),
  execSync: vi.fn().mockReturnValue('abc123\n'),
}));

// RFC-124: Mock PipelineRunChannel to prevent real WebSocket connections
vi.mock('../../../pipeline/pipeline-run-channel.js', () => ({
  PipelineRunChannel: vi.fn().mockImplementation(() => ({
    connect: vi.fn().mockResolvedValue(undefined),
    createRun: vi.fn().mockResolvedValue({ runId: 'mock-run-id' }),
    transitionStatus: vi.fn().mockResolvedValue(undefined),
    registerIssues: vi.fn().mockResolvedValue(undefined),
    complete: vi.fn().mockResolvedValue(undefined),
    fail: vi.fn().mockResolvedValue(undefined),
    disconnect: vi.fn(),
    isConnected: vi.fn().mockReturnValue(true),
  })),
}));

describe('executeAllPhases vulnerabilities handoff to MITIGATE', () => {
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
        owner: 'arubis',
        name: 'Student-Feedback-System'
      },
      issueLabel: 'rsolv:detected',
      rsolvApiKey: 'test-api-key',
      maxIssues: 1,
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

  test('stores backend validation result in phase data (not issue.specificVulnerabilities)', async () => {
    // Arrange: scan creates an issue
    mockScanOrchestrator.performScan.mockResolvedValue({
      vulnerabilities: [{ file: 'app.py', line: 6, type: 'hardcoded_secrets' }],
      createdIssues: [{ number: 1, url: 'https://github.com/arubis/Student-Feedback-System/issues/1' }]
    });

    // Issue from GitHub API does NOT have specificVulnerabilities
    const mockIssue: IssueContext = {
      number: 1,
      title: 'CWE-798: Hardcoded secrets found',
      body: '#### `app.py`\n- **Line 6**: Hardcoded secret detected',
      labels: ['rsolv:detected'],
      repository: mockConfig.repository!,
      url: 'https://github.com/arubis/Student-Feedback-System/issues/1'
    };

    mockGetIssue.mockResolvedValueOnce(mockIssue);

    // Mock executeMitigate to avoid actual mitigation
    const mockExecuteMitigate = vi.fn().mockResolvedValueOnce({
      success: true,
      phase: 'mitigate',
      data: { mitigation: { 'issue-1': { fixed: true } } }
    });

    // Spy on storePhaseData to capture what gets stored
    const storePhaseDataSpy = vi.spyOn(executor, 'storePhaseData' as any);

    executor._setTestDependencies({
      scanner: mockScanOrchestrator,
    });
    executor.executeMitigate = mockExecuteMitigate;

    // Act
    await executor.executeAllPhases({ repository: mockConfig.repository });

    // Assert: storePhaseData should store backend validation result
    const validationStoreCall = storePhaseDataSpy.mock.calls.find(
      (call: unknown[]) => call[0] === 'validation'
    );

    expect(validationStoreCall).toBeDefined();

    const storedData = validationStoreCall![1] as Record<string, Record<string, unknown>>;
    // Backend path stores with issue-N key format
    const issueData = storedData['issue-1'];

    expect(issueData).toBeDefined();
    // Backend validation stores the classification and cwe_id from the backend result
    expect(issueData.validated).toBe(true);
    expect(issueData.cwe_id).toBe('CWE-798');
    expect(issueData.classification).toBe('validated');
    expect(issueData.backendOrchestrated).toBe(true);
  });

  test('does not use issue.specificVulnerabilities for storage', async () => {
    mockScanOrchestrator.performScan.mockResolvedValue({
      vulnerabilities: [{ file: 'app.py', line: 6, type: 'hardcoded_secrets' }],
      createdIssues: [{ number: 1, url: 'https://github.com/arubis/test/issues/1' }]
    });

    // Issue WITH specificVulnerabilities — should be ignored by backend path
    const mockIssue: IssueContext = {
      number: 1,
      title: 'CWE-798: Test',
      body: '#### `app.py`\n- **Line 6**: Hardcoded secret',
      labels: ['rsolv:detected'],
      repository: mockConfig.repository!,
      url: 'https://github.com/arubis/test/issues/1',
      specificVulnerabilities: [
        { file: 'WRONG.py', line: 999, type: 'wrong_type', remediation: 'wrong' }
      ]
    };

    mockGetIssue.mockResolvedValueOnce(mockIssue);

    const mockExecuteMitigate = vi.fn().mockResolvedValue({
      success: true, phase: 'mitigate', data: {}
    });

    const storePhaseDataSpy = vi.spyOn(executor, 'storePhaseData' as any);

    executor._setTestDependencies({
      scanner: mockScanOrchestrator,
    });
    executor.executeMitigate = mockExecuteMitigate;

    await executor.executeAllPhases({ repository: mockConfig.repository });

    const validationStoreCall = storePhaseDataSpy.mock.calls.find(
      (call: unknown[]) => call[0] === 'validation'
    );

    expect(validationStoreCall).toBeDefined();
    const storedData = validationStoreCall![1] as Record<string, Record<string, unknown>>;
    const issueData = storedData['issue-1'];

    // Should store backend result, NOT issue.specificVulnerabilities
    expect(issueData).toBeDefined();
    expect(issueData.validated).toBe(true);
    expect(issueData.backendOrchestrated).toBe(true);
    // The key point: the stored data comes from the backend ValidationClient,
    // not from the issue's specificVulnerabilities property
    expect(issueData.cwe_id).toBe('CWE-798');
  });
});
