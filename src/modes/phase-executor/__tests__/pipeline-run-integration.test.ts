/**
 * Tests for PipelineRun Channel integration in executeAllPhases (RFC-124).
 *
 * Verifies:
 * - Channel connects and creates run
 * - Issues registered with Coordinator after scan
 * - pipelineRunId passed through storePhaseData
 * - Channel failure is non-fatal (graceful degradation)
 * - Run completed/failed via Channel
 */

import { describe, test, expect, beforeEach, afterEach, vi } from 'vitest';
import { PhaseExecutor } from '../index.js';
import type { ActionConfig } from '../../../types/index.js';

// Track Channel method calls
const channelCalls = {
  connect: vi.fn().mockResolvedValue(undefined),
  createRun: vi.fn().mockResolvedValue({ runId: 'test-run-id-123' }),
  transitionStatus: vi.fn().mockResolvedValue(undefined),
  registerIssues: vi.fn().mockResolvedValue(undefined),
  reportSessionStarted: vi.fn().mockResolvedValue(undefined),
  complete: vi.fn().mockResolvedValue(undefined),
  fail: vi.fn().mockResolvedValue(undefined),
  disconnect: vi.fn(),
  isConnected: vi.fn().mockReturnValue(true),
};

// Mock PipelineRunChannel
vi.mock('../../../pipeline/pipeline-run-channel.js', () => ({
  PipelineRunChannel: vi.fn().mockImplementation(() => channelCalls),
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

// Mock ValidationClient
vi.mock('../../../pipeline/validation-client.js', () => ({
  ValidationClient: vi.fn().mockImplementation(() => ({
    runValidation: vi.fn().mockResolvedValue({
      validated: true,
      test_path: 'spec/vulnerability_spec.rb',
      test_code: 'it { expect... }',
      classification: 'validated',
      framework: 'rspec',
      cwe_id: 'CWE-79',
    }),
  })),
}));

// Mock child_process
vi.mock('child_process', () => ({
  execSync: vi.fn().mockReturnValue('abc123def456\n'),
  exec: vi.fn(),
}));

// Mock label manager
vi.mock('../utils/label-manager.js', () => ({
  applyValidationLabels: vi.fn().mockResolvedValue(undefined),
}));

// Mock test runner
vi.mock('../../../ai/test-runner.js', () => ({
  TestRunner: vi.fn().mockImplementation(() => ({
    ensureRuntime: vi.fn().mockResolvedValue(undefined),
  })),
}));

describe('PhaseExecutor - PipelineRun Channel Integration', () => {
  let executor: PhaseExecutor;
  let mockConfig: ActionConfig;
  let mockScanOrchestrator: { performScan: ReturnType<typeof vi.fn> };

  beforeEach(async () => {
    vi.clearAllMocks();
    process.env.RSOLV_TESTING_MODE = 'true';

    // Reset channel call mocks
    Object.values(channelCalls).forEach(fn => fn.mockClear());
    channelCalls.connect.mockResolvedValue(undefined);
    channelCalls.createRun.mockResolvedValue({ runId: 'test-run-id-123' });
    channelCalls.isConnected.mockReturnValue(true);

    const { ScanOrchestrator } = await import('../../../scanner/index.js');
    mockScanOrchestrator = new (ScanOrchestrator as ReturnType<typeof vi.fn>)();

    const githubApi = await import('../../../github/api.js');
    const mockGetIssue = githubApi.getIssue as ReturnType<typeof vi.fn>;
    mockGetIssue.mockImplementation((owner: string, name: string, number: number) => ({
      id: number,
      number,
      title: `Security vulnerability #${number}`,
      body: 'CWE-79 vulnerability found',
      labels: ['rsolv:detected'],
      assignees: [],
      repository: { owner, name, fullName: `${owner}/${name}`, defaultBranch: 'main' },
      source: 'github',
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
    }));

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
      fixValidation: { enabled: false }
    } as ActionConfig;

    executor = new PhaseExecutor(mockConfig);
  });

  afterEach(() => {
    delete process.env.RSOLV_TESTING_MODE;
  });

  test('executeAllPhases connects to Channel and creates run', async () => {
    mockScanOrchestrator.performScan.mockResolvedValue({
      vulnerabilities: [{ file: 'test.js', line: 1, type: 'xss' }],
      createdIssues: [{ number: 42 }],
      summary: '1 vulnerability found'
    });
    executor._setTestDependencies({ scanner: mockScanOrchestrator });

    // Mock storePhaseData to avoid real API calls
    executor.storePhaseData = vi.fn().mockResolvedValue(undefined);

    const result = await executor.executeAllPhases({
      repository: mockConfig.repository
    });

    // Channel should have been used
    expect(channelCalls.connect).toHaveBeenCalledTimes(1);
    expect(channelCalls.createRun).toHaveBeenCalledWith(
      expect.objectContaining({ mode: 'full' })
    );
    expect(channelCalls.transitionStatus).toHaveBeenCalledWith('scanning');
  });

  test('executeAllPhases registers issues after scan', async () => {
    mockScanOrchestrator.performScan.mockResolvedValue({
      vulnerabilities: [{ file: 'test.js', line: 1, type: 'xss' }],
      createdIssues: [{ number: 42 }, { number: 43 }],
      summary: '2 issues'
    });
    executor._setTestDependencies({ scanner: mockScanOrchestrator });
    executor.storePhaseData = vi.fn().mockResolvedValue(undefined);

    await executor.executeAllPhases({ repository: mockConfig.repository });

    expect(channelCalls.registerIssues).toHaveBeenCalledWith([
      { issue_number: 42, cwe_id: undefined },
      { issue_number: 43, cwe_id: undefined },
    ]);
  });

  test('executeAllPhases includes pipelineRunId in result', async () => {
    mockScanOrchestrator.performScan.mockResolvedValue({
      vulnerabilities: [{ file: 'test.js', line: 1, type: 'xss' }],
      createdIssues: [{ number: 42 }],
      summary: '1 issue'
    });
    executor._setTestDependencies({ scanner: mockScanOrchestrator });
    executor.storePhaseData = vi.fn().mockResolvedValue(undefined);

    const result = await executor.executeAllPhases({ repository: mockConfig.repository });

    expect(result.data?.pipelineRunId).toBe('test-run-id-123');
  });

  test('executeAllPhases completes run via Channel', async () => {
    mockScanOrchestrator.performScan.mockResolvedValue({
      vulnerabilities: [],
      createdIssues: [],
      summary: 'No issues'
    });
    executor._setTestDependencies({ scanner: mockScanOrchestrator });

    await executor.executeAllPhases({ repository: mockConfig.repository });

    expect(channelCalls.complete).toHaveBeenCalled();
    expect(channelCalls.disconnect).toHaveBeenCalled();
  });

  test('executeAllPhases fails run via Channel on error', async () => {
    mockScanOrchestrator.performScan.mockRejectedValue(new Error('Scan exploded'));
    executor._setTestDependencies({ scanner: mockScanOrchestrator });

    const result = await executor.executeAllPhases({ repository: mockConfig.repository });

    expect(result.success).toBe(false);
    expect(channelCalls.fail).toHaveBeenCalledWith('Scan exploded');
    expect(channelCalls.disconnect).toHaveBeenCalled();
  });

  test('executeAllPhases degrades gracefully when Channel unavailable', async () => {
    // Channel connection fails
    channelCalls.connect.mockRejectedValue(new Error('WebSocket connection refused'));

    mockScanOrchestrator.performScan.mockResolvedValue({
      vulnerabilities: [],
      createdIssues: [],
      summary: 'No issues'
    });
    executor._setTestDependencies({ scanner: mockScanOrchestrator });

    // Should still succeed without Channel
    const result = await executor.executeAllPhases({ repository: mockConfig.repository });
    expect(result.success).toBe(true);
  });

  test('pipelineRunId passed to storePhaseData calls', async () => {
    mockScanOrchestrator.performScan.mockResolvedValue({
      vulnerabilities: [{ file: 'test.js', line: 1, type: 'xss' }],
      createdIssues: [{ number: 42 }],
      summary: '1 issue'
    });
    executor._setTestDependencies({ scanner: mockScanOrchestrator });

    const storePhaseDataSpy = vi.fn().mockResolvedValue(undefined);
    executor.storePhaseData = storePhaseDataSpy;

    await executor.executeAllPhases({ repository: mockConfig.repository });

    // At least one storePhaseData call should include pipelineRunId
    const callsWithRunId = storePhaseDataSpy.mock.calls.filter(
      (call: unknown[]) => (call[2] as Record<string, unknown>)?.pipelineRunId === 'test-run-id-123'
    );

    expect(callsWithRunId.length).toBeGreaterThan(0);
  });

  test('disconnects Channel in finally block', async () => {
    mockScanOrchestrator.performScan.mockResolvedValue({
      vulnerabilities: [],
      createdIssues: [],
      summary: 'No issues'
    });
    executor._setTestDependencies({ scanner: mockScanOrchestrator });

    await executor.executeAllPhases({ repository: mockConfig.repository });

    expect(channelCalls.disconnect).toHaveBeenCalled();
  });
});
