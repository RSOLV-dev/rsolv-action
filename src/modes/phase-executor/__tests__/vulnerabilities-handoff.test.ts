/**
 * Test for the MITIGATE "0 validated vulnerabilities" bug fix.
 *
 * Root cause: executeAllPhases line 1291 used `issue.specificVulnerabilities || []`
 * instead of `validationData.vulnerabilities || []`, causing the phase-executor's
 * second store to overwrite validation-mode's correct store with empty vulnerabilities.
 *
 * MITIGATE reads the LATEST validation execution (ordered by inserted_at DESC),
 * which was the phase-executor's store with empty vulnerabilities.
 */

import { describe, test, expect, beforeEach, afterEach, vi } from 'vitest';
import { PhaseExecutor } from '../index.js';
import type { ActionConfig, IssueContext } from '../../../types/index.js';

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

  test('stores validationData.vulnerabilities (not issue.specificVulnerabilities) in phase data', async () => {
    // Arrange: scan creates an issue
    mockScanOrchestrator.performScan.mockResolvedValue({
      vulnerabilities: [{ file: 'app.py', line: 6, type: 'hardcoded_secrets' }],
      createdIssues: [{ number: 1, url: 'https://github.com/arubis/Student-Feedback-System/issues/1' }]
    });

    // Issue from GitHub API does NOT have specificVulnerabilities
    const mockIssue: IssueContext = {
      number: 1,
      title: 'Hardcoded secrets found',
      body: '#### `app.py`\n- **Line 6**: Hardcoded secret detected',
      labels: ['rsolv:detected'],
      repository: mockConfig.repository!,
      url: 'https://github.com/arubis/Student-Feedback-System/issues/1'
      // No specificVulnerabilities — this is what comes from GitHub API
    };

    mockGetIssue.mockResolvedValueOnce(mockIssue);

    // validateVulnerability extracts and returns vulnerabilities from issue body
    const expectedVulnerabilities = [
      { file: 'app.py', line: 6, type: 'hardcoded_secrets', cweId: 'CWE-798', confidence: 'CRITICAL' }
    ];

    const mockValidateVulnerability = vi.fn().mockResolvedValueOnce({
      issueId: 1,
      validated: true,
      vulnerabilities: expectedVulnerabilities,
      testResults: { success: true },
      branchName: 'rsolv/validate/issue-1',
      timestamp: new Date().toISOString(),
      commitHash: 'abc123'
    });

    const mockExecuteMitigate = vi.fn().mockResolvedValueOnce({
      success: true,
      phase: 'mitigate',
      data: { mitigation: { 'issue-1': { fixed: true } } }
    });

    // Spy on storePhaseData to capture what gets stored
    const storePhaseDataSpy = vi.spyOn(executor, 'storePhaseData' as any);

    executor._setTestDependencies({
      scanner: mockScanOrchestrator,
      validationMode: { validateVulnerability: mockValidateVulnerability }
    });
    executor.executeMitigate = mockExecuteMitigate;

    // Act
    await executor.executeAllPhases({ repository: mockConfig.repository });

    // Assert: storePhaseData should store vulnerabilities from validateVulnerability return
    const validationStoreCall = storePhaseDataSpy.mock.calls.find(
      (call: unknown[]) => call[0] === 'validation'
    );

    expect(validationStoreCall).toBeDefined();

    const storedData = validationStoreCall![1] as Record<string, Record<string, unknown>>;
    const issueData = storedData['issue-1'];

    expect(issueData).toBeDefined();
    expect(issueData.vulnerabilities).toEqual(expectedVulnerabilities);
    expect(issueData.vulnerabilities).toHaveLength(1);
    expect((issueData.vulnerabilities as Array<{ file: string }>)[0].file).toBe('app.py');
    expect((issueData.vulnerabilities as Array<{ cweId: string }>)[0].cweId).toBe('CWE-798');
  });

  test('does not use issue.specificVulnerabilities for storage', async () => {
    // This test ensures the bug doesn't regress — even if issue has specificVulnerabilities,
    // the stored data should come from validateVulnerability return, not from the issue.

    mockScanOrchestrator.performScan.mockResolvedValue({
      vulnerabilities: [{ file: 'app.py', line: 6, type: 'hardcoded_secrets' }],
      createdIssues: [{ number: 1, url: 'https://github.com/arubis/test/issues/1' }]
    });

    // Issue WITH specificVulnerabilities (different from what validateVulnerability returns)
    const mockIssue: IssueContext = {
      number: 1,
      title: 'Test',
      body: '#### `app.py`\n- **Line 6**: Hardcoded secret',
      labels: ['rsolv:detected'],
      repository: mockConfig.repository!,
      url: 'https://github.com/arubis/test/issues/1',
      specificVulnerabilities: [
        { file: 'WRONG.py', line: 999, type: 'wrong_type', remediation: 'wrong' }
      ]
    };

    mockGetIssue.mockResolvedValueOnce(mockIssue);

    // validateVulnerability returns DIFFERENT vulnerabilities than issue.specificVulnerabilities
    const correctVulnerabilities = [
      { file: 'app.py', line: 6, type: 'hardcoded_secrets', cweId: 'CWE-798' }
    ];

    const mockValidateVulnerability = vi.fn().mockResolvedValueOnce({
      issueId: 1,
      validated: true,
      vulnerabilities: correctVulnerabilities,
      timestamp: new Date().toISOString(),
      commitHash: 'abc123'
    });

    const mockExecuteMitigate = vi.fn().mockResolvedValue({
      success: true, phase: 'mitigate', data: {}
    });

    const storePhaseDataSpy = vi.spyOn(executor, 'storePhaseData' as any);

    executor._setTestDependencies({
      scanner: mockScanOrchestrator,
      validationMode: { validateVulnerability: mockValidateVulnerability }
    });
    executor.executeMitigate = mockExecuteMitigate;

    await executor.executeAllPhases({ repository: mockConfig.repository });

    const validationStoreCall = storePhaseDataSpy.mock.calls.find(
      (call: unknown[]) => call[0] === 'validation'
    );

    expect(validationStoreCall).toBeDefined();
    const storedData = validationStoreCall![1] as Record<string, Record<string, unknown>>;
    const issueData = storedData['issue-1'];

    // Should use validateVulnerability's return, NOT issue.specificVulnerabilities
    expect(issueData.vulnerabilities).toEqual(correctVulnerabilities);
    expect((issueData.vulnerabilities as Array<{ file: string }>)[0].file).toBe('app.py');
    expect((issueData.vulnerabilities as Array<{ file: string }>)[0].file).not.toBe('WRONG.py');
  });
});
