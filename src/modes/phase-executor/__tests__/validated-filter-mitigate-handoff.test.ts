/**
 * Test for the validated filter that gates MITIGATE entry in executeAllPhases.
 *
 * Bug: executeValidateForIssue returns data nested under a dynamic key:
 *   data.validation[`issue_${N}`].validated = true
 *
 * But executeAllPhases checks:
 *   data.validation.validated  → always undefined
 *
 * This causes "0 of N issues validated" even when validation succeeds,
 * and MITIGATE is never entered.
 *
 * Observed in production: railsgoat run #16 (2026-02-27), VALIDATE succeeded
 * with rsolv:validated label applied, but MITIGATE never fired.
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

// Mock the validation client to return a successful backend result
vi.mock('../../../pipeline/validation-client.js', () => ({
  ValidationClient: vi.fn().mockImplementation(() => ({
    runValidation: vi.fn().mockResolvedValue({
      validated: true,
      test_path: 'spec/vulnerabilities/weak_password_crypto_spec.rb',
      test_code: 'RSpec.describe "CWE-916" do ... end',
      framework: 'rspec',
      cwe_id: 'CWE-916',
      classification: 'validated',
      test_type: 'behavioral',
      retry_count: 1,
    }),
  })),
}));

// Mock child_process for git operations
vi.mock('child_process', () => ({
  exec: vi.fn(),
  execSync: vi.fn().mockReturnValue('abc123\n'),
}));

describe('executeAllPhases validated filter → MITIGATE handoff', () => {
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
        name: 'railsgoat-vulnerability-demo'
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

  test('calls executeMitigate when validation succeeds with dynamic issue key', async () => {
    // Arrange: SCAN creates one issue
    mockScanOrchestrator.performScan.mockResolvedValue({
      vulnerabilities: [{ file: 'app/models/user.rb', line: 12, type: 'weak_crypto' }],
      createdIssues: [{ number: 154, url: 'https://github.com/arubis/railsgoat-vulnerability-demo/issues/154' }]
    });

    const mockIssue: IssueContext = {
      number: 154,
      title: 'CWE-916: Weak Password Hashing',
      body: '#### `app/models/user.rb`\n- **Line 12**: Uses MD5 for password hashing',
      labels: ['rsolv:detected'],
      repository: mockConfig.repository!,
      url: 'https://github.com/arubis/railsgoat-vulnerability-demo/issues/154'
    };

    mockGetIssue.mockResolvedValueOnce(mockIssue);

    // Mock executeMitigate — we want to verify it gets CALLED
    const mockExecuteMitigate = vi.fn().mockResolvedValue({
      success: true,
      phase: 'mitigate',
      data: { mitigation: { fixed: true } }
    });

    executor._setTestDependencies({
      scanner: mockScanOrchestrator,
    });
    executor.executeMitigate = mockExecuteMitigate;

    // Act
    const result = await executor.executeAllPhases({ repository: mockConfig.repository });

    // Assert: MITIGATE must be called for the validated issue
    expect(mockExecuteMitigate).toHaveBeenCalledTimes(1);
    expect(mockExecuteMitigate).toHaveBeenCalledWith(
      expect.objectContaining({ issueNumber: 154 })
    );

    // The result message should report 1 validated and 1 mitigated
    expect(result.message).toContain('1 validated');
    expect(result.message).toContain('1 mitigated');
  });

  test('reports correct validated count in result message', async () => {
    // Arrange: SCAN creates one issue
    mockScanOrchestrator.performScan.mockResolvedValue({
      vulnerabilities: [{ file: 'config/secrets.yml', line: 3, type: 'hardcoded_secrets' }],
      createdIssues: [{ number: 42, url: 'https://github.com/arubis/railsgoat-vulnerability-demo/issues/42' }]
    });

    const mockIssue: IssueContext = {
      number: 42,
      title: 'CWE-798: Hardcoded Secrets',
      body: '#### `config/secrets.yml`\n- **Line 3**: Hardcoded API key',
      labels: ['rsolv:detected'],
      repository: mockConfig.repository!,
      url: 'https://github.com/arubis/railsgoat-vulnerability-demo/issues/42'
    };

    mockGetIssue.mockResolvedValueOnce(mockIssue);

    const mockExecuteMitigate = vi.fn().mockResolvedValue({
      success: true, phase: 'mitigate', data: {}
    });

    executor._setTestDependencies({ scanner: mockScanOrchestrator });
    executor.executeMitigate = mockExecuteMitigate;

    // Act
    const result = await executor.executeAllPhases({ repository: mockConfig.repository });

    // Assert: must say "1 validated", not "0 ... validated"
    expect(result.message).not.toContain('0 validated');
    expect(result.message).toContain('1 validated');
  });
});
