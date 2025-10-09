/**
 * RFC-060 Blocker 1: MitigationMode PhaseDataClient Integration Tests
 * Direct unit tests for MitigationMode class using PhaseDataClient
 */

import { describe, test, expect, beforeEach, vi } from 'vitest';
import { MitigationMode } from '../mitigation-mode.js';
import { IssueContext, ActionConfig } from '../../types/index.js';

// Use vi.hoisted to hoist all mock functions
const {
  mockRetrievePhaseResults,
  mockGetPhaseTestInfo,
  mockSaveTestResults,
  mockRunTest,
  mockReadFileSync
} = vi.hoisted(() => ({
  mockRetrievePhaseResults: vi.fn(),
  mockGetPhaseTestInfo: vi.fn(),
  mockSaveTestResults: vi.fn(),
  mockRunTest: vi.fn(),
  mockReadFileSync: vi.fn()
}));

// Mock PhaseDataClient
const mockPhaseDataClient = {
  retrievePhaseResults: mockRetrievePhaseResults,
  storePhaseResults: vi.fn(),
  getPhaseTestInfo: mockGetPhaseTestInfo,
  saveTestResults: mockSaveTestResults
} as any;

// Mock execSync and exec to avoid actual git commands
vi.mock('child_process', () => ({
  execSync: vi.fn((cmd: string) => {
    if (cmd.includes('git rev-parse HEAD')) {
      return 'abc123def456';
    }
    if (cmd.includes('git fetch')) {
      return '';
    }
    if (cmd.includes('git checkout')) {
      return '';
    }
    return '';
  }),
  exec: vi.fn((cmd: string, callback: any) => {
    if (callback) {
      callback(null, '', '');
    }
  })
}));

// Mock fs for test content reading
vi.mock('fs', () => ({
  readFileSync: vi.fn(),
  existsSync: vi.fn(() => true)
}));

// Mock TestRunner
vi.mock('../../services/test-runner.js', () => ({
  TestRunner: vi.fn(() => ({
    runTest: mockRunTest,
    validate: vi.fn(() => true)
  }))
}));

describe('MitigationMode - PhaseDataClient Integration', () => {
  let mitigationMode: MitigationMode;
  let mockConfig: ActionConfig;
  let mockIssue: IssueContext;

  beforeEach(() => {
    vi.clearAllMocks();

    mockConfig = {
      aiProvider: {
        provider: 'anthropic',
        apiKey: 'test-key',
        model: 'claude-3',
        maxTokens: 4000
      },
      github: {
        token: 'test-token',
        owner: 'test',
        repo: 'webapp'
      }
    } as ActionConfig;

    mockIssue = {
      id: 'issue-789',
      number: 789,
      title: 'SQL Injection in user query',
      body: 'User input not properly parameterized',
      labels: ['rsolv:automate', 'security'],
      assignees: [],
      repository: {
        owner: 'test',
        name: 'webapp',
        fullName: 'test/webapp',
        defaultBranch: 'main',
        language: 'JavaScript'
      },
      source: 'github',
      createdAt: '2025-10-06T14:00:00Z',
      updatedAt: '2025-10-06T14:00:00Z',
      metadata: {}
    };

    mitigationMode = new MitigationMode(mockConfig, '/test/repo', mockPhaseDataClient);
  });

  describe('RFC-060: PhaseDataClient Integration', () => {
    test('should call PhaseDataClient.retrievePhaseResults() when checking out validation branch', async () => {
      // Arrange
      mockRetrievePhaseResults.mockResolvedValue({
        validate: {
          'issue-789': {
            validated: true,
            branchName: 'rsolv/validate/issue-789',
            generatedTests: {
              success: true,
              tests: []
            }
          }
        }
      });

      // Act
      const result = await mitigationMode.checkoutValidationBranch(mockIssue);

      // Assert
      expect(mockRetrievePhaseResults).toHaveBeenCalledWith(
        'test/webapp',
        789,
        'abc123def456'
      );
      expect(result).toBe(true);
    });

    test('should use PhaseDataClient API instead of local file reads', async () => {
      // Arrange
      mockRetrievePhaseResults.mockResolvedValue({
        validate: {
          'issue-789': {
            validated: true,
            branchName: 'rsolv/validate/issue-789'
          }
        }
      });

      // Act
      await mitigationMode.checkoutValidationBranch(mockIssue);

      // Assert - PhaseDataClient was called (proves we're using API, not local files)
      expect(mockRetrievePhaseResults).toHaveBeenCalledTimes(1);
      expect(mockRetrievePhaseResults).toHaveBeenCalledWith(
        'test/webapp',
        789,
        'abc123def456'
      );
    });

    test('should handle missing validation data gracefully', async () => {
      // Arrange
      mockRetrievePhaseResults.mockResolvedValue(null);

      // Act
      const result = await mitigationMode.checkoutValidationBranch(mockIssue);

      // Assert
      expect(result).toBe(false);
      expect(mockRetrievePhaseResults).toHaveBeenCalled();
    });

    test('should handle missing validate key in phase data', async () => {
      // Arrange
      mockRetrievePhaseResults.mockResolvedValue({
        scan: { vulnerabilities: [] }
        // No validate key
      });

      // Act
      const result = await mitigationMode.checkoutValidationBranch(mockIssue);

      // Assert
      expect(result).toBe(false);
    });

    test('should handle missing branchName in validation data', async () => {
      // Arrange
      mockRetrievePhaseResults.mockResolvedValue({
        validate: {
          'issue-789': {
            validated: true
            // No branchName
          }
        }
      });

      // Act
      const result = await mitigationMode.checkoutValidationBranch(mockIssue);

      // Assert
      expect(result).toBe(false);
    });

    test('should return false when PhaseDataClient is not available', async () => {
      // Arrange
      const modeWithoutClient = new MitigationMode(mockConfig, '/test/repo');

      // Act
      const result = await modeWithoutClient.checkoutValidationBranch(mockIssue);

      // Assert
      expect(result).toBe(false);
    });
  });

  describe('RFC-060 Phase 3.1: No Local File Fallback', () => {
    test('should retrieve branchName exclusively from PhaseDataClient API', async () => {
      // Arrange
      mockRetrievePhaseResults.mockResolvedValue({
        validate: {
          'issue-789': {
            validated: true,
            branchName: 'rsolv/validate/issue-789',
            testPath: '__tests__/security/issue-789.test.js'
          }
        }
      });

      // Act
      const result = await mitigationMode.checkoutValidationBranch(mockIssue);

      // Assert - PhaseDataClient was called (proves we're using API, not local files)
      expect(mockRetrievePhaseResults).toHaveBeenCalledWith(
        'test/webapp',
        789,
        'abc123def456'
      );
      expect(result).toBe(true);
    });
  });

  describe('#prepareTestContext', () => {
    const sampleTestContent = `
      describe('Security Test', () => {
        it('validates behavior', () => {
          expect(true).toBe(true);
        });
      });
    `;

    test('retrieves branch name from PhaseDataClient', async () => {
      mockGetPhaseTestInfo.mockResolvedValue({
        branchName: 'rsolv/validate/issue-123',
        testPath: '__tests__/security/rsolv-issue-123.test.js',
        framework: 'jest',
        command: 'npm test -- __tests__/security/rsolv-issue-123.test.js'
      });

      await mitigationMode.prepareTestContext('issue-123');

      expect(mockGetPhaseTestInfo).toHaveBeenCalledWith('issue-123');
    });

    test('reads test file content from git', async () => {
      const testPath = '__tests__/security/rsolv-issue-456.test.js';
      const fs = await import('fs');
      const mockFsRead = vi.mocked(fs.readFileSync);
      mockFsRead.mockReturnValue(sampleTestContent);

      mockGetPhaseTestInfo.mockResolvedValue({
        branchName: 'rsolv/validate/issue-456',
        testPath,
        framework: 'jest',
        command: `npm test -- ${testPath}`
      });

      const context = await mitigationMode.prepareTestContext('issue-456');

      expect(context.testContent).toBe(sampleTestContent);
      expect(context.testPath).toBe(testPath);
    });
  });

  describe('#buildTestAwarePrompt', () => {
    test('includes test content in prompt', async () => {
      const testContent = `describe('SQL Injection', () => {})`;
      const testPath = '__tests__/security/rsolv-issue-789.test.js';
      const fs = await import('fs');
      const mockFsRead = vi.mocked(fs.readFileSync);
      mockFsRead.mockReturnValue(testContent);

      mockGetPhaseTestInfo.mockResolvedValue({
        branchName: 'rsolv/validate/issue-789',
        testPath,
        framework: 'mocha',
        command: `npm test -- ${testPath}`
      });

      const prompt = await mitigationMode.buildTestAwarePrompt('issue-789', 'Fix SQL injection');

      expect(prompt).toContain(testContent);
      expect(prompt).toContain('The following test validates the expected behavior');
      expect(prompt).toContain(testPath);
    });
  });

  describe('#runPreFixTest', () => {

    test('executes test and returns failure result', async () => {
      const command = 'npm test -- __tests__/security/rsolv-issue-111.test.js';
      mockGetPhaseTestInfo.mockResolvedValue({
        branchName: 'rsolv/validate/issue-111',
        testPath: '__tests__/security/rsolv-issue-111.test.js',
        framework: 'jest',
        command
      });
      mockRunTest.mockResolvedValue({ passed: false, output: 'Test failed' });

      const result = await mitigationMode.runPreFixTest('issue-111');

      expect(mockRunTest).toHaveBeenCalledWith(command);
      expect(result.passed).toBe(false);
    });
  });

  describe('#runPostFixTest', () => {

    test('executes test and returns success result', async () => {
      const command = 'npm test -- __tests__/security/rsolv-issue-222.test.js';
      mockGetPhaseTestInfo.mockResolvedValue({
        branchName: 'rsolv/validate/issue-222',
        testPath: '__tests__/security/rsolv-issue-222.test.js',
        framework: 'jest',
        command
      });
      mockRunTest.mockResolvedValue({ passed: true, output: 'All tests passed' });

      const result = await mitigationMode.runPostFixTest('issue-222');

      expect(mockRunTest).toHaveBeenCalledWith(command);
      expect(result.passed).toBe(true);
    });
  });

  describe('#saveTestResults', () => {
    test('delegates to PhaseDataClient', async () => {
      const testResults = {
        issueId: 'issue-333',
        preTestPassed: false,
        postTestPassed: true,
        trustScore: 100
      };

      await mitigationMode.saveTestResults(testResults);

      expect(mockSaveTestResults).toHaveBeenCalledWith(testResults);
    });
  });

  describe('#calculateTrustScore', () => {
    test('returns 0 when both tests fail', async () => {
      const score = await mitigationMode.calculateTrustScore(false, false);
      expect(score).toBe(0);
    });

    test('returns 100 for perfect fix (pre-fail, post-pass)', async () => {
      const score = await mitigationMode.calculateTrustScore(false, true);
      expect(score).toBe(100);
    });

    test('returns 50 when both tests pass', async () => {
      const score = await mitigationMode.calculateTrustScore(true, true);
      expect(score).toBe(50);
    });

    test('returns 0 when pre-pass but post-fail', async () => {
      const score = await mitigationMode.calculateTrustScore(true, false);
      expect(score).toBe(0);
    });
  });

  describe('#runTestSafely', () => {

    test('catches and returns error when test execution fails', async () => {
      mockGetPhaseTestInfo.mockResolvedValue({
        branchName: 'rsolv/validate/issue-444',
        testPath: '__tests__/error/rsolv-issue-444.test.js',
        framework: 'jest',
        command: 'npm test -- __tests__/error/rsolv-issue-444.test.js'
      });
      mockRunTest.mockRejectedValue(new Error('Test runner crashed'));

      const result = await mitigationMode.runTestSafely('issue-444');

      expect(result.error).toBe('Test runner crashed');
      expect(result.passed).toBe(false);
    });
  });
});
