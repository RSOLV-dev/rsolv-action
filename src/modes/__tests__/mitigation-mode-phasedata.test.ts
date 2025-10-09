/**
 * RFC-060 Blocker 1: MitigationMode PhaseDataClient Integration Tests
 * Direct unit tests for MitigationMode class using PhaseDataClient
 */

import { describe, test, expect, beforeEach, vi } from 'vitest';
import { MitigationMode } from '../mitigation-mode.js';
import { IssueContext, ActionConfig } from '../../types/index.js';

// Mock PhaseDataClient
const mockRetrievePhaseResults = vi.fn();
const mockPhaseDataClient = {
  retrievePhaseResults: mockRetrievePhaseResults,
  storePhaseResults: vi.fn()
} as any;

// Mock execSync to avoid actual git commands
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
  })
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
});
