/**
 * Tests for MitigationMode PhaseDataClient integration
 * RFC-060 Blocker 1: Verify NO local file reading, use API instead
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { MitigationMode } from '../mitigation-mode.js';
import { PhaseDataClient } from '../phase-data-client/index.js';
import { ActionConfig, IssueContext } from '../../types/index.js';
import * as fs from 'fs';

// Mock fs to ensure it's never called
vi.mock('fs', () => ({
  default: {
    existsSync: vi.fn(),
    readFileSync: vi.fn(),
    readdirSync: vi.fn(),
  },
  existsSync: vi.fn(),
  readFileSync: vi.fn(),
  readdirSync: vi.fn(),
}));

// Mock child_process for git operations
vi.mock('child_process', () => ({
  execSync: vi.fn(),
}));

describe('MitigationMode - PhaseDataClient Integration (RFC-060 Blocker 1)', () => {
  let mitigationMode: MitigationMode;
  let mockPhaseClient: PhaseDataClient;
  let mockConfig: ActionConfig;
  let mockIssue: IssueContext;

  beforeEach(() => {
    vi.clearAllMocks();

    mockConfig = {
      repo: 'test/repo',
      apiKey: 'test-api-key',
      phases: { scan: true, validate: true, mitigate: true },
      aiProvider: {
        provider: 'anthropic',
        apiKey: 'test-ai-key',
        model: 'claude-sonnet-4-5-20250929'
      }
    } as ActionConfig;

    mockIssue = {
      number: 123,
      title: 'Test Security Issue',
      body: 'Test description'
    } as IssueContext;

    mockPhaseClient = new PhaseDataClient('test-api-key');
    mitigationMode = new MitigationMode(mockConfig, '/fake/repo');
  });

  describe('checkoutValidationBranch', () => {
    it('should NOT read from local .rsolv/validation/*.json files', async () => {
      // RED TEST: This should FAIL initially because current code uses fs.existsSync
      // After fix: This should PASS because code will use PhaseDataClient instead

      const result = await mitigationMode.checkoutValidationBranch(mockIssue);

      // Verify fs.existsSync was NEVER called for validation files
      expect(fs.existsSync).not.toHaveBeenCalledWith(
        expect.stringContaining('.rsolv/validation')
      );

      // Verify fs.readFileSync was NEVER called
      expect(fs.readFileSync).not.toHaveBeenCalled();
    });

    it('should use PhaseDataClient.retrievePhaseResults() to get validation data', async () => {
      // RED TEST: This should FAIL initially because current code doesn't use PhaseDataClient
      // After fix: This should PASS

      // Mock PhaseDataClient to return validation data
      const mockValidationData = {
        validate: {
          'issue-123': {
            validated: true,
            branchName: 'rsolv/validate/issue-123',
            timestamp: '2025-10-06T00:00:00.000Z'
          }
        }
      };

      const retrieveSpy = vi.spyOn(mockPhaseClient, 'retrievePhaseResults')
        .mockResolvedValue(mockValidationData);

      // Inject PhaseDataClient into MitigationMode
      (mitigationMode as any).phaseClient = mockPhaseClient;

      const result = await mitigationMode.checkoutValidationBranch(mockIssue);

      // Verify PhaseDataClient.retrievePhaseResults was called
      expect(retrieveSpy).toHaveBeenCalledWith(
        mockConfig.repo,
        mockIssue.number,
        expect.any(String) // commitSha
      );

      // Verify NO local file system access
      expect(fs.existsSync).not.toHaveBeenCalled();
      expect(fs.readFileSync).not.toHaveBeenCalled();
    });

    it('should handle missing validation data gracefully from API', async () => {
      // Mock PhaseDataClient to return null (no validation data)
      const retrieveSpy = vi.spyOn(mockPhaseClient, 'retrievePhaseResults')
        .mockResolvedValue(null);

      (mitigationMode as any).phaseClient = mockPhaseClient;

      const result = await mitigationMode.checkoutValidationBranch(mockIssue);

      expect(result).toBe(false);
      expect(retrieveSpy).toHaveBeenCalled();

      // Verify NO local file system access
      expect(fs.existsSync).not.toHaveBeenCalled();
    });

    it('should extract branchName from PhaseDataClient response', async () => {
      const mockValidationData = {
        validate: {
          'issue-123': {
            validated: true,
            branchName: 'rsolv/validate/issue-123',
            timestamp: '2025-10-06T00:00:00.000Z'
          }
        }
      };

      vi.spyOn(mockPhaseClient, 'retrievePhaseResults')
        .mockResolvedValue(mockValidationData);

      (mitigationMode as any).phaseClient = mockPhaseClient;

      // Note: This test will verify branch checkout logic uses API data
      // The actual git checkout will be mocked via execSync mock
      const result = await mitigationMode.checkoutValidationBranch(mockIssue);

      // Verify NO local file reads
      expect(fs.readFileSync).not.toHaveBeenCalled();
    });
  });

  describe('getValidationTests', () => {
    it('should NOT read from local .rsolv/tests directory', async () => {
      // RED TEST: Current code uses fs.readdirSync to read .rsolv/tests
      // After fix: Should use PhaseDataClient or validation branch content

      const result = await mitigationMode.getValidationTests(mockIssue);

      // Verify fs.readdirSync was NEVER called for .rsolv/tests
      expect(fs.readdirSync).not.toHaveBeenCalledWith(
        expect.stringContaining('.rsolv/tests')
      );
    });

    it('should retrieve test content from PhaseDataClient or validation branch', async () => {
      // RED TEST: This should FAIL initially
      // After fix: Should retrieve tests via API

      const mockValidationData = {
        validate: {
          'issue-123': {
            validated: true,
            testResults: {
              generatedTests: {
                red: {
                  testName: 'should be vulnerable to SQL injection',
                  testCode: 'test("should fail", () => { expect(true).toBe(false); })',
                }
              }
            },
            timestamp: '2025-10-06T00:00:00.000Z'
          }
        }
      };

      vi.spyOn(mockPhaseClient, 'retrievePhaseResults')
        .mockResolvedValue(mockValidationData);

      (mitigationMode as any).phaseClient = mockPhaseClient;

      const result = await mitigationMode.getValidationTests(mockIssue);

      // Verify NO local directory reading
      expect(fs.readdirSync).not.toHaveBeenCalled();
      expect(fs.existsSync).not.toHaveBeenCalled();
    });
  });
});
