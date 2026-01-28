/**
 * Test suite for ValidationMode test commit behavior
 *
 * Verifies that commitTestsToBranch works correctly:
 * - Writes executable JS (not JSON) to .rsolv/tests/
 * - Handles git branch/push failures gracefully
 * - Works in RSOLV_TESTING_MODE
 */

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { ValidationMode } from '../validation-mode.js';
import { execSync } from 'child_process';
import * as fs from 'fs';
import * as path from 'path';
import { createTestConfig, createTestIssue, type ValidationModeTestAccess } from './test-fixtures.js';

vi.mock('child_process');
vi.mock('fs');
vi.mock('../test-integration-client.js');
vi.mock('../../github/api', () => ({
  getGitHubClient: vi.fn(() => ({
    issues: {
      addLabels: vi.fn(),
      createComment: vi.fn()
    }
  }))
}));

describe('ValidationMode - Test Commit in Test Mode', () => {
  let validationMode: ValidationMode;
  let originalEnv: NodeJS.ProcessEnv;
  const mockRepoPath = '/test/repo';
  const mockIssue = createTestIssue();

  beforeEach(() => {
    originalEnv = { ...process.env };
    vi.clearAllMocks();
    process.env.RSOLV_TESTING_MODE = 'true';
    // Clear RSOLV_API_URL to force the fallback path (.rsolv/tests/)
    // Backend integration is tested in validation-mode-backend-integration.test.ts
    delete process.env.RSOLV_API_URL;

    const config = createTestConfig({ rsolvApiKey: undefined });
    validationMode = new ValidationMode(config, mockRepoPath);

    // Mock fs operations
    (fs.mkdirSync as ReturnType<typeof vi.fn>).mockReturnValue(undefined);
    (fs.writeFileSync as ReturnType<typeof vi.fn>).mockReturnValue(undefined);
    (fs.existsSync as ReturnType<typeof vi.fn>).mockReturnValue(true);
    (fs.readdirSync as ReturnType<typeof vi.fn>).mockReturnValue([]);
  });

  afterEach(() => {
    process.env = originalEnv;
  });

  describe('commitTestsToBranch', () => {
    it('should write executable JavaScript when given an object with redTests', async () => {
      const testContent = {
        redTests: [
          { testName: 'SQL injection test', testCode: 'expect(true).toBe(true);' }
        ]
      };

      const execSyncMock = execSync as unknown as ReturnType<typeof vi.fn>;
      execSyncMock.mockReturnValue(Buffer.from(''));

      await validationMode.commitTestsToBranch(testContent, 'rsolv/validate/issue-123', mockIssue);

      // Verify test file was written with executable JS (not JSON)
      expect(fs.writeFileSync).toHaveBeenCalledWith(
        expect.stringContaining('validation.test.js'),
        expect.any(String),
        'utf8'
      );

      const writtenContent = (fs.writeFileSync as ReturnType<typeof vi.fn>).mock.calls[0][1] as string;
      expect(writtenContent).toContain('describe(');
      expect(writtenContent).toContain("it('SQL injection test'");
      expect(writtenContent).toContain('expect(true).toBe(true);');
      // Should NOT be JSON
      expect(writtenContent).not.toMatch(/^\s*\{/);
    });

    it('should handle branch creation failure and still commit tests', async () => {
      const testContent = {
        redTests: [{ testName: 'test', testCode: 'expect(1).toBe(1);' }]
      };

      const execSyncMock = execSync as unknown as ReturnType<typeof vi.fn>;
      execSyncMock.mockImplementation((cmd: string) => {
        if (typeof cmd === 'string' && cmd.includes('git checkout -b')) {
          throw new Error('Branch already exists');
        }
        return Buffer.from('');
      });

      // commitTestsToBranch doesn't create branches itself - it writes files and commits
      await validationMode.commitTestsToBranch(testContent, 'rsolv/validate/issue-123', mockIssue);

      // Verify test file was still written
      expect(fs.writeFileSync).toHaveBeenCalled();
    });

    it('should convert arbitrary object content to executable tests', async () => {
      const arbitraryContent = {
        red: {
          testName: 'Arbitrary test',
          testCode: 'const x = 1;\nexpect(x).toBe(1);'
        }
      };

      const execSyncMock = execSync as unknown as ReturnType<typeof vi.fn>;
      execSyncMock.mockReturnValue(Buffer.from(''));

      await validationMode.commitTestsToBranch(arbitraryContent, 'rsolv/validate/issue-123', mockIssue);

      const writtenContent = (fs.writeFileSync as ReturnType<typeof vi.fn>).mock.calls[0][1] as string;
      // Should contain describe/it structure
      expect(writtenContent).toContain('describe(');
      expect(writtenContent).toContain("it('Arbitrary test'");
    });

    it('should handle git push failure gracefully', async () => {
      const testContent = {
        redTests: [{ testName: 'test', testCode: 'expect(1).toBe(1);' }]
      };

      const execSyncMock = execSync as unknown as ReturnType<typeof vi.fn>;
      execSyncMock.mockImplementation((cmd: string) => {
        if (typeof cmd === 'string' && cmd.includes('git push')) {
          throw new Error('Authentication failed');
        }
        return Buffer.from('');
      });

      // Should not throw even if push fails
      await expect(
        validationMode.commitTestsToBranch(testContent, 'rsolv/validate/issue-123', mockIssue)
      ).resolves.not.toThrow();

      // Verify test was still written and committed locally
      expect(fs.writeFileSync).toHaveBeenCalled();
      expect(execSyncMock).toHaveBeenCalledWith(
        expect.stringMatching(/git commit/),
        expect.any(Object)
      );
    });

    it('should pass string content through without conversion', async () => {
      const stringContent = "describe('Existing test', () => {\n  it('works', () => {\n    expect(true).toBe(true);\n  });\n});\n";

      const execSyncMock = execSync as unknown as ReturnType<typeof vi.fn>;
      execSyncMock.mockReturnValue(Buffer.from(''));

      await validationMode.commitTestsToBranch(stringContent, 'rsolv/validate/issue-123', mockIssue);

      const writtenContent = (fs.writeFileSync as ReturnType<typeof vi.fn>).mock.calls[0][1] as string;
      expect(writtenContent).toBe(stringContent);
    });
  });

  describe('validateVulnerability in test mode', () => {
    it('should attempt test commits in test mode regardless of test quality', async () => {
      process.env.RSOLV_TESTING_MODE = 'true';

      // Cast to test access type for spying on private methods
      // vi.spyOn requires the object directly; ValidationModeTestAccess
      // provides type-safe method names without `as any`
      const spyTarget = validationMode as unknown as ValidationModeTestAccess;

      const createBranchSpy = vi.spyOn(spyTarget, 'createValidationBranch')
        .mockResolvedValue('rsolv/validate/issue-123');

      const commitTestsSpy = vi.spyOn(spyTarget, 'commitTestsToBranch')
        .mockResolvedValue(undefined);

      vi.spyOn(spyTarget, 'generateRedTests')
        .mockResolvedValue({
          generatedTests: {
            testSuite: { redTests: [{ testCode: 'test', testName: 'test' }] }
          }
        });

      vi.spyOn(spyTarget, 'storeValidationResultWithBranch').mockResolvedValue(undefined);

      // Call validateVulnerability
      await validationMode.validateVulnerability(mockIssue);

      // Verify branch creation and test commit were attempted
      expect(createBranchSpy).toHaveBeenCalled();
      expect(commitTestsSpy).toHaveBeenCalled();
    });
  });
});
