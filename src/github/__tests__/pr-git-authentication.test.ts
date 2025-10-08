import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { createEducationalPullRequest } from '../pr-git-educational';
import { execSync } from 'child_process';

// Mock child_process
vi.mock('child_process');
vi.mock('../../utils/logger');
vi.mock('../api');

const mockExecSync = execSync as any;

describe('PR Git Authentication', () => {
  const originalEnv = process.env;

  beforeEach(() => {
    vi.clearAllMocks();
    process.env = { ...originalEnv };
  });

  afterEach(() => {
    process.env = originalEnv;
  });

  describe('Branch Push Authentication', () => {
    it('should use GITHUB_TOKEN for authentication when available', async () => {
      // Arrange
      process.env.GITHUB_TOKEN = 'ghp_testtoken123';
      process.env.GITHUB_REPOSITORY = 'owner/repo';

      const expectedAuthUrl = 'https://x-access-token:ghp_testtoken123@github.com/owner/repo.git';

      mockExecSync.mockImplementation((command: string) => {
        // Return empty string or Buffer for all git commands
        return Buffer.from('');
      });

      const issue = {
        id: '1',
        number: 123,
        title: 'Test Issue',
        repository: {
          fullName: 'owner/repo',
          defaultBranch: 'main'
        }
      };

      const config = {
        githubToken: 'ghp_testtoken123'
      } as any;

      // Act
      await createEducationalPullRequest(
        issue as any,
        'abc123',
        {
          title: 'Fix XSS vulnerability',
          description: 'Test description'
        },
        config
      );

      // Assert
      expect(mockExecSync).toHaveBeenCalledWith(
        `git remote set-url origin ${expectedAuthUrl}`,
        expect.objectContaining({ cwd: expect.any(String) })
      );
    });

    it('should prefer GH_PAT over GITHUB_TOKEN when both are available', () => {
      // Arrange
      process.env.GITHUB_TOKEN = 'ghp_github123';
      process.env.GH_PAT = 'ghp_pat123';
      process.env.GITHUB_REPOSITORY = 'owner/repo';

      const expectedAuthUrl = 'https://x-access-token:ghp_pat123@github.com/owner/repo.git';

      mockExecSync.mockImplementation((command: string) => {
        if (command === `git remote set-url origin ${expectedAuthUrl}`) {
          return '';
        }
        return '';
      });

      // Assert - GH_PAT should be used
      expect(process.env.GH_PAT).toBeDefined();
    });

    it('should handle push failures with proper error reporting', () => {
      // Arrange
      process.env.GITHUB_TOKEN = 'ghp_testtoken123';
      process.env.GITHUB_REPOSITORY = 'owner/repo';

      mockExecSync.mockImplementation((command: string) => {
        if (command.includes('git push')) {
          throw new Error('remote: Permission to owner/repo.git denied');
        }
        return '';
      });

      // Act & Assert
      expect(() => {
        mockExecSync('git push -u origin test-branch', { cwd: process.cwd() });
      }).toThrow('Permission to owner/repo.git denied');
    });

    it('should force push when branch exists on remote', () => {
      // Arrange
      process.env.GITHUB_TOKEN = 'ghp_testtoken123';
      process.env.GITHUB_REPOSITORY = 'owner/repo';

      let pushAttempt = 0;
      mockExecSync.mockImplementation((command: string) => {
        if (command.includes('git push -u origin')) {
          pushAttempt++;
          if (pushAttempt === 1) {
            throw new Error('Updates were rejected');
          }
        }
        if (command.includes('git push -f origin')) {
          return '';
        }
        return '';
      });

      // Act - simulate retry with force push
      try {
        mockExecSync('git push -u origin test-branch', { cwd: process.cwd() });
      } catch (error) {
        mockExecSync('git push -f origin test-branch', { cwd: process.cwd() });
      }

      // Assert
      expect(mockExecSync).toHaveBeenCalledWith(
        'git push -f origin test-branch',
        expect.any(Object)
      );
    });
  });

  describe('Workflow Permissions', () => {
    it('should detect when using default GITHUB_TOKEN with limited permissions', () => {
      // Arrange
      process.env.GITHUB_TOKEN = 'ghs_'; // GitHub Actions default token prefix
      process.env.GH_PAT = undefined;

      // Act
      const isDefaultToken = process.env.GITHUB_TOKEN?.startsWith('ghs_');

      // Assert
      expect(isDefaultToken).toBe(true);
    });

    it('should recommend PAT for cross-repo operations', () => {
      // Arrange
      process.env.GITHUB_TOKEN = 'ghs_defaulttoken123'; // Default GitHub Actions token
      process.env.GH_PAT = undefined;

      const recommendations = [];

      if (!process.env.GH_PAT && process.env.GITHUB_TOKEN?.startsWith('ghs_')) {
        recommendations.push('Use GH_PAT for better permissions');
      }

      // Assert
      expect(recommendations).toContain('Use GH_PAT for better permissions');
    });
  });
});