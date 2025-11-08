import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { createPullRequest, PullRequestOptions } from '../github-client.js';
import { Octokit } from '@octokit/rest';
import { execSync } from 'child_process';

// Mock Octokit
vi.mock('@octokit/rest', () => ({
  Octokit: vi.fn()
}));

// Mock child_process execSync
vi.mock('child_process', () => ({
  execSync: vi.fn()
}));

describe('github-client', () => {
  let mockOctokit: any;
  let originalEnv: NodeJS.ProcessEnv;

  beforeEach(() => {
    // Save original env
    originalEnv = { ...process.env };

    // Mock Octokit instance
    mockOctokit = {
      rest: {
        git: {
          getRef: vi.fn(),
          createRef: vi.fn()
        },
        pulls: {
          create: vi.fn()
        },
        issues: {
          addLabels: vi.fn()
        }
      }
    };

    // Make Octokit constructor return our mock
    (Octokit as any).mockImplementation(() => mockOctokit);

    // Mock execSync to simulate successful git commands
    vi.mocked(execSync).mockImplementation((command: string) => {
      // Return current branch name for rev-parse command
      if (command.includes('rev-parse --abbrev-ref HEAD')) {
        return Buffer.from('main');
      }
      // For all other git commands, return empty buffer (success)
      return Buffer.from('');
    });

    // Set GitHub token
    process.env.GITHUB_TOKEN = 'test-token';
  });

  afterEach(() => {
    // Restore original env
    process.env = originalEnv;
    vi.clearAllMocks();
  });

  describe('createPullRequest', () => {
    const mockOptions: PullRequestOptions = {
      repository: 'owner/repo',
      commitSha: 'abc123',
      issueNumber: 5,
      title: 'Fix: SQL Injection vulnerability',
      body: '## Security Fix\n\nThis fixes the SQL injection issue.',
      base: 'main'
    };

    it('should create a branch, PR, and apply label successfully', async () => {
      // Setup mocks
      mockOctokit.rest.git.getRef.mockResolvedValue({
        data: { object: { sha: 'base-sha' } }
      });

      mockOctokit.rest.git.createRef.mockResolvedValue({
        data: { ref: 'refs/heads/rsolv/fix/issue-5' }
      });

      mockOctokit.rest.pulls.create.mockResolvedValue({
        data: {
          number: 10,
          html_url: 'https://github.com/owner/repo/pull/10',
          title: 'Fix: SQL Injection vulnerability'
        }
      });

      mockOctokit.rest.issues.addLabels.mockResolvedValue({
        data: []
      });

      // Execute
      const result = await createPullRequest(mockOptions);

      // Verify Octokit was initialized with token
      expect(Octokit).toHaveBeenCalledWith({ auth: 'test-token' });

      // Note: Branch creation is now done via git commands (not Octokit API)
      // Verify execSync was called for git operations
      expect(execSync).toHaveBeenCalled();

      // Verify PR creation
      expect(mockOctokit.rest.pulls.create).toHaveBeenCalledWith({
        owner: 'owner',
        repo: 'repo',
        title: 'Fix: SQL Injection vulnerability',
        body: '## Security Fix\n\nThis fixes the SQL injection issue.',
        head: 'rsolv/fix/issue-5',
        base: 'main'
      });

      // Verify label application
      expect(mockOctokit.rest.issues.addLabels).toHaveBeenCalledWith({
        owner: 'owner',
        repo: 'repo',
        issue_number: 5,
        labels: ['rsolv:mitigated']
      });

      // Verify result
      expect(result).toEqual({
        number: 10,
        url: 'https://github.com/owner/repo/pull/10',
        title: 'Fix: SQL Injection vulnerability'
      });
    });

    it('should handle branch creation failure', async () => {
      // Mock git checkout to fail (simulating branch creation failure)
      vi.mocked(execSync).mockImplementation((command: string) => {
        if (command.includes('rev-parse --abbrev-ref HEAD')) {
          return Buffer.from('main');
        }
        if (command.includes('git checkout') || command.includes('git push')) {
          throw new Error('fatal: unable to create branch');
        }
        return Buffer.from('');
      });

      await expect(createPullRequest(mockOptions)).rejects.toThrow(
        'PR creation failed: Failed to push commit to remote'
      );
    });

    it('should handle PR creation failure', async () => {
      mockOctokit.rest.git.createRef.mockResolvedValue({
        data: { ref: 'refs/heads/rsolv/fix/issue-5' }
      });

      mockOctokit.rest.pulls.create.mockRejectedValue(
        new Error('A pull request already exists')
      );

      await expect(createPullRequest(mockOptions)).rejects.toThrow(
        'PR creation failed: A pull request already exists'
      );
    });

    it('should handle label application failure gracefully', async () => {
      mockOctokit.rest.git.createRef.mockResolvedValue({
        data: { ref: 'refs/heads/rsolv/fix/issue-5' }
      });

      mockOctokit.rest.pulls.create.mockResolvedValue({
        data: {
          number: 10,
          html_url: 'https://github.com/owner/repo/pull/10',
          title: 'Fix: SQL Injection vulnerability'
        }
      });

      mockOctokit.rest.issues.addLabels.mockRejectedValue(
        new Error('Label does not exist')
      );

      // Should still throw since we want to know about label failures
      await expect(createPullRequest(mockOptions)).rejects.toThrow(
        'PR creation failed: Label does not exist'
      );
    });

    it('should handle missing GITHUB_TOKEN', async () => {
      delete process.env.GITHUB_TOKEN;

      // Should throw error before initializing Octokit
      await expect(createPullRequest(mockOptions)).rejects.toThrow(
        'PR creation failed: GITHUB_TOKEN environment variable is not set'
      );

      // Octokit should not be initialized when token is missing
      expect(Octokit).not.toHaveBeenCalled();
    });

    it('should parse repository owner and name correctly', async () => {
      mockOctokit.rest.git.createRef.mockResolvedValue({
        data: { ref: 'refs/heads/rsolv/fix/issue-5' }
      });

      mockOctokit.rest.pulls.create.mockResolvedValue({
        data: {
          number: 10,
          html_url: 'https://github.com/test-org/my-repo/pull/10',
          title: 'Fix: Test'
        }
      });

      mockOctokit.rest.issues.addLabels.mockResolvedValue({
        data: []
      });

      await createPullRequest({
        ...mockOptions,
        repository: 'test-org/my-repo'
      });

      // Verify PR was created with correct owner/repo
      expect(mockOctokit.rest.pulls.create).toHaveBeenCalledWith(
        expect.objectContaining({
          owner: 'test-org',
          repo: 'my-repo'
        })
      );
    });

    it('should create branch with correct naming pattern', async () => {
      mockOctokit.rest.git.createRef.mockResolvedValue({
        data: { ref: 'refs/heads/rsolv/fix/issue-123' }
      });

      mockOctokit.rest.pulls.create.mockResolvedValue({
        data: {
          number: 10,
          html_url: 'https://github.com/owner/repo/pull/10',
          title: 'Fix: Test'
        }
      });

      mockOctokit.rest.issues.addLabels.mockResolvedValue({
        data: []
      });

      await createPullRequest({
        ...mockOptions,
        issueNumber: 123
      });

      // Verify PR was created with correct branch naming pattern
      expect(mockOctokit.rest.pulls.create).toHaveBeenCalledWith(
        expect.objectContaining({
          head: 'rsolv/fix/issue-123'
        })
      );
    });

    it('should use correct base branch from options', async () => {
      mockOctokit.rest.git.createRef.mockResolvedValue({
        data: { ref: 'refs/heads/rsolv/fix/issue-5' }
      });

      mockOctokit.rest.pulls.create.mockResolvedValue({
        data: {
          number: 10,
          html_url: 'https://github.com/owner/repo/pull/10',
          title: 'Fix: Test'
        }
      });

      mockOctokit.rest.issues.addLabels.mockResolvedValue({
        data: []
      });

      await createPullRequest({
        ...mockOptions,
        base: 'develop'
      });

      expect(mockOctokit.rest.pulls.create).toHaveBeenCalledWith(
        expect.objectContaining({
          base: 'develop'
        })
      );
    });
  });
});
