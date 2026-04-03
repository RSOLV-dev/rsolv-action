import { describe, it, expect, vi, beforeEach } from 'vitest';
import { GitHubAdapter } from '../github-adapter.js';
import type { ForgeIssue, ForgePR, ForgeTreeEntry } from '../forge-adapter.js';

// Mock Octokit
const mockIssues = {
  listForRepo: vi.fn(),
  create: vi.fn(),
  update: vi.fn(),
  addLabels: vi.fn(),
  createComment: vi.fn(),
};

const mockPulls = {
  create: vi.fn(),
  list: vi.fn(),
};

const mockGit = {
  getTree: vi.fn(),
};

const mockRepos = {
  getContent: vi.fn(),
};

vi.mock('@octokit/rest', () => ({
  Octokit: vi.fn().mockImplementation(() => ({
    issues: mockIssues,
    pulls: mockPulls,
    git: mockGit,
    repos: mockRepos,
    request: vi.fn(),
  })),
}));

describe('GitHubAdapter', () => {
  let adapter: GitHubAdapter;

  beforeEach(() => {
    vi.clearAllMocks();
    adapter = new GitHubAdapter('test-token');
  });

  describe('listIssues', () => {
    it('calls Octokit issues.listForRepo with correct params', async () => {
      mockIssues.listForRepo.mockResolvedValue({
        data: [
          {
            number: 1,
            title: 'SQL Injection',
            html_url: 'https://github.com/org/repo/issues/1',
            labels: [{ name: 'rsolv:detected' }],
            state: 'open',
          },
        ],
      });

      const result = await adapter.listIssues('org', 'repo', 'rsolv:detected', 'open');

      expect(mockIssues.listForRepo).toHaveBeenCalledWith({
        owner: 'org',
        repo: 'repo',
        labels: 'rsolv:detected',
        state: 'open',
      });

      expect(result).toHaveLength(1);
      expect(result[0].number).toBe(1);
      expect(result[0].title).toBe('SQL Injection');
      expect(result[0].labels).toContain('rsolv:detected');
    });
  });

  describe('createIssue', () => {
    it('calls Octokit issues.create with correct params', async () => {
      mockIssues.create.mockResolvedValue({
        data: {
          number: 42,
          title: 'CWE-89: SQL Injection',
          html_url: 'https://github.com/org/repo/issues/42',
          labels: [{ name: 'rsolv:detected' }, { name: 'security' }],
          state: 'open',
        },
      });

      const result = await adapter.createIssue('org', 'repo', {
        title: 'CWE-89: SQL Injection',
        body: 'Description here',
        labels: ['rsolv:detected', 'security'],
      });

      expect(mockIssues.create).toHaveBeenCalledWith({
        owner: 'org',
        repo: 'repo',
        title: 'CWE-89: SQL Injection',
        body: 'Description here',
        labels: ['rsolv:detected', 'security'],
      });

      expect(result.number).toBe(42);
      expect(result.title).toBe('CWE-89: SQL Injection');
    });
  });

  describe('addLabels', () => {
    it('calls Octokit issues.addLabels', async () => {
      mockIssues.addLabels.mockResolvedValue({ data: [] });

      await adapter.addLabels('org', 'repo', 1, ['rsolv:validated']);

      expect(mockIssues.addLabels).toHaveBeenCalledWith({
        owner: 'org',
        repo: 'repo',
        issue_number: 1,
        labels: ['rsolv:validated'],
      });
    });
  });

  describe('createPullRequest', () => {
    it('calls Octokit pulls.create with correct params', async () => {
      mockPulls.create.mockResolvedValue({
        data: {
          number: 5,
          title: 'Fix CWE-89',
          html_url: 'https://github.com/org/repo/pull/5',
          head: { ref: 'fix/cwe-89' },
          base: { ref: 'main' },
        },
      });

      const result = await adapter.createPullRequest('org', 'repo', {
        title: 'Fix CWE-89',
        body: 'Fixes SQL injection',
        head: 'fix/cwe-89',
        base: 'main',
      });

      expect(mockPulls.create).toHaveBeenCalledWith({
        owner: 'org',
        repo: 'repo',
        title: 'Fix CWE-89',
        body: 'Fixes SQL injection',
        head: 'fix/cwe-89',
        base: 'main',
      });

      expect(result.number).toBe(5);
      expect(result.url).toBe('https://github.com/org/repo/pull/5');
    });
  });

  describe('getFileTree', () => {
    it('calls Octokit git.getTree and returns blobs only', async () => {
      mockGit.getTree.mockResolvedValue({
        data: {
          tree: [
            { type: 'blob', path: 'src/app.py', sha: 'abc123', size: 1024 },
            { type: 'tree', path: 'src', sha: 'def456' },
            { type: 'blob', path: 'tests/test_app.py', sha: 'ghi789', size: 512 },
          ],
        },
      });

      const result = await adapter.getFileTree('org', 'repo', 'main');

      expect(mockGit.getTree).toHaveBeenCalledWith({
        owner: 'org',
        repo: 'repo',
        tree_sha: 'main',
        recursive: '1',
      });

      // Should return all entries (both blobs and trees)
      expect(result).toHaveLength(3);
      expect(result[0].path).toBe('src/app.py');
      expect(result[0].type).toBe('blob');
    });
  });

  describe('getFileContent', () => {
    it('calls Octokit repos.getContent and decodes base64', async () => {
      const encoded = Buffer.from('print("hello")').toString('base64');
      mockRepos.getContent.mockResolvedValue({
        data: {
          content: encoded,
          encoding: 'base64',
        },
      });

      const result = await adapter.getFileContent('org', 'repo', 'src/app.py', 'main');

      expect(mockRepos.getContent).toHaveBeenCalledWith({
        owner: 'org',
        repo: 'repo',
        path: 'src/app.py',
        ref: 'main',
      });

      expect(result).toBe('print("hello")');
    });

    it('returns null for 404 errors', async () => {
      mockRepos.getContent.mockRejectedValue({ status: 404 });

      const result = await adapter.getFileContent('org', 'repo', 'missing.py', 'main');

      expect(result).toBeNull();
    });
  });

  describe('removeLabel', () => {
    it('removes a label via Octokit request', async () => {
      const mockRequest = vi.fn().mockResolvedValue({ data: {} });
      // Access the mock octokit's request directly
      const octokitInstance = (adapter as unknown as { octokit: { request: typeof mockRequest } }).octokit;
      octokitInstance.request = mockRequest;

      await adapter.removeLabel('org', 'repo', 1, 'old-label');

      expect(mockRequest).toHaveBeenCalledWith(
        'DELETE /repos/{owner}/{repo}/issues/{issue_number}/labels/{name}',
        {
          owner: 'org',
          repo: 'repo',
          issue_number: 1,
          name: 'old-label',
        }
      );
    });
  });

  describe('updateIssue', () => {
    it('calls Octokit issues.update with partial updates', async () => {
      mockIssues.update.mockResolvedValue({ data: {} });

      await adapter.updateIssue('org', 'repo', 1, { title: 'Updated title' });

      expect(mockIssues.update).toHaveBeenCalledWith({
        owner: 'org',
        repo: 'repo',
        issue_number: 1,
        title: 'Updated title',
      });
    });
  });
});
