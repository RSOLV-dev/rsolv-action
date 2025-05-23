import { describe, it, expect, beforeEach, vi, Mock, afterEach } from 'vitest';
import type { ActionConfig } from '../../src/types';

// We'll need to manually mock these since vi.mock doesn't work in Bun
const mockDetectIssues = vi.fn();
const mockCreateAndAuthenticate = vi.fn();

// Mock the modules before importing the code under test
vi.doMock('../../src/github/issues', () => ({
  detectIssues: mockDetectIssues
}));

vi.doMock('../../src/platforms/platform-factory', () => ({
  PlatformFactory: {
    createAndAuthenticate: mockCreateAndAuthenticate
  }
}));

// Now import the code under test
const { detectIssuesFromAllPlatforms } = await import('../../src/platforms/issue-detector');

// Mock fetch for Jira API calls
global.fetch = vi.fn() as Mock;

describe('Multi-Platform Issue Detection', () => {
  let mockConfig: ActionConfig;

  beforeEach(() => {
    vi.clearAllMocks();
    
    mockConfig = {
      issueLabel: 'rsolv:automate',
      enabled: true,
      permissions: {
        allowedRepositories: ['*'],
        deniedRepositories: [],
        allowedFiles: ['*'],
        deniedFiles: []
      },
      security: {
        preventSecrets: true,
        preventDestructive: true,
        requireApproval: false
      },
      limits: {
        maxIssuesPerRun: 10,
        maxFilesPerIssue: 20,
        maxChangesPerFile: 100
      },
      ai: {
        provider: 'anthropic',
        model: 'claude-3-opus-20240229',
        temperature: 0.2,
        maxTokens: 4000
      }
    };
  });

  it('should detect issues from GitHub only when no other platforms configured', async () => {
    // Mock GitHub issues
    const mockGitHubIssues = [
      {
        id: 'github-1',
        number: 1,
        title: 'Fix bug in auth',
        body: 'Authentication is broken',
        labels: ['rsolv:automate', 'bug'],
        source: 'github'
      }
    ];
    
    vi.mocked(githubIssues.detectIssues).mockResolvedValue(mockGitHubIssues as any);

    const issues = await detectIssuesFromAllPlatforms(mockConfig);

    expect(issues).toHaveLength(1);
    expect(issues[0].source).toBe('github');
    expect(vi.mocked(githubIssues.detectIssues)).toHaveBeenCalledWith(mockConfig);
  });

  it('should detect issues from both GitHub and Jira when configured', async () => {
    // Set Jira environment variables
    process.env.JIRA_HOST = 'test.atlassian.net';
    process.env.JIRA_EMAIL = 'test@example.com';
    process.env.JIRA_API_TOKEN = 'test-token';

    // Mock GitHub issues
    const mockGitHubIssues = [
      {
        id: 'github-1',
        number: 1,
        title: 'GitHub Issue',
        source: 'github'
      }
    ];
    vi.mocked(githubIssues.detectIssues).mockResolvedValue(mockGitHubIssues as any);

    // Mock Jira adapter
    const mockJiraAdapter = {
      searchIssues: vi.fn().mockResolvedValue([
        {
          id: 'jira-1001',
          platform: 'jira',
          key: 'PROJ-123',
          title: 'Jira Issue',
          description: 'Repository: https://github.com/owner/repo',
          labels: ['autofix'],
          status: 'To Do',
          url: 'https://test.atlassian.net/browse/PROJ-123',
          createdAt: new Date(),
          updatedAt: new Date()
        }
      ])
    };

    vi.mocked(PlatformFactory.createAndAuthenticate).mockResolvedValue(mockJiraAdapter as any);

    const issues = await detectIssuesFromAllPlatforms(mockConfig);

    expect(issues).toHaveLength(2);
    expect(issues[0].source).toBe('github');
    expect(issues[1].source).toBe('jira');
    expect(issues[1].metadata?.platformKey).toBe('PROJ-123');
    expect(issues[1].repository.owner).toBe('owner');
    expect(issues[1].repository.name).toBe('repo');

    // Clean up env vars
    delete process.env.JIRA_HOST;
    delete process.env.JIRA_EMAIL;
    delete process.env.JIRA_API_TOKEN;
  });

  it('should handle errors gracefully and continue with other platforms', async () => {
    // Set Jira environment variables
    process.env.JIRA_HOST = 'test.atlassian.net';
    process.env.JIRA_EMAIL = 'test@example.com';
    process.env.JIRA_API_TOKEN = 'test-token';

    // Mock GitHub to throw error
    vi.mocked(githubIssues.detectIssues).mockRejectedValue(new Error('GitHub API error'));

    // Mock Jira to work normally
    const mockJiraAdapter = {
      searchIssues: vi.fn().mockResolvedValue([
        {
          id: 'jira-1001',
          platform: 'jira',
          key: 'PROJ-123',
          title: 'Jira Issue',
          description: 'Test issue',
          labels: ['autofix'],
          status: 'To Do',
          url: 'https://test.atlassian.net/browse/PROJ-123',
          createdAt: new Date(),
          updatedAt: new Date()
        }
      ])
    };

    vi.mocked(PlatformFactory.createAndAuthenticate).mockResolvedValue(mockJiraAdapter as any);

    const issues = await detectIssuesFromAllPlatforms(mockConfig);

    // Should still get Jira issues even though GitHub failed
    expect(issues).toHaveLength(1);
    expect(issues[0].source).toBe('jira');

    // Clean up env vars
    delete process.env.JIRA_HOST;
    delete process.env.JIRA_EMAIL;
    delete process.env.JIRA_API_TOKEN;
  });

  it('should extract repository info from Jira issue description', async () => {
    process.env.JIRA_HOST = 'test.atlassian.net';
    process.env.JIRA_EMAIL = 'test@example.com';
    process.env.JIRA_API_TOKEN = 'test-token';

    vi.mocked(githubIssues.detectIssues).mockResolvedValue([]);

    const mockJiraAdapter = {
      searchIssues: vi.fn().mockResolvedValue([
        {
          id: 'jira-1001',
          platform: 'jira',
          key: 'PROJ-456',
          title: 'Fix security issue',
          description: `
            There's a security vulnerability in our auth system.
            
            Repository: https://github.com/myorg/myapp
            File: src/auth/validator.js
            
            Please fix ASAP.
          `,
          labels: ['autofix', 'security'],
          status: 'To Do',
          url: 'https://test.atlassian.net/browse/PROJ-456',
          createdAt: new Date(),
          updatedAt: new Date()
        }
      ])
    };

    vi.mocked(PlatformFactory.createAndAuthenticate).mockResolvedValue(mockJiraAdapter as any);

    const issues = await detectIssuesFromAllPlatforms(mockConfig);

    expect(issues).toHaveLength(1);
    const issue = issues[0];
    expect(issue.repository.owner).toBe('myorg');
    expect(issue.repository.name).toBe('myapp');
    expect(issue.repository.fullName).toBe('myorg/myapp');
    expect(issue.labels).toContain('security');

    // Clean up env vars
    delete process.env.JIRA_HOST;
    delete process.env.JIRA_EMAIL;
    delete process.env.JIRA_API_TOKEN;
  });
});