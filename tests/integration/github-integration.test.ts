import { describe, expect, test, mock, beforeEach } from 'bun:test';
import { detectIssues } from '../../src/github/issues.js';
import { createPullRequest } from '../../src/github/pr.js';
import { getRepositoryFiles } from '../../src/github/files.js';
import { IssueContext, ActionConfig, AnalysisData } from '../../src/types/index.js';

// Mock the logger module first
mock.module('../../src/utils/logger.js', () => ({
  logger: {
    info: mock(() => {}),
    warn: mock(() => {}),
    error: mock(() => {}),
    debug: mock(() => {}),
    log: mock(() => {})
  }
}));

// Mock the GitHub API client
mock.module('../../src/github/api.js', () => {
  return {
    getGitHubClient: () => ({
      repos: {
        getContent: async ({ owner, repo, path, ref }: any) => {
          if (path === 'not-found.js') {
            throw { status: 404, message: 'Not found' };
          }
          
          return {
            data: {
              sha: 'abc123',
              content: Buffer.from('// Mock file content').toString('base64')
            }
          };
        },
        createOrUpdateFileContents: async () => ({ data: { commit: { sha: 'def456' } } }),
      },
      git: {
        getRef: async ({ ref }: any) => ({ data: { object: { sha: '789xyz' } } }),
        createRef: async () => ({ data: { ref: 'refs/heads/test-branch' } })
      },
      pulls: {
        create: async ({ title, head, base }: any) => ({
          data: {
            number: 123,
            html_url: 'https://github.com/test-owner/test-repo/pull/123'
          }
        })
      },
      issues: {
        listForRepo: async ({ labels }: any) => ({
          data: [
            {
              id: 'issue-1',
              number: 42,
              title: 'Test Issue',
              body: 'This is a test issue',
              labels: [{ name: labels }],
              assignees: [],
              created_at: '2025-03-23T00:00:00Z',
              updated_at: '2025-03-23T01:00:00Z',
              html_url: 'https://github.com/test-owner/test-repo/issues/42'
            }
          ]
        }),
        addLabels: async () => ({}),
        createComment: async () => ({})
      }
    }),
    getRepositoryDetails: async () => ({
      id: 'repo-123',
      name: 'test-repo',
      fullName: 'test-owner/test-repo',
      owner: 'test-owner',
      defaultBranch: 'main',
      language: 'TypeScript'
    })
  };
});

// Mock the AI client
mock.module('../../src/ai/client.js', () => ({
  getAiClient: () => ({
    complete: async (prompt: string) => {
      return 'This pull request fixes the authentication bug reported in issue #42.\n\n## Changes\n- Fixed token validation\n- Added proper error handling\n\n## Testing\n- Added unit tests\n- Manual testing completed';
    }
  })
}));

// Mock configuration for tests
const mockConfig: ActionConfig = {
  apiKey: 'test-api-key',
  configPath: '.github/rsolv.yml',
  issueLabel: 'rsolv:automate',
  aiProvider: {
    provider: 'anthropic',
    model: 'claude-3-sonnet-20240229'
  },
  containerConfig: {
    enabled: false
  },
  securitySettings: {
    disableNetworkAccess: true,
    preventSecretLeakage: true
  }
};

// Mock issue data
const mockIssue: IssueContext = {
  id: 'github-123',
  number: 42,
  title: 'Fix bug in authentication',
  body: 'There is a bug in the authentication system.',
  labels: ['bug', 'rsolv:automate'],
  assignees: [],
  repository: {
    owner: 'test-owner',
    name: 'test-repo',
    fullName: 'test-owner/test-repo',
    defaultBranch: 'main',
    language: 'TypeScript'
  },
  source: 'github',
  createdAt: '2025-03-23T00:00:00Z',
  updatedAt: '2025-03-23T01:00:00Z'
};

// Mock analysis data
const mockAnalysis: AnalysisData = {
  issueType: 'bug',
  filesToModify: ['src/auth.ts', 'src/utils.ts'],
  estimatedComplexity: 'medium',
  requiredContext: [],
  suggestedApproach: 'Fix the authentication token validation'
};

describe('GitHub Integration', () => {
  beforeEach(() => {
    // Set environment variables for tests
    process.env.GITHUB_REPOSITORY = 'test-owner/test-repo';
    process.env.GITHUB_TOKEN = 'test-token';
    process.env.NODE_ENV = 'test';
  });
  
  test('detectIssues should find issues with automation label', async () => {
    const issues = await detectIssues(mockConfig);
    
    expect(issues).toBeDefined();
    expect(issues.length).toBeGreaterThan(0);
    expect(issues[0].number).toBe(42);
  });
  
  test('getRepositoryFiles should fetch file contents', async () => {
    const filePaths = ['src/auth.ts', 'src/utils.ts'];
    const fileContents = await getRepositoryFiles(mockIssue, filePaths);
    
    expect(fileContents).toBeDefined();
    expect(Object.keys(fileContents).length).toBe(2);
    expect(fileContents['src/auth.ts']).toBeDefined();
    expect(fileContents['src/utils.ts']).toBeDefined();
  });
  
  test('getRepositoryFiles should handle file not found', async () => {
    const filePaths = ['not-found.js'];
    const fileContents = await getRepositoryFiles(mockIssue, filePaths);
    
    expect(fileContents).toBeDefined();
    // In test mode, it should still return a mock file
    expect(Object.keys(fileContents).length).toBe(1);
  });
  
  test('createPullRequest should create a PR with file changes', async () => {
    const changes = {
      'src/auth.ts': 'export function authenticate() { /* fixed */ }',
      'src/utils.ts': 'export function validate() { /* fixed */ }'
    };
    
    const result = await createPullRequest(mockIssue, changes, mockAnalysis, mockConfig);
    
    expect(result.success).toBe(true);
    expect(result.pullRequestUrl).toBeDefined();
    expect(result.pullRequestNumber).toBeDefined();
  });
});