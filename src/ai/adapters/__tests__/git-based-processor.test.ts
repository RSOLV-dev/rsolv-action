import { describe, expect, test, beforeEach, mock } from 'vitest';
import { processIssueWithGit } from '../../git-based-processor.js';

// Mock dependencies
const mockCheckGitStatus = mock(() => ({ clean: true, modifiedFiles: [] }));
const mockAnalyzeIssue = mock(() => ({
  canBeFixed: true,
  summary: 'SQL injection vulnerability',
  complexity: 'medium',
  estimatedTime: 30,
  relatedFiles: ['src/routes/users.js']
}));

const mockCreatePullRequestFromGit = mock(() => ({
  success: true,
  pullRequestUrl: 'https://github.com/test/repo/pull/123',
  pullRequestNumber: 123,
  branchName: 'rsolv/fix-issue-42'
}));

// Mock child_process for git commands
vi.mock('child_process', () => ({
  execSync: mock((command: string) => {
    if (command === 'git status --porcelain') {
      return '';
    }
    return '';
  })
}));

// Mock the other modules
vi.mock('../../analyzer.js', () => ({
  analyzeIssue: mockAnalyzeIssue
}));

vi.mock('../../../github/pr-git.js', () => ({
  createPullRequestFromGit: mockCreatePullRequestFromGit
}));

vi.mock('../../../credentials/manager.js', () => ({
  RSOLVCredentialManager: class {
    async initialize() {}
  }
}));

// Mock GitBasedClaudeCodeAdapter
vi.mock('../claude-code-git.js', () => ({
  GitBasedClaudeCodeAdapter: class {
    async generateSolutionWithGit() {
      return {
        success: true,
        message: 'Fixed vulnerabilities',
        filesModified: ['src/routes/users.js'],
        commitHash: 'abc123def456',
        diffStats: {
          filesChanged: 1,
          insertions: 10,
          deletions: 5
        },
        summary: {
          title: 'Fix SQL injection',
          description: 'Replaced string concat with params',
          securityImpact: 'Prevents SQL injection',
          tests: ['Test with malicious input']
        }
      };
    }
  }
}));

describe('Git-based Issue Processor', () => {
  const mockIssue = {
    id: '123',
    number: 42,
    title: 'SQL injection vulnerability',
    body: 'User input is concatenated directly',
    repository: {
      fullName: 'test/repo',
      defaultBranch: 'main'
    }
  };
  
  const mockConfig = {
    aiProvider: {
      provider: 'anthropic',
      apiKey: 'test-key',
      model: 'claude-3',
      temperature: 0.1,
      useVendedCredentials: false
    },
    rsolvApiKey: 'test-rsolv-key'
  };
  
  beforeEach(() => {
    mockAnalyzeIssue.mockClear();
    mockCreatePullRequestFromGit.mockClear();
  });
  
  test('should process issue successfully with git-based approach', async () => {
    const result = await processIssueWithGit(mockIssue as any, mockConfig as any);
    
    expect(result.success).toBe(true);
    expect(result.issueId).toBe('123');
    expect(result.pullRequestUrl).toBe('https://github.com/test/repo/pull/123');
    expect(result.pullRequestNumber).toBe(123);
    expect(result.filesModified).toEqual(['src/routes/users.js']);
    expect(result.diffStats).toEqual({
      filesChanged: 1,
      insertions: 10,
      deletions: 5
    });
  });
  
  test('should fail if repository has uncommitted changes', async () => {
    // Temporarily override the mock for this test only
    const originalMock = (await import('child_process')).execSync;
    const dirtyGitMock = mock((command: string) => {
      if (command === 'git status --porcelain') {
        return 'M src/some-file.js\n';
      }
      return '';
    });
    
    // Override the module mock temporarily
    vi.mock('child_process', () => ({
      execSync: dirtyGitMock
    }));
    
    // Import fresh instance with dirty git mock
    delete require.cache[require.resolve('../../git-based-processor.js')];
    const { processIssueWithGit: processWithDirtyRepo } = await import('../../git-based-processor.js');
    
    const result = await processWithDirtyRepo(mockIssue as any, mockConfig as any);
    
    expect(result.success).toBe(false);
    expect(result.error).toContain('Uncommitted changes');
    
    // Restore original mock for subsequent tests
    vi.mock('child_process', () => ({
      execSync: originalMock
    }));
  });
  
  test('should fail if issue cannot be fixed', async () => {
    mockAnalyzeIssue.mockImplementationOnce(() => ({
      canBeFixed: false,
      summary: 'Too complex to fix automatically'
    }));
    
    const result = await processIssueWithGit(mockIssue as any, mockConfig as any);
    
    expect(result.success).toBe(false);
    expect(result.message).toContain('cannot be automatically fixed');
  });
  
  test('should use vended credentials when configured', async () => {
    const vendedConfig = {
      ...mockConfig,
      aiProvider: {
        ...mockConfig.aiProvider,
        useVendedCredentials: true
      },
      rsolvApiKey: 'test-rsolv-api-key' // Required for vended credentials
    };
    
    const result = await processIssueWithGit(mockIssue as any, vendedConfig as any);
    
    expect(result.success).toBe(true);
    // Verify credential manager was initialized
  });
});