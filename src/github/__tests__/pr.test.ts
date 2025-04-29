import { test, expect, mock, beforeEach } from 'bun:test';
import { GitHubPRManager } from '../pr';
import { IssueContext } from '../../types';
import { PullRequestSolution } from '../../ai/types';

// Mock GitHubApiClient
const mockCreatePullRequest = mock(() => Promise.resolve(123));
const mockCommentOnIssue = mock(() => Promise.resolve());

// Mock GitHubFileManager
const mockBranchExists = mock(() => Promise.resolve(false));
const mockGetReference = mock(() => Promise.resolve('base-sha-123'));
const mockCreateBranch = mock(() => Promise.resolve());
const mockUpdateMultipleFiles = mock(() => Promise.resolve());

// Mock GitHub module for createComment and addLabels
const mockCreateComment = mock(() => Promise.resolve());
const mockAddLabels = mock(() => Promise.resolve());
const mockAddAssignees = mock(() => Promise.resolve());

mock.module('../api', () => ({
  GitHubApiClient: class {
    constructor() {}
    createPullRequest = mockCreatePullRequest;
  }
}));

mock.module('../files', () => ({
  GitHubFileManager: class {
    constructor() {}
    branchExists = mockBranchExists;
    getReference = mockGetReference;
    createBranch = mockCreateBranch;
    updateMultipleFiles = mockUpdateMultipleFiles;
  }
}));

mock.module('@actions/github', () => ({
  getOctokit: () => ({
    rest: {
      issues: {
        createComment: mockCreateComment,
        addLabels: mockAddLabels,
        addAssignees: mockAddAssignees
      }
    }
  })
}));

// Setup for tests
let prManager: GitHubPRManager;

beforeEach(() => {
  // Reset mocks
  mockCreatePullRequest.mockClear();
  mockBranchExists.mockClear();
  mockGetReference.mockClear();
  mockCreateBranch.mockClear();
  mockUpdateMultipleFiles.mockClear();
  mockCreateComment.mockClear();
  mockAddLabels.mockClear();
  mockAddAssignees.mockClear();
  
  // Create fresh instance for each test
  prManager = new GitHubPRManager('test-token', 'test-owner', 'test-repo');
});

test('createPullRequestFromSolution should create a PR with the solution', async () => {
  // Test data
  const issueContext: IssueContext = {
    id: '42',
    source: 'github',
    title: 'Fix the bug',
    body: 'There is a bug that needs fixing',
    labels: ['bug', 'AUTOFIX'],
    repository: {
      owner: 'test-owner',
      name: 'test-repo',
      branch: 'main'
    },
    metadata: {},
    url: 'https://github.com/test-owner/test-repo/issues/42'
  };
  
  const solution: PullRequestSolution = {
    title: 'Fix: Update error handling',
    description: 'This PR fixes the error handling',
    files: [
      {
        path: 'src/component.ts',
        changes: 'Updated component code'
      }
    ],
    tests: ['Test the fix']
  };
  
  const result = await prManager.createPullRequestFromSolution(issueContext, solution);
  
  // Verify branch creation
  expect(mockBranchExists).toHaveBeenCalled();
  expect(mockGetReference).toHaveBeenCalledWith('heads/main');
  expect(mockCreateBranch).toHaveBeenCalled();
  
  // Verify file updates
  expect(mockUpdateMultipleFiles).toHaveBeenCalledWith(
    [{ path: 'src/component.ts', content: 'Updated component code' }],
    'Apply AI-generated solution',
    expect.any(String) // Branch name will be generated
  );
  
  // Verify PR creation
  expect(mockCreatePullRequest).toHaveBeenCalledWith(
    'Fix: Update error handling',
    expect.stringContaining('Issue Summary'), // PR body
    expect.stringMatching(/^fix-42-/), // Branch name
    'main'
  );
  
  // Verify result
  expect(result.prNumber).toBe(123);
  expect(result.prUrl).toBe('https://github.com/test-owner/test-repo/pull/123');
});

test('generateBranchName should create a valid branch name', async () => {
  const issueContext: IssueContext = {
    id: '42',
    source: 'github',
    title: 'This is a very long issue title with special characters: @#$%^&*()!',
    body: 'Issue body',
    labels: [],
    repository: {
      owner: 'test-owner',
      name: 'test-repo'
    },
    metadata: {}
  };
  
  // We need to access the private method - this is a bit hacky for testing
  const branchName = (prManager as any).generateBranchName(issueContext);
  
  expect(branchName).toMatch(/^fix-42-this-is-a-very-long-issue/);
  expect(branchName).not.toContain('@#$%^&*()!');
  expect(branchName.length).toBeLessThanOrEqual(50); // Branch names shouldn't be too long
});

test('formatPRDescription should format the PR description correctly', async () => {
  const issueContext: IssueContext = {
    id: '42',
    source: 'github',
    title: 'Fix the bug',
    body: 'There is a bug',
    labels: [],
    repository: {
      owner: 'test-owner',
      name: 'test-repo'
    },
    metadata: {}
  };
  
  const solution: PullRequestSolution = {
    title: 'Fix: Update error handling',
    description: 'This PR fixes the error handling',
    files: [
      {
        path: 'src/component.ts',
        changes: 'Updated component code'
      },
      {
        path: 'src/utils.ts',
        changes: 'Updated utils'
      }
    ],
    tests: ['Test 1', 'Test 2']
  };
  
  const description = (prManager as any).formatPRDescription(issueContext, solution);
  
  expect(description).toContain('## Issue Summary');
  expect(description).toContain('Fix the bug');
  expect(description).toContain('## Changes Made');
  expect(description).toContain('This PR fixes the error handling');
  expect(description).toContain('## Files Changed');
  expect(description).toContain('- src/component.ts');
  expect(description).toContain('- src/utils.ts');
  expect(description).toContain('## Tests');
  expect(description).toContain('- Test 1');
  expect(description).toContain('- Test 2');
  expect(description).toContain('## Closes');
  expect(description).toContain('Closes #42');
  expect(description).toContain('## Request Expert Review');
  expect(description).toContain('/request-expert-review');
});

test('requestExpertReview should request a review and send notification', async () => {
  await prManager.requestExpertReview(123, 'expert-username');
  
  // Verify labels added
  expect(mockAddLabels).toHaveBeenCalledWith({
    owner: 'test-owner',
    repo: 'test-repo',
    issue_number: 123,
    labels: ['expert-review-requested']
  });
  
  // Verify comment added
  expect(mockCreateComment).toHaveBeenCalledWith({
    owner: 'test-owner',
    repo: 'test-repo',
    issue_number: 123,
    body: expect.stringContaining('@expert-username')
  });
  
  // Verify assignee added
  expect(mockAddAssignees).toHaveBeenCalledWith({
    owner: 'test-owner',
    repo: 'test-repo',
    issue_number: 123,
    assignees: ['expert-username']
  });
});

test('requestExpertReview should work without a specific expert', async () => {
  await prManager.requestExpertReview(123);
  
  // Verify expert not assigned but review still requested
  expect(mockAddLabels).toHaveBeenCalled();
  expect(mockCreateComment).toHaveBeenCalledWith({
    owner: 'test-owner',
    repo: 'test-repo',
    issue_number: 123,
    body: expect.stringContaining('@RSOLV-expert')
  });
  
  // Assignees should not be called
  expect(mockAddAssignees).not.toHaveBeenCalled();
});