import { test, expect, mock, beforeEach } from 'bun:test';
import { GitHubFileManager } from '../files.js';

// Mock data
const mockOwner = 'test-owner';
const mockRepo = 'test-repo';
const mockToken = 'test-token';
const mockFilePath = 'path/to/file.txt';
const mockContent = 'This is the file content';
const mockSha = '123abc';
const mockBranch = 'test-branch';

// Mock octokit
const mockOctokit = {
  rest: {
    repos: {
      getContent: mock(() => Promise.resolve({
        data: {
          content: Buffer.from(mockContent).toString('base64'),
          sha: mockSha
        }
      })),
      createOrUpdateFileContents: mock(() => Promise.resolve({
        data: {
          content: {
            sha: 'new-sha-123'
          }
        }
      })),
      compareCommits: mock(() => Promise.resolve({
        data: {
          files: [
            {
              filename: 'file1.txt',
              status: 'modified',
              additions: 10,
              deletions: 5,
              changes: 15,
              patch: '@@ -1,5 +1,10 @@'
            }
          ]
        }
      }))
    },
    git: {
      getRef: mock(() => Promise.resolve({
        data: {
          object: {
            sha: 'base-sha-123'
          }
        }
      })),
      createRef: mock(() => Promise.resolve({ data: {} }))
    }
  }
};

// Mock github module
mock.module('@actions/github', () => ({
  getOctokit: () => mockOctokit
}));

// Setup for tests
let fileManager: GitHubFileManager;

beforeEach(() => {
  // Reset mocks
  mockOctokit.rest.repos.getContent.mockClear();
  mockOctokit.rest.repos.createOrUpdateFileContents.mockClear();
  mockOctokit.rest.git.getRef.mockClear();
  mockOctokit.rest.git.createRef.mockClear();
  
  // Create fresh instance for each test
  fileManager = new GitHubFileManager(mockToken, mockOwner, mockRepo);
});

test('getFileContent should return content and SHA', async () => {
  const result = await fileManager.getFileContent(mockFilePath);
  
  expect(mockOctokit.rest.repos.getContent).toHaveBeenCalledWith({
    owner: mockOwner,
    repo: mockRepo,
    path: mockFilePath,
    ref: undefined
  });
  
  expect(result.content).toBe(mockContent);
  expect(result.sha).toBe(mockSha);
});

test('getFileContent should include ref when provided', async () => {
  await fileManager.getFileContent(mockFilePath, mockBranch);
  
  expect(mockOctokit.rest.repos.getContent).toHaveBeenCalledWith({
    owner: mockOwner,
    repo: mockRepo,
    path: mockFilePath,
    ref: mockBranch
  });
});

test('updateFile should call GitHub API correctly', async () => {
  const commitMessage = 'Update file';
  
  await fileManager.updateFile(
    mockFilePath,
    mockContent,
    commitMessage,
    mockBranch,
    mockSha
  );
  
  expect(mockOctokit.rest.repos.createOrUpdateFileContents).toHaveBeenCalledWith({
    owner: mockOwner,
    repo: mockRepo,
    path: mockFilePath,
    message: commitMessage,
    content: Buffer.from(mockContent).toString('base64'),
    branch: mockBranch,
    sha: mockSha
  });
});

test('updateMultipleFiles should process each file', async () => {
  // Mock getFileContent to return different content to trigger update
  mockOctokit.rest.repos.getContent.mockImplementation(() => 
    Promise.resolve({
      data: {
        content: Buffer.from('Different content').toString('base64'),
        sha: 'different-sha'
      }
    })
  );
  
  const files = [
    { path: 'file1.txt', content: 'Content 1' },
    { path: 'file2.txt', content: 'Content 2' }
  ];
  
  await fileManager.updateMultipleFiles(files, 'Update multiple files', mockBranch);
  
  // Should have been called twice (once per file)
  expect(mockOctokit.rest.repos.createOrUpdateFileContents).toHaveBeenCalledTimes(2);
});

test('getReference should return SHA', async () => {
  const result = await fileManager.getReference('heads/main');
  
  expect(mockOctokit.rest.git.getRef).toHaveBeenCalledWith({
    owner: mockOwner,
    repo: mockRepo,
    ref: 'heads/main'
  });
  
  expect(result).toBe('base-sha-123');
});

test('createBranch should call GitHub API correctly', async () => {
  await fileManager.createBranch('new-branch', 'base-sha-123');
  
  expect(mockOctokit.rest.git.createRef).toHaveBeenCalledWith({
    owner: mockOwner,
    repo: mockRepo,
    ref: 'refs/heads/new-branch',
    sha: 'base-sha-123'
  });
});

test('branchExists should return true when branch exists', async () => {
  const result = await fileManager.branchExists('existing-branch');
  
  expect(mockOctokit.rest.git.getRef).toHaveBeenCalledWith({
    owner: mockOwner,
    repo: mockRepo,
    ref: 'heads/existing-branch'
  });
  
  expect(result).toBe(true);
});

test('branchExists should return false when branch does not exist', async () => {
  mockOctokit.rest.git.getRef.mockImplementationOnce(() => {
    const error: any = new Error('Not Found');
    error.status = 404;
    return Promise.reject(error);
  });
  
  const result = await fileManager.branchExists('non-existing-branch');
  
  expect(result).toBe(false);
});

test('getDiff should return file differences', async () => {
  const result = await fileManager.getDiff('main', 'feature');
  
  expect(mockOctokit.rest.repos.compareCommits).toHaveBeenCalledWith({
    owner: mockOwner,
    repo: mockRepo,
    base: 'main',
    head: 'feature'
  });
  
  expect(result).toHaveLength(1);
  expect(result[0].path).toBe('file1.txt');
  expect(result[0].status).toBe('modified');
  expect(result[0].patch).toBe('@@ -1,5 +1,10 @@');
});