/**
 * Mock implementation of Claude Code SDK for testing
 * Prevents actual process spawning in tests
 */

import { vi } from 'vitest';

// Mock the query function to prevent actual Claude Code process spawning
export const mockQuery = vi.fn(async function* (options: any) {
  // Simulate CLI-based execution without spawning processes
  const messages = [];
  
  // Add initial message
  messages.push({
    type: 'text',
    text: 'Analyzing the vulnerability...'
  });
  
  // Simulate file editing
  if (options.prompt?.includes('Edit') || options.prompt?.includes('fix')) {
    messages.push({
      type: 'tool_use',
      name: 'Edit',
      input: {
        file_path: 'src/vulnerable.js',
        old_string: 'eval(userInput)',
        new_string: 'safeEval(userInput)'
      }
    });
    
    messages.push({
      type: 'text',
      text: 'File successfully edited'
    });
  }
  
  // Simulate solution summary
  messages.push({
    type: 'text',
    text: `Solution complete. Here's the summary:
\`\`\`json
{
  "title": "Fix security vulnerability",
  "description": "Applied security patch via CLI",
  "files": [{
    "path": "src/vulnerable.js",
    "changes": "Replaced unsafe eval with safe alternative"
  }],
  "tests": ["Security test added", "No regressions"]
}
\`\`\``
  });
  
  // Yield messages
  for (const message of messages) {
    yield message;
  }
});

// Global state for mock git branches (persists across mock calls)
const mockGitState = {
  branches: new Set(['main']),
  currentBranch: 'main'
};

// Reset git state between tests
export function resetMockGitState() {
  mockGitState.branches = new Set(['main']);
  mockGitState.currentBranch = 'main';
}

// Mock the entire @anthropic-ai/claude-code module
export function setupClaudeCodeMock() {
  vi.mock('@anthropic-ai/claude-code', () => ({
    query: mockQuery,
    // Add other exports if needed
    version: '1.0.67',
    ClaudeCodeError: class ClaudeCodeError extends Error {
      constructor(message: string) {
        super(message);
        this.name = 'ClaudeCodeError';
      }
    }
  }));

  // Also mock child_process to prevent any subprocess spawning
  vi.mock('child_process', () => ({
    spawn: vi.fn(() => ({
      stdout: { on: vi.fn() },
      stderr: { on: vi.fn() },
      on: vi.fn((event, cb) => {
        if (event === 'close') {
          setTimeout(() => cb(0), 10);
        }
      }),
      kill: vi.fn()
    })),
    exec: vi.fn((cmd, opts, cb) => {
      const callback = cb || opts;
      if (typeof callback === 'function') {
        callback(null, '', '');
      }
    }),
    execSync: vi.fn((cmd) => {
      // Return appropriate responses for git commands
      if (cmd.includes('git status')) return '';
      if (cmd.includes('git diff --name-only')) return 'src/vulnerable.js';
      if (cmd.includes('git diff --stat')) return '1 file changed, 5 insertions(+), 3 deletions(-)';
      if (cmd.includes('git rev-parse HEAD')) return 'abc123def456';

      // Handle branch creation (git checkout -b)
      if (cmd.includes('git checkout -b')) {
        const match = cmd.match(/git checkout -b\s+["']?([^\s"']+)["']?/);
        if (match) {
          const branchName = match[1];
          mockGitState.branches.add(branchName);
          mockGitState.currentBranch = branchName;
        }
        return '';
      }

      // Handle branch switching (git checkout without -b)
      if (cmd.includes('git checkout') && !cmd.includes('-b')) {
        const match = cmd.match(/git checkout\s+["']?([^\s"']+)["']?/);
        if (match) {
          const branchName = match[1];
          if (mockGitState.branches.has(branchName)) {
            mockGitState.currentBranch = branchName;
            return '';
          } else {
            // Git checkout to non-existent branch should fail
            throw new Error(`error: pathspec '${branchName}' did not match any file(s) known to git`);
          }
        }
        return '';
      }

      // Handle branch listing
      if (cmd.includes('git branch')) {
        if (cmd.includes('--show-current')) {
          return mockGitState.currentBranch;
        }
        // Return list of branches with current branch marked
        return Array.from(mockGitState.branches)
          .map(b => b === mockGitState.currentBranch ? `* ${b}` : `  ${b}`)
          .join('\n');
      }

      if (cmd.includes('git config user.email')) return 'test@example.com';
      return '';
    })
  }));
}

// Setup function to be called in test setup
export function setupTestEnvironment() {
  // Set NODE_ENV to test
  process.env.NODE_ENV = 'test';
  
  // Disable actual Claude Code CLI execution
  delete process.env.CLAUDE_CODE_PATH;
  process.env.RSOLV_USE_CLI = 'false';
  process.env.FORCE_MOCK_CLAUDE_CODE = 'true';
  
  // Setup mocks
  setupClaudeCodeMock();
}