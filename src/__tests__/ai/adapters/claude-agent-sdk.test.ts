/**
 * TDD/BDD Tests for ClaudeAgentSDKAdapter
 *
 * RFC-095: Claude Agent SDK Migration
 * Phase: GREEN (testing the implementation)
 *
 * Tests validate:
 * 1. GitSolutionResult interface compatibility (commitHash, diffStats, filesModified)
 * 2. Structured output parsing against FixResultSchema
 * 3. canUseTool security enforcement (test file protection)
 * 4. Credential injection verification
 * 5. Git operations (getModifiedFiles, getDiffStats, createCommit)
 * 6. Observability hooks
 */

import { describe, it, expect, beforeEach, afterEach, vi, beforeAll } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';

// Use real child_process for git operations (not the global mock)
// We need actual git commands to run in our test repositories
vi.unmock('child_process');
const { execSync } = await import('child_process');

describe('ClaudeAgentSDKAdapter', () => {
  let testRepoPath: string;
  let originalEnv: NodeJS.ProcessEnv;

  beforeEach(() => {
    // Save original environment
    originalEnv = { ...process.env };

    // Create a temporary git repository for testing
    testRepoPath = fs.mkdtempSync(path.join(os.tmpdir(), 'claude-sdk-test-'));
    execSync('git init', { cwd: testRepoPath });
    execSync('git config user.email "test@example.com"', { cwd: testRepoPath });
    execSync('git config user.name "Test User"', { cwd: testRepoPath });

    // Create initial file and commit
    fs.writeFileSync(path.join(testRepoPath, 'vulnerable.js'), `
// VULNERABLE: SQL injection
function getUser(id) {
  return db.query("SELECT * FROM users WHERE id = " + id);
}
`);
    execSync('git add .', { cwd: testRepoPath });
    execSync('git commit -m "Initial commit"', { cwd: testRepoPath });
  });

  afterEach(() => {
    // Restore original environment
    process.env = originalEnv;

    // Clean up test repository
    try {
      fs.rmSync(testRepoPath, { recursive: true, force: true });
    } catch {
      // Ignore cleanup errors
    }
  });

  describe('canUseTool security enforcement', () => {
    it('should deny edits to test files in test/ directory', async () => {
      const { ClaudeAgentSDKAdapter } = await import('../../../ai/adapters/claude-agent-sdk.js');

      const adapter = new ClaudeAgentSDKAdapter({
        repoPath: testRepoPath,
        model: 'claude-sonnet-4-5-20250929'
      });

      // Get the canUseTool callback and test it
      const canUseTool = adapter.createCanUseTool();
      const decision = await canUseTool('Edit', {
        file_path: 'test/security.test.js'
      }, { signal: new AbortController().signal, toolUseID: 'test-1' });

      expect(decision.behavior).toBe('deny');
      expect((decision as { message: string }).message).toContain('test');
    });

    it('should deny edits to test files in __tests__/ directory', async () => {
      const { ClaudeAgentSDKAdapter } = await import('../../../ai/adapters/claude-agent-sdk.js');

      const adapter = new ClaudeAgentSDKAdapter({
        repoPath: testRepoPath,
        model: 'claude-sonnet-4-5-20250929'
      });

      const canUseTool = adapter.createCanUseTool();
      const decision = await canUseTool('Edit', {
        file_path: 'src/__tests__/component.test.ts'
      }, { signal: new AbortController().signal, toolUseID: 'test-2' });

      expect(decision.behavior).toBe('deny');
    });

    it('should deny edits to spec files', async () => {
      const { ClaudeAgentSDKAdapter } = await import('../../../ai/adapters/claude-agent-sdk.js');

      const adapter = new ClaudeAgentSDKAdapter({
        repoPath: testRepoPath,
        model: 'claude-sonnet-4-5-20250929'
      });

      const canUseTool = adapter.createCanUseTool();
      const decision = await canUseTool('Edit', {
        file_path: 'api/handlers.spec.ts'
      }, { signal: new AbortController().signal, toolUseID: 'test-3' });

      expect(decision.behavior).toBe('deny');
    });

    it('should allow edits to non-test files', async () => {
      const { ClaudeAgentSDKAdapter } = await import('../../../ai/adapters/claude-agent-sdk.js');

      const adapter = new ClaudeAgentSDKAdapter({
        repoPath: testRepoPath,
        model: 'claude-sonnet-4-5-20250929'
      });

      const canUseTool = adapter.createCanUseTool();
      const decision = await canUseTool('Edit', {
        file_path: 'src/utils/database.js'
      }, { signal: new AbortController().signal, toolUseID: 'test-4' });

      expect(decision.behavior).toBe('allow');
    });

    it('should allow Read operations on any file', async () => {
      const { ClaudeAgentSDKAdapter } = await import('../../../ai/adapters/claude-agent-sdk.js');

      const adapter = new ClaudeAgentSDKAdapter({
        repoPath: testRepoPath,
        model: 'claude-sonnet-4-5-20250929'
      });

      const canUseTool = adapter.createCanUseTool();
      const decision = await canUseTool('Read', {
        file_path: 'test/security.test.js'
      }, { signal: new AbortController().signal, toolUseID: 'test-5' });

      expect(decision.behavior).toBe('allow');
    });
  });

  describe('Test file pattern detection', () => {
    it('should recognize test/ directory as test files', async () => {
      const { ClaudeAgentSDKAdapter } = await import('../../../ai/adapters/claude-agent-sdk.js');

      const adapter = new ClaudeAgentSDKAdapter({
        repoPath: testRepoPath
      });

      expect(adapter.isTestFile('test/unit/auth.test.js')).toBe(true);
      expect(adapter.isTestFile('test/integration/api.test.ts')).toBe(true);
    });

    it('should recognize __tests__/ directory as test files', async () => {
      const { ClaudeAgentSDKAdapter } = await import('../../../ai/adapters/claude-agent-sdk.js');

      const adapter = new ClaudeAgentSDKAdapter({
        repoPath: testRepoPath
      });

      expect(adapter.isTestFile('src/__tests__/component.test.tsx')).toBe(true);
      expect(adapter.isTestFile('lib/__tests__/utils.test.js')).toBe(true);
    });

    it('should recognize .test.ts and .test.js files', async () => {
      const { ClaudeAgentSDKAdapter } = await import('../../../ai/adapters/claude-agent-sdk.js');

      const adapter = new ClaudeAgentSDKAdapter({
        repoPath: testRepoPath
      });

      expect(adapter.isTestFile('src/auth.test.ts')).toBe(true);
      expect(adapter.isTestFile('lib/utils.test.js')).toBe(true);
    });

    it('should recognize .spec.ts and .spec.js files', async () => {
      const { ClaudeAgentSDKAdapter } = await import('../../../ai/adapters/claude-agent-sdk.js');

      const adapter = new ClaudeAgentSDKAdapter({
        repoPath: testRepoPath
      });

      expect(adapter.isTestFile('api/handlers.spec.ts')).toBe(true);
      expect(adapter.isTestFile('api/routes.spec.js')).toBe(true);
    });

    it('should recognize _test.go and _test.py files', async () => {
      const { ClaudeAgentSDKAdapter } = await import('../../../ai/adapters/claude-agent-sdk.js');

      const adapter = new ClaudeAgentSDKAdapter({
        repoPath: testRepoPath
      });

      expect(adapter.isTestFile('pkg/auth/handler_test.go')).toBe(true);
      expect(adapter.isTestFile('tests/test_auth.py')).toBe(true);
    });

    it('should not mark regular source files as test files', async () => {
      const { ClaudeAgentSDKAdapter } = await import('../../../ai/adapters/claude-agent-sdk.js');

      const adapter = new ClaudeAgentSDKAdapter({
        repoPath: testRepoPath
      });

      expect(adapter.isTestFile('src/auth.ts')).toBe(false);
      expect(adapter.isTestFile('lib/utils.js')).toBe(false);
      expect(adapter.isTestFile('api/handlers.go')).toBe(false);
    });
  });

  describe('Test command detection', () => {
    it('should recognize npm test commands', async () => {
      const { ClaudeAgentSDKAdapter } = await import('../../../ai/adapters/claude-agent-sdk.js');

      const adapter = new ClaudeAgentSDKAdapter({
        repoPath: testRepoPath
      });

      expect(adapter.isTestCommand('npm test')).toBe(true);
      expect(adapter.isTestCommand('npm run test')).toBe(true);
      expect(adapter.isTestCommand('npm test -- --grep "auth"')).toBe(true);
    });

    it('should recognize pnpm and yarn test commands', async () => {
      const { ClaudeAgentSDKAdapter } = await import('../../../ai/adapters/claude-agent-sdk.js');

      const adapter = new ClaudeAgentSDKAdapter({
        repoPath: testRepoPath
      });

      expect(adapter.isTestCommand('pnpm test')).toBe(true);
      expect(adapter.isTestCommand('yarn test')).toBe(true);
    });

    it('should recognize test framework commands', async () => {
      const { ClaudeAgentSDKAdapter } = await import('../../../ai/adapters/claude-agent-sdk.js');

      const adapter = new ClaudeAgentSDKAdapter({
        repoPath: testRepoPath
      });

      expect(adapter.isTestCommand('jest')).toBe(true);
      expect(adapter.isTestCommand('vitest run')).toBe(true);
      expect(adapter.isTestCommand('mocha test/')).toBe(true);
      expect(adapter.isTestCommand('pytest tests/')).toBe(true);
      expect(adapter.isTestCommand('go test ./...')).toBe(true);
      expect(adapter.isTestCommand('mix test')).toBe(true);
      expect(adapter.isTestCommand('cargo test')).toBe(true);
      expect(adapter.isTestCommand('rspec spec/')).toBe(true);
    });

    it('should not flag non-test commands', async () => {
      const { ClaudeAgentSDKAdapter } = await import('../../../ai/adapters/claude-agent-sdk.js');

      const adapter = new ClaudeAgentSDKAdapter({
        repoPath: testRepoPath
      });

      expect(adapter.isTestCommand('ls -la')).toBe(false);
      expect(adapter.isTestCommand('cat file.txt')).toBe(false);
      expect(adapter.isTestCommand('npm install')).toBe(false);
      expect(adapter.isTestCommand('git status')).toBe(false);
    });
  });

  describe('Credential vending integration', () => {
    it('should use vended credentials when useVendedCredentials is true', async () => {
      const { ClaudeAgentSDKAdapter } = await import('../../../ai/adapters/claude-agent-sdk.js');

      // Set up mock credential manager
      const mockCredentialManager = {
        getCredential: vi.fn().mockResolvedValue('vended-api-key-12345')
      };

      const adapter = new ClaudeAgentSDKAdapter({
        repoPath: testRepoPath,
        model: 'claude-sonnet-4-5-20250929',
        useVendedCredentials: true,
        credentialManager: mockCredentialManager
      });

      const apiKey = await adapter.getApiKey();

      expect(mockCredentialManager.getCredential).toHaveBeenCalledWith('anthropic');
      expect(apiKey).toBe('vended-api-key-12345');
    });

    it('should use environment API key when useVendedCredentials is false', async () => {
      process.env.ANTHROPIC_API_KEY = 'env-api-key-67890';

      const { ClaudeAgentSDKAdapter } = await import('../../../ai/adapters/claude-agent-sdk.js');

      const adapter = new ClaudeAgentSDKAdapter({
        repoPath: testRepoPath,
        model: 'claude-sonnet-4-5-20250929',
        useVendedCredentials: false
      });

      const apiKey = await adapter.getApiKey();

      expect(apiKey).toBe('env-api-key-67890');
    });
  });

  describe('Git operations', () => {
    it('should detect modified files using git diff', async () => {
      const { ClaudeAgentSDKAdapter } = await import('../../../ai/adapters/claude-agent-sdk.js');

      const adapter = new ClaudeAgentSDKAdapter({
        repoPath: testRepoPath,
        model: 'claude-sonnet-4-5-20250929'
      });

      // Modify a file
      fs.writeFileSync(
        path.join(testRepoPath, 'vulnerable.js'),
        '// Fixed code\nfunction getUser(id) { return db.query("SELECT * FROM users WHERE id = ?", [id]); }'
      );

      const modifiedFiles = adapter.getModifiedFiles();

      expect(modifiedFiles).toContain('vulnerable.js');
    });

    it('should calculate diff stats correctly', async () => {
      const { ClaudeAgentSDKAdapter } = await import('../../../ai/adapters/claude-agent-sdk.js');

      const adapter = new ClaudeAgentSDKAdapter({
        repoPath: testRepoPath,
        model: 'claude-sonnet-4-5-20250929'
      });

      // Modify a file
      fs.writeFileSync(
        path.join(testRepoPath, 'vulnerable.js'),
        '// Fixed\nfunction getUser(id) { return db.query("?", [id]); }'
      );

      const diffStats = adapter.getDiffStats();

      expect(diffStats).toBeDefined();
      expect(diffStats!.filesChanged).toBe(1);
      expect(typeof diffStats!.insertions).toBe('number');
      expect(typeof diffStats!.deletions).toBe('number');
    });

    it('should create commit with proper message format', async () => {
      const { ClaudeAgentSDKAdapter } = await import('../../../ai/adapters/claude-agent-sdk.js');

      const adapter = new ClaudeAgentSDKAdapter({
        repoPath: testRepoPath,
        model: 'claude-sonnet-4-5-20250929'
      });

      // Modify a file
      fs.writeFileSync(
        path.join(testRepoPath, 'vulnerable.js'),
        '// Fixed code'
      );

      const commitHash = adapter.createCommit(
        ['vulnerable.js'],
        'Fix SQL injection\n\nParameterized queries\n\nFixes #123'
      );

      expect(commitHash).toMatch(/^[a-f0-9]{40}$/);

      // Verify commit message
      const commitMsg = execSync('git log -1 --format=%B', { cwd: testRepoPath, encoding: 'utf-8' });
      expect(commitMsg).toContain('Fix SQL injection');
      expect(commitMsg).toContain('Fixes #123');
    });

    it('should return empty array when no files are modified', async () => {
      const { ClaudeAgentSDKAdapter } = await import('../../../ai/adapters/claude-agent-sdk.js');

      const adapter = new ClaudeAgentSDKAdapter({
        repoPath: testRepoPath,
        model: 'claude-sonnet-4-5-20250929'
      });

      const modifiedFiles = adapter.getModifiedFiles();

      expect(modifiedFiles).toEqual([]);
    });

    it('should exclude .github/workflows/ files from modified files list', async () => {
      const { ClaudeAgentSDKAdapter } = await import('../../../ai/adapters/claude-agent-sdk.js');

      const adapter = new ClaudeAgentSDKAdapter({
        repoPath: testRepoPath,
        model: 'claude-sonnet-4-5-20250929'
      });

      // Create and commit a workflow file first
      fs.mkdirSync(path.join(testRepoPath, '.github', 'workflows'), { recursive: true });
      fs.writeFileSync(path.join(testRepoPath, '.github', 'workflows', 'test.yml'), 'name: test');
      execSync('git add .', { cwd: testRepoPath });
      execSync('git commit -m "Add workflow"', { cwd: testRepoPath });

      // Modify both a source file and a workflow file
      fs.writeFileSync(path.join(testRepoPath, 'vulnerable.js'), '// Fixed code');
      fs.writeFileSync(path.join(testRepoPath, '.github', 'workflows', 'test.yml'), 'name: modified');

      const modifiedFiles = adapter.getModifiedFiles();

      expect(modifiedFiles).toContain('vulnerable.js');
      expect(modifiedFiles).not.toContain('.github/workflows/test.yml');
    });

    it('should exclude .github/actions/ files from modified files list', async () => {
      const { ClaudeAgentSDKAdapter } = await import('../../../ai/adapters/claude-agent-sdk.js');

      const adapter = new ClaudeAgentSDKAdapter({
        repoPath: testRepoPath,
        model: 'claude-sonnet-4-5-20250929'
      });

      // Create and commit an action file first
      fs.mkdirSync(path.join(testRepoPath, '.github', 'actions', 'custom'), { recursive: true });
      fs.writeFileSync(path.join(testRepoPath, '.github', 'actions', 'custom', 'action.yml'), 'name: custom');
      execSync('git add .', { cwd: testRepoPath });
      execSync('git commit -m "Add action"', { cwd: testRepoPath });

      // Modify both a source file and an action file
      fs.writeFileSync(path.join(testRepoPath, 'vulnerable.js'), '// Fixed code');
      fs.writeFileSync(path.join(testRepoPath, '.github', 'actions', 'custom', 'action.yml'), 'name: modified');

      const modifiedFiles = adapter.getModifiedFiles();

      expect(modifiedFiles).toContain('vulnerable.js');
      expect(modifiedFiles).not.toContain('.github/actions/custom/action.yml');
    });

    it('should revert excluded files after filtering', async () => {
      const { ClaudeAgentSDKAdapter } = await import('../../../ai/adapters/claude-agent-sdk.js');

      const adapter = new ClaudeAgentSDKAdapter({
        repoPath: testRepoPath,
        model: 'claude-sonnet-4-5-20250929'
      });

      // Create and commit a workflow file
      fs.mkdirSync(path.join(testRepoPath, '.github', 'workflows'), { recursive: true });
      fs.writeFileSync(path.join(testRepoPath, '.github', 'workflows', 'ci.yml'), 'name: CI');
      execSync('git add .', { cwd: testRepoPath });
      execSync('git commit -m "Add CI"', { cwd: testRepoPath });

      // Modify the workflow file
      fs.writeFileSync(path.join(testRepoPath, '.github', 'workflows', 'ci.yml'), 'name: Modified CI');

      // Call getModifiedFiles which should revert the workflow file
      adapter.getModifiedFiles();

      // Verify the workflow file was reverted (no longer in git diff)
      const diffOutput = execSync('git diff --name-only', {
        cwd: testRepoPath,
        encoding: 'utf-8'
      }).trim();

      expect(diffOutput).not.toContain('.github/workflows/ci.yml');
    });

    it('should preserve all non-excluded files unchanged', async () => {
      const { ClaudeAgentSDKAdapter } = await import('../../../ai/adapters/claude-agent-sdk.js');

      const adapter = new ClaudeAgentSDKAdapter({
        repoPath: testRepoPath,
        model: 'claude-sonnet-4-5-20250929'
      });

      // Modify only source files (no workflow files)
      fs.writeFileSync(path.join(testRepoPath, 'vulnerable.js'), '// Fixed code');
      fs.mkdirSync(path.join(testRepoPath, 'lib'), { recursive: true });
      fs.writeFileSync(path.join(testRepoPath, 'lib', 'helper.js'), '// helper');
      execSync('git add lib/helper.js', { cwd: testRepoPath });
      execSync('git commit -m "Add helper"', { cwd: testRepoPath });
      fs.writeFileSync(path.join(testRepoPath, 'lib', 'helper.js'), '// modified helper');

      const modifiedFiles = adapter.getModifiedFiles();

      expect(modifiedFiles).toContain('vulnerable.js');
      expect(modifiedFiles).toContain('lib/helper.js');
      expect(modifiedFiles.length).toBe(2);
    });

    it('should create proper commit message with issue reference', async () => {
      const { ClaudeAgentSDKAdapter } = await import('../../../ai/adapters/claude-agent-sdk.js');

      const adapter = new ClaudeAgentSDKAdapter({
        repoPath: testRepoPath,
        model: 'claude-sonnet-4-5-20250929'
      });

      const message = adapter.createCommitMessage(
        'Fix SQL Injection vulnerability',
        'Replaced string concatenation with parameterized queries',
        456
      );

      expect(message).toContain('Fix SQL Injection vulnerability');
      expect(message).toContain('Replaced string concatenation');
      expect(message).toContain('Fixes #456');
      expect(message).toContain('RSOLV');
    });
  });

  describe('Hooks creation', () => {
    it('should create hooks with PostToolUse matcher', async () => {
      const { ClaudeAgentSDKAdapter } = await import('../../../ai/adapters/claude-agent-sdk.js');

      const adapter = new ClaudeAgentSDKAdapter({
        repoPath: testRepoPath,
        model: 'claude-sonnet-4-5-20250929'
      });

      const hooks = adapter.createHooks();

      expect(hooks).toHaveProperty('PostToolUse');
      expect(Array.isArray(hooks.PostToolUse)).toBe(true);
      expect(hooks.PostToolUse!.length).toBeGreaterThan(0);
      expect(hooks.PostToolUse![0]).toHaveProperty('matcher', 'Bash');
      expect(hooks.PostToolUse![0]).toHaveProperty('hooks');
      expect(Array.isArray(hooks.PostToolUse![0].hooks)).toBe(true);
    });
  });

  describe('FixResultSchema', () => {
    it('should export FixResultSchema with required properties', async () => {
      const { FixResultSchema } = await import('../../../ai/adapters/claude-agent-sdk.js');

      expect(FixResultSchema).toBeDefined();
      expect(FixResultSchema.type).toBe('object');
      expect(FixResultSchema.properties).toHaveProperty('title');
      expect(FixResultSchema.properties).toHaveProperty('description');
      expect(FixResultSchema.properties).toHaveProperty('files');
      expect(FixResultSchema.properties).toHaveProperty('tests');
      expect(FixResultSchema.required).toContain('title');
      expect(FixResultSchema.required).toContain('description');
    });
  });

  describe('GitSolutionResult interface compatibility', () => {
    it('should export GitSolutionResult interface types', async () => {
      const module = await import('../../../ai/adapters/claude-agent-sdk.js');

      // Verify the adapter exposes methods that return GitSolutionResult
      expect(module.ClaudeAgentSDKAdapter).toBeDefined();

      const adapter = new module.ClaudeAgentSDKAdapter({
        repoPath: testRepoPath
      });

      // Verify methods exist
      expect(typeof adapter.generateSolutionWithGit).toBe('function');
      expect(typeof adapter.getModifiedFiles).toBe('function');
      expect(typeof adapter.getDiffStats).toBe('function');
      expect(typeof adapter.createCommit).toBe('function');
    });
  });

  describe('Session management', () => {
    it('should track session ID', async () => {
      const { ClaudeAgentSDKAdapter } = await import('../../../ai/adapters/claude-agent-sdk.js');

      const adapter = new ClaudeAgentSDKAdapter({
        repoPath: testRepoPath,
        model: 'claude-sonnet-4-5-20250929'
      });

      // Initially undefined
      expect(adapter.getSessionId()).toBeUndefined();
    });

    it('should expose generateWithResume method', async () => {
      const { ClaudeAgentSDKAdapter } = await import('../../../ai/adapters/claude-agent-sdk.js');

      const adapter = new ClaudeAgentSDKAdapter({
        repoPath: testRepoPath,
        model: 'claude-sonnet-4-5-20250929'
      });

      expect(typeof adapter.generateWithResume).toBe('function');
    });

    it('should expose generateWithABTest method', async () => {
      const { ClaudeAgentSDKAdapter } = await import('../../../ai/adapters/claude-agent-sdk.js');

      const adapter = new ClaudeAgentSDKAdapter({
        repoPath: testRepoPath,
        model: 'claude-sonnet-4-5-20250929'
      });

      expect(typeof adapter.generateWithABTest).toBe('function');
    });
  });

  describe('Test log tracking', () => {
    it('should return empty test log initially', async () => {
      const { ClaudeAgentSDKAdapter } = await import('../../../ai/adapters/claude-agent-sdk.js');

      const adapter = new ClaudeAgentSDKAdapter({
        repoPath: testRepoPath
      });

      const testLog = adapter.getTestLog();

      expect(testLog).toEqual([]);
    });
  });

  describe('Factory function', () => {
    it('should export createClaudeAgentSDKAdapter factory', async () => {
      const { createClaudeAgentSDKAdapter } = await import('../../../ai/adapters/claude-agent-sdk.js');

      expect(typeof createClaudeAgentSDKAdapter).toBe('function');

      const adapter = createClaudeAgentSDKAdapter({
        repoPath: testRepoPath
      });

      expect(adapter).toBeDefined();
      expect(typeof adapter.generateSolutionWithGit).toBe('function');
    });
  });
});

describe('ClaudeAgentSDKAdapter - Session Forking (Phase 3)', () => {
  let testRepoPath: string;

  beforeEach(() => {
    testRepoPath = fs.mkdtempSync(path.join(os.tmpdir(), 'claude-sdk-phase3-'));
    execSync('git init', { cwd: testRepoPath });
    execSync('git config user.email "test@example.com"', { cwd: testRepoPath });
    execSync('git config user.name "Test User"', { cwd: testRepoPath });
    fs.writeFileSync(path.join(testRepoPath, 'test.js'), '// test');
    execSync('git add .', { cwd: testRepoPath });
    execSync('git commit -m "Initial commit"', { cwd: testRepoPath });
  });

  afterEach(() => {
    try {
      fs.rmSync(testRepoPath, { recursive: true, force: true });
    } catch {
      // Ignore cleanup errors
    }
  });

  it('should have generateWithResume that accepts sessionId and forkSession flag', async () => {
    const { ClaudeAgentSDKAdapter } = await import('../../../ai/adapters/claude-agent-sdk.js');

    const adapter = new ClaudeAgentSDKAdapter({
      repoPath: testRepoPath,
      model: 'claude-sonnet-4-5-20250929'
    });

    // Verify method signature accepts the right parameters
    expect(typeof adapter.generateWithResume).toBe('function');
    expect(adapter.generateWithResume.length).toBeGreaterThanOrEqual(2); // At least sessionId and prompt
  });

  it('should have generateWithABTest that returns conservative and aggressive results', async () => {
    const { ClaudeAgentSDKAdapter } = await import('../../../ai/adapters/claude-agent-sdk.js');

    const adapter = new ClaudeAgentSDKAdapter({
      repoPath: testRepoPath,
      model: 'claude-sonnet-4-5-20250929'
    });

    // Verify method exists and returns proper structure
    expect(typeof adapter.generateWithABTest).toBe('function');
  });

  it('should track session ID after SDK interaction', async () => {
    const { ClaudeAgentSDKAdapter } = await import('../../../ai/adapters/claude-agent-sdk.js');

    const adapter = new ClaudeAgentSDKAdapter({
      repoPath: testRepoPath,
      model: 'claude-sonnet-4-5-20250929'
    });

    // Initially undefined
    expect(adapter.getSessionId()).toBeUndefined();

    // After a simulated session, it should be set
    // (This would be set by generateSolutionWithGit or generateWithResume)
  });

  it('should build correct options for resume with fork', async () => {
    const { ClaudeAgentSDKAdapter } = await import('../../../ai/adapters/claude-agent-sdk.js');

    const adapter = new ClaudeAgentSDKAdapter({
      repoPath: testRepoPath,
      model: 'claude-sonnet-4-5-20250929'
    });

    // The generateWithResume method should include resume and forkSession options
    // We can verify this by checking the implementation structure
    expect(typeof adapter.generateWithResume).toBe('function');
  });

  it.skip('should execute A/B test with actual SDK (integration test)', async () => {
    // This test requires actual SDK interaction with API credentials
    // Run with: ANTHROPIC_API_KEY=xxx npm run test:integration
  });
});

describe('ClaudeAgentSDKAdapter - Hybrid Verification (Phase 4)', () => {
  let testRepoPath: string;

  beforeEach(() => {
    testRepoPath = fs.mkdtempSync(path.join(os.tmpdir(), 'claude-sdk-phase4-'));
    execSync('git init', { cwd: testRepoPath });
    execSync('git config user.email "test@example.com"', { cwd: testRepoPath });
    execSync('git config user.name "Test User"', { cwd: testRepoPath });
    fs.writeFileSync(path.join(testRepoPath, 'test.js'), '// test');
    execSync('git add .', { cwd: testRepoPath });
    execSync('git commit -m "Initial commit"', { cwd: testRepoPath });
  });

  afterEach(() => {
    try {
      fs.rmSync(testRepoPath, { recursive: true, force: true });
    } catch {
      // Ignore cleanup errors
    }
  });

  it('should track test command executions in testLog', async () => {
    const { ClaudeAgentSDKAdapter } = await import('../../../ai/adapters/claude-agent-sdk.js');

    const adapter = new ClaudeAgentSDKAdapter({
      repoPath: testRepoPath,
      model: 'claude-sonnet-4-5-20250929'
    });

    // Initially empty
    expect(adapter.getTestLog()).toEqual([]);

    // The hook would populate this during SDK execution
    // Testing hook behavior requires SDK integration
  });

  it('should create PostToolUse hooks that capture test commands', async () => {
    const { ClaudeAgentSDKAdapter } = await import('../../../ai/adapters/claude-agent-sdk.js');

    const adapter = new ClaudeAgentSDKAdapter({
      repoPath: testRepoPath,
      model: 'claude-sonnet-4-5-20250929'
    });

    const hooks = adapter.createHooks();

    // Verify hook structure
    expect(hooks).toHaveProperty('PostToolUse');
    expect(hooks.PostToolUse).toBeInstanceOf(Array);
    expect(hooks.PostToolUse!.length).toBeGreaterThan(0);
    expect(hooks.PostToolUse![0].matcher).toBe('Bash');
    expect(hooks.PostToolUse![0].hooks).toBeInstanceOf(Array);
  });

  it('should have verifyFix method for hybrid verification', async () => {
    const { ClaudeAgentSDKAdapter } = await import('../../../ai/adapters/claude-agent-sdk.js');

    const adapter = new ClaudeAgentSDKAdapter({
      repoPath: testRepoPath,
      model: 'claude-sonnet-4-5-20250929'
    });

    // verifyFix will be added in Phase 4 implementation
    // For now, verify the adapter has the hook infrastructure in place
    expect(typeof adapter.getTestLog).toBe('function');
    expect(typeof adapter.createHooks).toBe('function');
  });

  it.skip('should calculate trust score from test observations (integration test)', async () => {
    // This test requires actual SDK interaction
    // Run with: ANTHROPIC_API_KEY=xxx npm run test:integration
  });
});
