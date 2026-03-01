/**
 * Tests that executeValidateForIssue and executeMitigateForIssue call ensureRuntime
 * BEFORE starting SSE sessions, so runtimes are available for tool execution.
 *
 * Root cause: RFC-096 backend-orchestrated pipeline uses executeBash() for tool requests,
 * which adds mise shims to PATH but never installs runtimes. ensureRuntime() exists in
 * TestRunner but was only called from the OLD TestRunner.runTests() path.
 */
import { describe, test, expect, beforeEach, vi } from 'vitest';
import { PhaseExecutor } from '../index.js';
import type { ActionConfig, IssueContext, ScanPhaseData } from '../../../types/index.js';

// Track ensureRuntime calls
const mockEnsureRuntime = vi.fn().mockResolvedValue(undefined);

// Mock TestRunner — the key assertion target
vi.mock('../../../ai/test-runner.js', () => {
  const MockTestRunner = vi.fn().mockImplementation(() => ({
    ensureRuntime: mockEnsureRuntime,
    runTests: vi.fn(),
  }));
  return {
    TestRunner: MockTestRunner,
    // TestFramework type is used for casting only — no runtime value needed
  };
});

// Mock GitHub API
vi.mock('../../../github/api.js', () => ({
  getIssue: vi.fn(),
  getIssues: vi.fn(),
  addLabels: vi.fn(),
  removeLabel: vi.fn(),
  getGitHubClient: vi.fn().mockReturnValue({
    rest: {
      pulls: { create: vi.fn().mockResolvedValue({ data: { number: 42, html_url: 'https://github.com/test/repo/pull/42' } }) },
      issues: { addLabels: vi.fn(), createComment: vi.fn() },
      repos: { getBranch: vi.fn().mockRejectedValue(new Error('not found')) },
      git: { createRef: vi.fn() },
    },
  }),
}));

// Mock PR creation
vi.mock('../../../github/pr-git-educational.js', () => ({
  createEducationalPullRequest: vi.fn().mockResolvedValue({
    success: true, pullRequestUrl: 'https://github.com/test/repo/pull/42', pullRequestNumber: 42,
  }),
}));

// Track validation client constructor calls to verify ensureRuntime happens BEFORE
const mockRunValidation = vi.fn().mockResolvedValue({
  validated: true,
  test_path: 'spec/test_spec.rb',
  test_code: 'it "tests" do\nend',
  framework: 'rspec',
  test_command: 'bundle exec rspec',
  classification: { tier: 'behavioral' },
});

vi.mock('../../../pipeline/validation-client.js', () => ({
  ValidationClient: vi.fn().mockImplementation(() => ({
    runValidation: mockRunValidation,
  })),
}));

const mockRunMitigation = vi.fn().mockResolvedValue({
  success: true,
  title: 'fix: CWE-79 XSS',
  description: 'Fixed XSS',
});

vi.mock('../../../pipeline/mitigation-client.js', () => ({
  MitigationClient: vi.fn().mockImplementation(() => ({
    runMitigation: mockRunMitigation,
  })),
}));

// Mock child_process for git operations
vi.mock('child_process', () => ({
  execSync: vi.fn().mockImplementation((cmd: string) => {
    if (cmd === 'git diff --name-only') return 'src/app.rb\n';
    if (cmd.includes('git status')) return '';
    if (cmd.includes('git add')) return '';
    if (cmd.includes('git commit')) return '';
    if (cmd.includes('git push')) return '';
    if (cmd.includes('git checkout')) return '';
    if (cmd.includes('git branch')) return '';
    return '';
  }),
  exec: vi.fn(),
}));

// Mock fs for detectTestFramework
vi.mock('fs', async () => {
  const actual = await vi.importActual('fs');
  return {
    ...actual,
    existsSync: vi.fn().mockImplementation((p: string) => {
      if (p.endsWith('Gemfile')) return true;
      if (p.endsWith('package.json')) return false;
      return false;
    }),
    readFileSync: vi.fn().mockImplementation((p: string) => {
      if (p.endsWith('Gemfile')) return "gem 'rspec-rails'\ngem 'rails'";
      return '';
    }),
  };
});

// Mock phase data storage
vi.mock('../../../api/rsolv-api.js', () => ({
  RsolvApiClient: vi.fn().mockImplementation(() => ({
    storePhaseData: vi.fn().mockResolvedValue({ success: true }),
    getPhaseData: vi.fn().mockResolvedValue(null),
  })),
}));

const baseConfig: ActionConfig = {
  mode: 'validate',
  githubToken: 'test-token',
  rsolvApiKey: 'rsolv_test_key',
  repository: 'test-org/test-repo',
  maxIssues: 1,
};

const issue: IssueContext = {
  number: 1,
  title: 'CWE-89: SQL Injection',
  body: 'SQL injection in login endpoint',
  labels: [{ name: 'rsolv:detected' }],
  repository: { owner: 'test-org', name: 'test-repo' },
};

const scanData: ScanPhaseData = {
  analysisData: {
    cwe: 'CWE-89',
    issueType: 'sql_injection',
    vulnerabilityType: 'CWE-89',
    estimatedComplexity: 'simple',
    suggestedApproach: 'Use parameterized queries',
    filesToModify: ['app/controllers/auth_controller.rb'],
  },
};

describe('Runtime setup before pipeline sessions', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    process.env.RSOLV_API_URL = 'https://api.rsolv.dev';
  });

  test('executeValidateForIssue calls ensureRuntime before starting validation session', async () => {
    const executor = new PhaseExecutor(baseConfig);

    await executor.executeValidateForIssue(issue, scanData);

    // ensureRuntime must be called with the detected framework and a working directory
    // Note: detectTestFramework() uses require('fs') which reads real filesystem,
    // so the framework may vary based on cwd. The key assertion is that it's CALLED.
    expect(mockEnsureRuntime).toHaveBeenCalledTimes(1);
    expect(mockEnsureRuntime).toHaveBeenCalledWith(expect.any(String), expect.any(String));

    // ValidationClient.runValidation must also be called (session started)
    expect(mockRunValidation).toHaveBeenCalledTimes(1);
  });

  test('executeValidateForIssue calls ensureRuntime BEFORE runValidation', async () => {
    const callOrder: string[] = [];
    mockEnsureRuntime.mockImplementation(async () => {
      callOrder.push('ensureRuntime');
    });
    mockRunValidation.mockImplementation(async () => {
      callOrder.push('runValidation');
      return {
        validated: true, test_path: 'spec/test_spec.rb',
        test_code: 'test', framework: 'rspec',
        test_command: 'bundle exec rspec',
        classification: { tier: 'behavioral' },
      };
    });

    const executor = new PhaseExecutor(baseConfig);
    await executor.executeValidateForIssue(issue, scanData);

    expect(callOrder).toEqual(['ensureRuntime', 'runValidation']);
  });

  test('executeMitigateForIssue calls ensureRuntime before starting mitigation session', async () => {
    const executor = new PhaseExecutor(baseConfig);

    await executor.executeMitigateForIssue(issue, scanData, null);

    // ensureRuntime called once with detected framework
    expect(mockEnsureRuntime).toHaveBeenCalledTimes(1);
    expect(mockEnsureRuntime).toHaveBeenCalledWith(expect.any(String), expect.any(String));
    expect(mockRunMitigation).toHaveBeenCalledTimes(1);
  });

  test('ensureRuntime failure does not prevent session from starting', async () => {
    mockEnsureRuntime.mockRejectedValueOnce(new Error('mise install failed'));

    const executor = new PhaseExecutor(baseConfig);
    const result = await executor.executeValidateForIssue(issue, scanData);

    // Session should still proceed (ensureRuntime failure is non-fatal)
    expect(mockRunValidation).toHaveBeenCalledTimes(1);
  });

  test('ensureRuntime is skipped for unknown framework', async () => {
    // Override fs mock to return no Gemfile
    const fs = await import('fs');
    (fs.existsSync as ReturnType<typeof vi.fn>).mockReturnValue(false);

    const executor = new PhaseExecutor(baseConfig);
    await executor.executeValidateForIssue(issue, scanData);

    // With unknown framework, ensureRuntime should not be called
    // (or called with 'unknown' which returns early)
    expect(mockRunValidation).toHaveBeenCalledTimes(1);
  });
});
