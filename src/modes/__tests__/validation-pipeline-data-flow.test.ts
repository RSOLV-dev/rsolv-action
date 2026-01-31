/**
 * Validation Pipeline Data Flow Integration Tests
 *
 * Verifies that framework, vulnerability type, and test execution context
 * flow correctly through the validation pipeline without being lost or
 * re-detected at internal boundaries.
 *
 * These tests mock ONLY external boundaries (LLM API, GitHub API, backend API)
 * and exercise the REAL internal methods to catch data flow breaks.
 *
 * @see docs/audits/validate-iteration2-remaining-issues.md
 * @implements RFC-060-AMENDMENT-001 Iteration 3
 */

import { describe, test, expect, beforeEach, afterEach, vi } from 'vitest';
import type { Vulnerability, TestFileContext, TestFramework } from '../types.js';

// Hoisted mocks and shared state — must be in vi.hoisted so vi.mock factories can access them
const { mockAiComplete, mockGetAiClient, mockExecSync, execCommandLog } = vi.hoisted(() => {
  const mockAiComplete = vi.fn();
  const mockGetAiClient = vi.fn();
  const execCommandLog: string[] = [];
  const mockExecSync = vi.fn().mockImplementation((cmd: string) => {
    execCommandLog.push(cmd);
    if (cmd.includes('git')) return 'abc123';
    if (cmd.includes('node --check')) return '';
    if (cmd.includes('npx mocha') || cmd.includes('npx jest') || cmd.includes('npx vitest') || cmd.includes('bundle exec rspec') || cmd.includes('pytest')) {
      const err: Error & { stdout?: string } = new Error('1 failing');
      err.stdout = 'Failures:\n  1) security test failed';
      throw err;
    }
    if (cmd.includes('echo "No test runner"')) return 'No test runner';
    return '';
  });
  return { mockAiComplete, mockGetAiClient, mockExecSync, execCommandLog };
});

// Track prompt sent to AI
let capturedPrompt: string | null = null;

// Mock only external boundaries
vi.mock('../../ai/client.js', () => ({
  getAiClient: mockGetAiClient
}));

vi.mock('../../ai/analyzer.js', () => ({
  analyzeIssue: vi.fn()
}));

vi.mock('../../github/api.js', () => ({
  getGitHubClient: vi.fn().mockReturnValue({
    issues: { addLabels: vi.fn(), createLabel: vi.fn(), createComment: vi.fn() }
  })
}));

vi.mock('../test-integration-client.js', () => ({
  TestIntegrationClient: vi.fn().mockImplementation(() => ({
    analyze: vi.fn(),
    generate: vi.fn(),
    detectFramework: vi.fn()
  }))
}));

vi.mock('../../modes/phase-data-client/index.js', () => ({
  PhaseDataClient: vi.fn().mockImplementation(() => ({
    storePhaseResults: vi.fn().mockResolvedValue({ success: true })
  }))
}));

vi.mock('child_process', () => ({
  execSync: mockExecSync
}));

vi.mock('fs', () => ({
  default: {
    existsSync: vi.fn().mockReturnValue(true),
    readFileSync: vi.fn().mockReturnValue('// test file content'),
    writeFileSync: vi.fn(),
    mkdirSync: vi.fn(),
    readdirSync: vi.fn().mockReturnValue([])
  },
  existsSync: vi.fn().mockReturnValue(true),
  readFileSync: vi.fn().mockReturnValue('// test file content'),
  writeFileSync: vi.fn(),
  mkdirSync: vi.fn(),
  readdirSync: vi.fn().mockReturnValue([])
}));

vi.mock('../vendor-utils.js', () => ({
  vendorFilterUtils: {
    checkForVendorFiles: vi.fn().mockResolvedValue({ isVendor: false, files: [] })
  }
}));

import { ValidationMode } from '../validation-mode.js';
import type { ActionConfig } from '../../types/index.js';

describe('Validation Pipeline Data Flow', () => {
  let validationMode: ValidationMode;

  const mockConfig: ActionConfig = {
    apiKey: 'test-api-key',
    rsolvApiKey: 'test-rsolv-key',
    githubToken: 'test-token',
    mode: 'validate',
    executableTests: true,
    aiProvider: {
      provider: 'anthropic',
      apiKey: 'test-ai-key',
      model: 'claude-sonnet-4-5-20250929',
      maxTokens: 4000,
      useVendedCredentials: false
    }
  } as ActionConfig;

  const mochaVulnerability: Vulnerability = {
    type: 'code_injection',
    description: 'eval() of user input in contributions handler (CWE-94)',
    location: 'app/routes/contributions.js:42',
    attackVector: "require('child_process').execSync('cat /etc/passwd')",
    vulnerablePattern: 'eval(req.body.preTax)',
    source: 'NodeGoat'
  };

  const mochaTestFile: TestFileContext = {
    path: 'test/e2e/integration/contributions_spec.js',
    content: `const expect = require('chai').expect;
describe('Contributions', function() {
  it('should calculate pretax', function() {
    // existing test
  });
});`,
    framework: 'mocha'
  };

  beforeEach(() => {
    capturedPrompt = null;
    execCommandLog.length = 0;
    vi.clearAllMocks();

    // Re-apply execSync implementation after clearAllMocks
    mockExecSync.mockImplementation((cmd: string) => {
      execCommandLog.push(cmd);
      if (cmd.includes('git')) return 'abc123';
      if (cmd.includes('node --check')) return '';
      if (cmd.includes('npx mocha') || cmd.includes('npx jest') || cmd.includes('npx vitest') || cmd.includes('bundle exec rspec') || cmd.includes('pytest')) {
        const err: Error & { stdout?: string } = new Error('1 failing');
        err.stdout = 'Failures:\n  1) security test failed';
        throw err;
      }
      if (cmd.includes('echo "No test runner"')) return 'No test runner';
      return '';
    });

    // Setup AI client mock that captures the prompt
    mockAiComplete.mockImplementation(async (prompt: string) => {
      capturedPrompt = prompt;
      return `\`\`\`javascript
const expect = require('chai').expect;
const request = require('supertest');
const app = require('../../server');

describe('Security: Code Injection in Contributions', function() {
  it('should reject eval injection in preTax field', function(done) {
    request(app)
      .post('/contributions')
      .send({ preTax: "require('child_process').execSync('id')" })
      .expect(function(res) {
        expect(res.text).to.not.contain('uid=');
      })
      .end(done);
  });
});
\`\`\``;
    });

    mockGetAiClient.mockResolvedValue({
      complete: mockAiComplete
    });

    validationMode = new ValidationMode(mockConfig, '/tmp/test-repo');
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  describe('Framework flows from backend detection to test execution', () => {
    test('frameworkFromName("mocha") returns mocha TestFramework with npx mocha command', () => {
      const framework = (validationMode as any).frameworkFromName('mocha') as TestFramework;

      expect(framework.name).toBe('mocha');
      expect(framework.testCommand).toBe('npx mocha');
      expect(framework.syntaxCheckCommand).toBe('node --check');
    });

    test('frameworkFromName is case-insensitive', () => {
      const framework = (validationMode as any).frameworkFromName('Mocha') as TestFramework;
      expect(framework.name).toBe('mocha');
      expect(framework.testCommand).toBe('npx mocha');
    });

    test('frameworkFromName falls back to detectFrameworkFromPath for unknown names', () => {
      const framework = (validationMode as any).frameworkFromName('some_unknown_framework') as TestFramework;
      // detectFrameworkFromPath with a non-path string returns generic
      expect(framework.name).toBe('generic');
    });

    test('generateTestWithRetry uses targetTestFile.framework, not path detection', async () => {
      const result = await (validationMode as any).generateTestWithRetry(
        mochaVulnerability,
        mochaTestFile,
        3
      );

      expect(result).not.toBeNull();
      expect(result.framework).toBe('mocha');

      // The test runner should have been called with npx mocha, not echo
      const testRunCommands = execCommandLog.filter(
        cmd => cmd.includes('npx mocha') || cmd.includes('echo "No test runner"')
      );
      expect(testRunCommands.some(cmd => cmd.includes('npx mocha'))).toBe(true);
      expect(testRunCommands.some(cmd => cmd.includes('echo "No test runner"'))).toBe(false);
    });

    test('runTest executes framework command, not echo', async () => {
      const framework = (validationMode as any).frameworkFromName('mocha');
      const result = await (validationMode as any).runTest('/tmp/test.js', framework);

      const mochaCommands = execCommandLog.filter(cmd => cmd.includes('npx mocha'));
      expect(mochaCommands.length).toBeGreaterThan(0);
      // Should NOT have run echo
      const echoCommands = execCommandLog.filter(cmd => cmd.includes('echo "No test runner"'));
      expect(echoCommands.length).toBe(0);
      // RED test: passed should be false (test threw = vulnerability confirmed)
      expect(result.passed).toBe(false);
    });
  });

  describe('Vulnerability type flows through to LLM prompt unchanged', () => {
    test('LLM prompt contains correct vulnerability type', async () => {
      await (validationMode as any).generateTestWithRetry(
        mochaVulnerability,
        mochaTestFile,
        3
      );

      expect(capturedPrompt).not.toBeNull();
      expect(capturedPrompt).toContain('TYPE: code_injection');
    });

    test('LLM prompt contains correct attack vector', async () => {
      await (validationMode as any).generateTestWithRetry(
        mochaVulnerability,
        mochaTestFile,
        3
      );

      expect(capturedPrompt).not.toBeNull();
      expect(capturedPrompt).toContain("require('child_process').execSync('cat /etc/passwd')");
    });

    test('LLM prompt contains code_injection real-world example', async () => {
      await (validationMode as any).generateTestWithRetry(
        mochaVulnerability,
        mochaTestFile,
        3
      );

      expect(capturedPrompt).not.toBeNull();
      expect(capturedPrompt).toContain('eval(req.body.preTax)');
      expect(capturedPrompt).toContain('CWE-94');
    });

    test('LLM prompt contains framework name', async () => {
      await (validationMode as any).generateTestWithRetry(
        mochaVulnerability,
        mochaTestFile,
        3
      );

      expect(capturedPrompt).not.toBeNull();
      expect(capturedPrompt).toContain('FRAMEWORK: mocha');
    });
  });

  describe('LLM response is parsed directly, not re-analyzed', () => {
    test('aiClient.complete is called with the prompt (no TestGeneratingSecurityAnalyzer)', async () => {
      await (validationMode as any).generateTestWithRetry(
        mochaVulnerability,
        mochaTestFile,
        3
      );

      expect(mockGetAiClient).toHaveBeenCalled();
      expect(mockAiComplete).toHaveBeenCalledWith(
        expect.stringContaining('TYPE: code_injection'),
        expect.objectContaining({ temperature: 0.2 })
      );
    });

    test('returned testSuite.redTests contain the LLM response code', async () => {
      const result = await (validationMode as any).generateTestWithRetry(
        mochaVulnerability,
        mochaTestFile,
        3
      );

      expect(result).not.toBeNull();
      expect(result.redTests.length).toBeGreaterThan(0);
      // The test code should contain content from our mock LLM response
      const allCode = result.redTests.map((t: { testCode: string }) => t.testCode).join('\n');
      expect(allCode).toContain('Code Injection');
    });
  });

  describe('Vulnerability examples coverage', () => {
    test('code_injection example exists and contains eval pattern', () => {
      const example = (validationMode as any).getRealisticVulnerabilityExample('code_injection');
      expect(example).toContain('eval');
      expect(example).toContain('CWE-94');
    });

    test('hardcoded_secrets example exists', () => {
      const example = (validationMode as any).getRealisticVulnerabilityExample('hardcoded_secrets');
      expect(example).toContain('CWE-798');
    });

    test('unknown vulnerability type returns generic fallback', () => {
      const example = (validationMode as any).getRealisticVulnerabilityExample('unknown_vuln_xyz');
      expect(example).toContain('Vulnerability type: unknown_vuln_xyz');
    });
  });

  describe('parseTestResponse', () => {
    test('extracts code from markdown code block', () => {
      const response = '```javascript\nconst x = 1;\n```';
      const result = (validationMode as any).parseTestResponse(
        response,
        mochaVulnerability,
        { name: 'mocha', testCommand: 'npx mocha' }
      );
      expect(result.length).toBe(1);
      expect(result[0].testCode).toBe('const x = 1;');
    });

    test('handles raw code without code blocks', () => {
      const response = 'describe("test", function() { it("works", function() {}); });';
      const result = (validationMode as any).parseTestResponse(
        response,
        mochaVulnerability,
        { name: 'mocha', testCommand: 'npx mocha' }
      );
      expect(result.length).toBe(1);
      expect(result[0].testCode).toContain('describe');
    });

    test('splits multiple describe blocks into separate tests', () => {
      const response = `describe("test1", function() {
  it("a", function() {});
});
describe("test2", function() {
  it("b", function() {});
});`;
      const result = (validationMode as any).parseTestResponse(
        response,
        mochaVulnerability,
        { name: 'mocha', testCommand: 'npx mocha' }
      );
      expect(result.length).toBe(2);
    });

    test('sets attackVector from vulnerability', () => {
      const response = '```javascript\nit("test", function() {});\n```';
      const result = (validationMode as any).parseTestResponse(
        response,
        mochaVulnerability,
        { name: 'mocha', testCommand: 'npx mocha' }
      );
      expect(result[0].attackVector).toBe(mochaVulnerability.attackVector);
    });
  });

  describe('End-to-end: mocha + code_injection produces correct test', () => {
    test('full pipeline generates mocha test for code_injection vulnerability', async () => {
      const result = await (validationMode as any).generateTestWithRetry(
        mochaVulnerability,
        mochaTestFile,
        3
      );

      // Framework should be mocha (from targetTestFile.framework)
      expect(result).not.toBeNull();
      expect(result.framework).toBe('mocha');

      // The prompt should have gone to the AI directly
      expect(capturedPrompt).toContain('TYPE: code_injection');
      expect(capturedPrompt).toContain('FRAMEWORK: mocha');

      // Test execution should use npx mocha
      const hasNpxMocha = execCommandLog.some(cmd => cmd.includes('npx mocha'));
      expect(hasNpxMocha).toBe(true);

      // Should NOT have used echo
      const hasEcho = execCommandLog.some(cmd => cmd.includes('echo "No test runner"'));
      expect(hasEcho).toBe(false);
    });
  });
});
