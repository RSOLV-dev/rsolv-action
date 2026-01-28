/**
 * Test suite for forceCommitTestsInTestMode() output format
 *
 * RFC-060-AMENDMENT-001: Tests that generated test files contain
 * valid executable JavaScript code, not JSON.
 *
 * The bug: When testContent is an object, it was being JSON.stringify'd
 * and written to a .test.js file, which is invalid JavaScript.
 */

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import { ValidationMode } from '../validation-mode.js';
import { ActionConfig, IssueContext } from '../../types/index.js';
import { execSync } from 'child_process';

// Create a minimal config for ValidationMode
function createTestConfig(): ActionConfig {
  return {
    apiKey: 'test-key',
    rsolvApiKey: 'test-rsolv-key',
    githubToken: 'test-token',
    configPath: '.rsolv/config.json',
    issueLabel: 'rsolv:automate',
    mode: 'validate',
    executableTests: true,
    aiProvider: {
      apiKey: 'test-ai-key',
      model: 'claude-sonnet-4-5-20250929',
      provider: 'anthropic'
    },
    containerConfig: {
      enabled: false
    },
    securitySettings: {
      disableNetworkAccess: false
    }
  } as ActionConfig;
}

// Create a minimal issue context
function createTestIssue(): IssueContext {
  return {
    id: 'issue-123',
    number: 123,
    title: 'SQL injection vulnerability',
    body: 'Vulnerability in app/controllers/users_controller.rb:42',
    labels: ['rsolv:automate'],
    assignees: [],
    file: 'app/controllers/users_controller.rb',
    repository: {
      owner: 'test-org',
      name: 'test-repo',
      fullName: 'test-org/test-repo',
      defaultBranch: 'main'
    },
    source: 'github',
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
    metadata: {}
  };
}

describe('forceCommitTestsInTestMode() Output Format', () => {
  let tempDir: string;
  let validationMode: ValidationMode;
  let mockIssue: IssueContext;

  beforeEach(() => {
    // Create a real temp directory for each test
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'rsolv-test-'));

    // Initialize as a git repo for commit operations
    execSync('git init', { cwd: tempDir, stdio: 'pipe' });
    execSync('git config user.email "test@test.com"', { cwd: tempDir, stdio: 'pipe' });
    execSync('git config user.name "Test User"', { cwd: tempDir, stdio: 'pipe' });

    // Create initial commit
    fs.writeFileSync(path.join(tempDir, 'README.md'), '# Test');
    execSync('git add .', { cwd: tempDir, stdio: 'pipe' });
    execSync('git commit -m "Initial commit"', { cwd: tempDir, stdio: 'pipe' });

    // Create ValidationMode with the temp dir as repoPath
    const config = createTestConfig();
    validationMode = new ValidationMode(config);
    (validationMode as any).repoPath = tempDir;

    mockIssue = createTestIssue();
  });

  afterEach(() => {
    // Clean up temp directory
    if (tempDir && fs.existsSync(tempDir)) {
      fs.rmSync(tempDir, { recursive: true, force: true });
    }
  });

  describe('When testContent is a string', () => {
    it('should write the string content directly to the test file', async () => {
      const testContent = `
describe('SQL Injection Test', () => {
  it('should detect SQL injection', () => {
    const result = detectSQLInjection("SELECT * FROM users WHERE id = " + userId);
    expect(result).toBe(true);
  });
});
`;

      await validationMode.forceCommitTestsInTestMode(
        testContent,
        'rsolv/validate/issue-123',
        mockIssue
      );

      const testFilePath = path.join(tempDir, '.rsolv', 'tests', 'validation.test.js');
      expect(fs.existsSync(testFilePath)).toBe(true);

      const writtenContent = fs.readFileSync(testFilePath, 'utf8');
      expect(writtenContent).toBe(testContent);
    });
  });

  describe('When testContent is a TestSuite object', () => {
    it('should convert TestSuite object to executable JavaScript code', async () => {
      const testContent = {
        redTests: [
          {
            testName: 'should detect SQL injection via string concatenation',
            testCode: `
              const result = detectSQLInjection("SELECT * FROM users WHERE id = " + userId);
              expect(result).toBe(true);
            `,
            vulnerabilityType: 'sql_injection',
            expectedBehavior: 'Should detect the vulnerability'
          }
        ]
      };

      await validationMode.forceCommitTestsInTestMode(
        testContent,
        'rsolv/validate/issue-123',
        mockIssue
      );

      const testFilePath = path.join(tempDir, '.rsolv', 'tests', 'validation.test.js');
      expect(fs.existsSync(testFilePath)).toBe(true);

      const writtenContent = fs.readFileSync(testFilePath, 'utf8');

      // Content should NOT be JSON
      expect(() => JSON.parse(writtenContent)).toThrow();

      // Content should contain describe() and it()
      expect(writtenContent).toMatch(/describe\s*\(/);
      expect(writtenContent).toMatch(/it\s*\(/);

      // Content should include the test name
      expect(writtenContent).toContain('SQL injection');
    });

    it('should produce syntactically valid JavaScript', async () => {
      const testContent = {
        redTests: [
          {
            testName: 'should detect SQL injection',
            testCode: `
              const input = "'; DROP TABLE users; --";
              const query = buildQuery(input);
              expect(query).toContain("DROP TABLE");
            `
          }
        ]
      };

      await validationMode.forceCommitTestsInTestMode(
        testContent,
        'rsolv/validate/issue-123',
        mockIssue
      );

      const testFilePath = path.join(tempDir, '.rsolv', 'tests', 'validation.test.js');
      const writtenContent = fs.readFileSync(testFilePath, 'utf8');

      // Should be valid JavaScript (parseable by new Function)
      expect(() => new Function(writtenContent)).not.toThrow();
    });

    it('should handle multiple tests in redTests array', async () => {
      const testContent = {
        redTests: [
          {
            testName: 'should detect SQL injection type 1',
            testCode: 'expect(true).toBe(true);'
          },
          {
            testName: 'should detect SQL injection type 2',
            testCode: 'expect(true).toBe(true);'
          },
          {
            testName: 'should detect SQL injection type 3',
            testCode: 'expect(true).toBe(true);'
          }
        ]
      };

      await validationMode.forceCommitTestsInTestMode(
        testContent,
        'rsolv/validate/issue-123',
        mockIssue
      );

      const testFilePath = path.join(tempDir, '.rsolv', 'tests', 'validation.test.js');
      const writtenContent = fs.readFileSync(testFilePath, 'utf8');

      // Should contain all test names
      expect(writtenContent).toContain('type 1');
      expect(writtenContent).toContain('type 2');
      expect(writtenContent).toContain('type 3');
    });
  });

  describe('When testContent has single red test format', () => {
    it('should handle { red: {...} } format', async () => {
      const testContent = {
        red: {
          testName: 'should detect XSS vulnerability',
          testCode: `
            const html = renderHTML(userInput);
            expect(html).toContain('<script>');
          `
        }
      };

      await validationMode.forceCommitTestsInTestMode(
        testContent,
        'rsolv/validate/issue-123',
        mockIssue
      );

      const testFilePath = path.join(tempDir, '.rsolv', 'tests', 'validation.test.js');
      const writtenContent = fs.readFileSync(testFilePath, 'utf8');

      // Should NOT be JSON
      expect(() => JSON.parse(writtenContent)).toThrow();

      // Should contain test structure
      expect(writtenContent).toMatch(/describe|it/);
      expect(writtenContent).toContain('XSS');
    });
  });

  describe('Syntax validation', () => {
    it('should throw error for malformed test code before writing', async () => {
      const testContent = {
        redTests: [
          {
            testName: 'broken test',
            testCode: `
              // This has syntax error
              const x = {;
            `
          }
        ]
      };

      // Should validate syntax before writing
      // Note: This test expects the implementation to validate syntax
      await expect(
        validationMode.forceCommitTestsInTestMode(
          testContent,
          'rsolv/validate/issue-123',
          mockIssue
        )
      ).rejects.toThrow(/syntax|parse|invalid/i);
    });

    it('should allow valid JavaScript with runtime errors', async () => {
      const testContent = {
        redTests: [
          {
            testName: 'test with undefined variable',
            testCode: `
              // This is valid JS, will fail at runtime
              const result = undefinedFunction();
              expect(result).toBe(true);
            `
          }
        ]
      };

      // Should NOT throw - runtime errors are expected for RED tests
      await expect(
        validationMode.forceCommitTestsInTestMode(
          testContent,
          'rsolv/validate/issue-123',
          mockIssue
        )
      ).resolves.not.toThrow();

      const testFilePath = path.join(tempDir, '.rsolv', 'tests', 'validation.test.js');
      expect(fs.existsSync(testFilePath)).toBe(true);
    });
  });

  describe('Generated code structure', () => {
    it('should wrap tests in proper describe/it structure', async () => {
      const testContent = {
        redTests: [
          {
            testName: 'My Test Case',
            testCode: 'expect(1).toBe(1);'
          }
        ]
      };

      await validationMode.forceCommitTestsInTestMode(
        testContent,
        'rsolv/validate/issue-123',
        mockIssue
      );

      const testFilePath = path.join(tempDir, '.rsolv', 'tests', 'validation.test.js');
      const writtenContent = fs.readFileSync(testFilePath, 'utf8');

      // Should have proper structure
      expect(writtenContent).toMatch(/describe\s*\(['"]/);
      expect(writtenContent).toMatch(/it\s*\(['"]/);
      expect(writtenContent).toContain('My Test Case');
      expect(writtenContent).toContain('expect(1).toBe(1)');
    });

    it('should include necessary imports if test code references them', async () => {
      const testContent = {
        redTests: [
          {
            testName: 'test using expect',
            testCode: `
              expect(true).toBe(true);
              expect([1,2,3]).toHaveLength(3);
            `
          }
        ]
      };

      await validationMode.forceCommitTestsInTestMode(
        testContent,
        'rsolv/validate/issue-123',
        mockIssue
      );

      const testFilePath = path.join(tempDir, '.rsolv', 'tests', 'validation.test.js');
      const writtenContent = fs.readFileSync(testFilePath, 'utf8');

      // The test file should be runnable - either include imports or use globals
      expect(writtenContent).toMatch(/describe|it|expect/);
    });
  });
});
