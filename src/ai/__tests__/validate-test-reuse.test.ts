/**
 * Tests for MITIGATE: Validate Branch RED Test Reuse
 *
 * When VALIDATE proves a vulnerability with a behavioral RED test,
 * MITIGATE should reuse that test (ecosystem-native runner) instead of
 * generating a brand-new JS-only test suite via TestGeneratingSecurityAnalyzer.
 */
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import {
  extractValidateRedTest,
  runRedTestForVerification,
  verifyFixWithValidateRedTest,
  type ValidateRedTest,
  type RedTestVerificationResult,
} from '../validate-test-reuse.js';

// Mock child_process for runRedTestForVerification
vi.mock('child_process', () => ({
  execSync: vi.fn(),
}));

// Mock fs for file operations
vi.mock('fs', () => ({
  writeFileSync: vi.fn(),
  unlinkSync: vi.fn(),
  existsSync: vi.fn().mockReturnValue(true),
  mkdirSync: vi.fn(),
  default: {
    writeFileSync: vi.fn(),
    unlinkSync: vi.fn(),
    existsSync: vi.fn().mockReturnValue(true),
    mkdirSync: vi.fn(),
  },
}));

import { execSync } from 'child_process';
import { writeFileSync, unlinkSync } from 'fs';

const mockExecSync = vi.mocked(execSync);
const mockWriteFileSync = vi.mocked(writeFileSync);
const mockUnlinkSync = vi.mocked(unlinkSync);

describe('MITIGATE: Validate Branch RED Test Reuse', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  describe('extractValidateRedTest', () => {
    it('extracts RED test code, framework, and file path from validation phase data', () => {
      const validationData = {
        validation: {
          'issue-42': {
            issueNumber: 42,
            validated: true,
            framework: 'pytest',
            branchName: 'rsolv/validate/issue-42',
            redTests: {
              redTests: [
                {
                  testName: 'test_sql_injection_vulnerability',
                  testCode: 'import pytest\ndef test_sql_injection():\n    assert True',
                  attackVector: 'SQL injection via user input',
                  expectedBehavior: 'should_fail_on_vulnerable_code' as const,
                },
              ],
            },
            testResults: {
              testFile: 'tests/test_vulnerability_validation.py',
            },
          },
        },
      };

      const result = extractValidateRedTest(validationData, 42);
      expect(result).not.toBeNull();
      expect(result!.testCode).toContain('import pytest');
      expect(result!.framework).toBe('pytest');
      expect(result!.testFile).toBe('tests/test_vulnerability_validation.py');
      expect(result!.branchName).toBe('rsolv/validate/issue-42');
    });

    it('returns null when no validation data available', () => {
      const result = extractValidateRedTest(null, 42);
      expect(result).toBeNull();
    });

    it('returns null when validation data has no redTests', () => {
      const validationData = {
        validation: {
          'issue-42': {
            issueNumber: 42,
            validated: true,
            framework: 'pytest',
          },
        },
      };

      const result = extractValidateRedTest(validationData, 42);
      expect(result).toBeNull();
    });

    it('handles validate key (PhaseDataClient remap)', () => {
      const validationData = {
        validate: {
          'issue-10': {
            issueNumber: 10,
            validated: true,
            framework: 'rspec',
            branchName: 'rsolv/validate/issue-10',
            redTests: {
              redTests: [
                {
                  testName: 'test_insecure_random',
                  testCode: "require 'rspec'\nRSpec.describe 'random' do\n  it 'uses SecureRandom' do\n  end\nend",
                  attackVector: 'Insecure random number generation',
                  expectedBehavior: 'should_fail_on_vulnerable_code' as const,
                },
              ],
            },
            testResults: {
              testFile: 'spec/vulnerability_validation_spec.rb',
            },
          },
        },
      };

      const result = extractValidateRedTest(validationData, 10);
      expect(result).not.toBeNull();
      expect(result!.framework).toBe('rspec');
      expect(result!.testFile).toBe('spec/vulnerability_validation_spec.rb');
    });

    it('extracts from flat per-issue format (as passed by unified-processor)', () => {
      // When processIssueWithGit receives validationData via unified-processor,
      // it's already the per-issue object (not nested under validation.issue-N)
      const flatValidationData = {
        branchName: 'rsolv/validate/issue-42',
        framework: 'pytest',
        redTests: {
          framework: 'pytest',
          testFile: 'tests/test_vulnerability_validation.py',
          redTests: [
            {
              testName: 'test_secret_key_not_hardcoded',
              testCode: 'import pytest\ndef test_secret_key():\n    assert False',
              attackVector: 'hardcoded_secrets',
              expectedBehavior: 'should_fail_on_vulnerable_code' as const,
            },
          ],
        },
        testResults: {
          testFile: 'tests/test_vulnerability_validation.py',
          passed: 0,
          failed: 1,
          total: 1,
        },
        validated: true,
      };

      // Issue number doesn't matter for flat format — it's already per-issue
      const result = extractValidateRedTest(flatValidationData, 42);
      expect(result).not.toBeNull();
      expect(result!.testCode).toContain('import pytest');
      expect(result!.framework).toBe('pytest');
      expect(result!.testFile).toBe('tests/test_vulnerability_validation.py');
      expect(result!.branchName).toBe('rsolv/validate/issue-42');
    });

    it('extracts from flat format with redTests.testFile', () => {
      // The testFile can be in redTests instead of testResults
      const flatValidationData = {
        branchName: 'rsolv/validate/issue-3',
        framework: 'rspec',
        redTests: {
          framework: 'rspec',
          testFile: 'spec/vulnerability_validation_spec.rb',
          redTests: [
            {
              testName: 'test_secure_random',
              testCode: "require 'securerandom'\nRSpec.describe 'random' do\n  it 'test' do\n  end\nend",
              attackVector: 'weak_cryptography',
              expectedBehavior: 'should_fail_on_vulnerable_code' as const,
            },
          ],
        },
        validated: true,
      };

      const result = extractValidateRedTest(flatValidationData, 3);
      expect(result).not.toBeNull();
      expect(result!.framework).toBe('rspec');
      expect(result!.testFile).toBe('spec/vulnerability_validation_spec.rb');
    });

    it('extracts from single red test (non-array format)', () => {
      const validationData = {
        validation: {
          'issue-5': {
            issueNumber: 5,
            validated: true,
            framework: 'vitest',
            branchName: 'rsolv/validate/issue-5',
            redTests: {
              red: {
                testName: 'test_sql_injection',
                testCode: "import { describe } from 'vitest';",
                attackVector: 'SQL injection',
                expectedBehavior: 'should_fail_on_vulnerable_code' as const,
              },
            },
            testResults: {
              testFile: '__tests__/vulnerability_validation.test.ts',
            },
          },
        },
      };

      const result = extractValidateRedTest(validationData, 5);
      expect(result).not.toBeNull();
      expect(result!.framework).toBe('vitest');
    });
  });

  describe('runRedTestForVerification', () => {
    it('runs pytest for Python RED tests', async () => {
      mockExecSync.mockReturnValue(Buffer.from('1 passed'));

      const result = await runRedTestForVerification(
        'def test_vuln():\n    assert True',
        'tests/test_vulnerability_validation.py',
        'pytest',
        '/tmp/repo'
      );

      expect(result.passed).toBe(true);
      // Verify pytest command was used
      const call = mockExecSync.mock.calls[0];
      expect(call[0]).toContain('pytest');
      expect(call[0]).toContain('tests/test_vulnerability_validation.py');
    });

    it('runs rspec for Ruby RED tests', async () => {
      mockExecSync.mockReturnValue(Buffer.from('1 example, 0 failures'));

      const result = await runRedTestForVerification(
        "RSpec.describe 'vuln' do\n  it 'exists' do\n  end\nend",
        'spec/vulnerability_validation_spec.rb',
        'rspec',
        '/tmp/repo'
      );

      expect(result.passed).toBe(true);
      const call = mockExecSync.mock.calls[0];
      expect(call[0]).toContain('rspec');
    });

    it('runs vitest for JavaScript RED tests', async () => {
      mockExecSync.mockReturnValue(Buffer.from('Tests: 1 passed'));

      const result = await runRedTestForVerification(
        "import { test } from 'vitest';",
        '__tests__/vulnerability_validation.test.ts',
        'vitest',
        '/tmp/repo'
      );

      expect(result.passed).toBe(true);
      const call = mockExecSync.mock.calls[0];
      expect(call[0]).toContain('vitest');
    });

    it('returns { passed: true } when test passes (fix verified)', async () => {
      mockExecSync.mockReturnValue(Buffer.from('All tests passed'));

      const result = await runRedTestForVerification(
        'def test_vuln(): pass',
        'tests/test_vuln.py',
        'pytest',
        '/tmp/repo'
      );

      expect(result.passed).toBe(true);
      expect(result.exitCode).toBe(0);
    });

    it('returns { passed: false, output } when test fails (fix did not work)', async () => {
      const error = new Error('Process exited with code 1') as any;
      error.status = 1;
      error.stdout = Buffer.from('FAILED test_vuln');
      error.stderr = Buffer.from('AssertionError');
      mockExecSync.mockImplementation(() => {
        throw error;
      });

      const result = await runRedTestForVerification(
        'def test_vuln(): assert False',
        'tests/test_vuln.py',
        'pytest',
        '/tmp/repo'
      );

      expect(result.passed).toBe(false);
      expect(result.output).toBeDefined();
    });

    it('handles missing test runner gracefully (infrastructure failure)', async () => {
      const error = new Error('command not found: pytest') as any;
      error.status = 127;
      error.stdout = Buffer.from('');
      error.stderr = Buffer.from('pytest: command not found');
      mockExecSync.mockImplementation(() => {
        throw error;
      });

      const result = await runRedTestForVerification(
        'def test_vuln(): pass',
        'tests/test_vuln.py',
        'pytest',
        '/tmp/repo'
      );

      expect(result.passed).toBe(false);
      expect(result.infrastructureFailure).toBe(true);
    });
  });

  describe('verifyFixWithValidateRedTest', () => {
    const redTest: ValidateRedTest = {
      testCode: 'def test_vuln():\n    assert True',
      testFile: 'tests/test_vulnerability_validation.py',
      framework: 'pytest',
      branchName: 'rsolv/validate/issue-42',
    };

    it('runs RED test on vulnerable commit (expects FAIL) then on fixed commit (expects PASS)', async () => {
      // First call: git checkout vulnerable -> fail
      // Second call: run test on vulnerable -> test fails (exit 1)
      // Third call: git checkout fixed -> success
      // Fourth call: run test on fixed -> test passes (exit 0)
      let callCount = 0;
      mockExecSync.mockImplementation((cmd: string) => {
        callCount++;
        const cmdStr = typeof cmd === 'string' ? cmd : '';

        if (cmdStr.includes('git checkout')) {
          return Buffer.from('');
        }
        if (cmdStr.includes('pytest')) {
          // First pytest call = vulnerable commit → test FAILS (good)
          // Second pytest call = fixed commit → test PASSES (good)
          if (callCount <= 3) {
            // Vulnerable commit - test should fail
            const err = new Error('test failed') as any;
            err.status = 1;
            err.stdout = Buffer.from('FAILED');
            err.stderr = Buffer.from('');
            throw err;
          } else {
            // Fixed commit - test should pass
            return Buffer.from('1 passed');
          }
        }
        return Buffer.from('');
      });

      const result = await verifyFixWithValidateRedTest(
        'abc123',
        'def456',
        redTest,
        '/tmp/repo'
      );

      expect(result.isValidFix).toBe(true);
      expect(result.vulnerableResult.passed).toBe(false);
      expect(result.fixedResult.passed).toBe(true);
    });

    it('returns isValidFix=false when RED still fails on fixed commit', async () => {
      mockExecSync.mockImplementation((cmd: string) => {
        const cmdStr = typeof cmd === 'string' ? cmd : '';
        if (cmdStr.includes('git checkout')) {
          return Buffer.from('');
        }
        if (cmdStr.includes('pytest')) {
          // Both vulnerable and fixed → test fails
          const err = new Error('test failed') as any;
          err.status = 1;
          err.stdout = Buffer.from('FAILED');
          err.stderr = Buffer.from('');
          throw err;
        }
        return Buffer.from('');
      });

      const result = await verifyFixWithValidateRedTest(
        'abc123',
        'def456',
        redTest,
        '/tmp/repo'
      );

      expect(result.isValidFix).toBe(false);
      expect(result.fixedResult.passed).toBe(false);
    });

    it('returns isValidFix=false when RED passes on vulnerable commit (test is wrong)', async () => {
      mockExecSync.mockImplementation((cmd: string) => {
        const cmdStr = typeof cmd === 'string' ? cmd : '';
        if (cmdStr.includes('git checkout')) {
          return Buffer.from('');
        }
        if (cmdStr.includes('pytest')) {
          // Both pass - means the test doesn't actually detect the vulnerability
          return Buffer.from('1 passed');
        }
        return Buffer.from('');
      });

      const result = await verifyFixWithValidateRedTest(
        'abc123',
        'def456',
        redTest,
        '/tmp/repo'
      );

      expect(result.isValidFix).toBe(false);
      // The vulnerable result passed when it shouldn't have
      expect(result.vulnerableResult.passed).toBe(true);
    });

    it('includes retry context when fix verification fails', async () => {
      mockExecSync.mockImplementation((cmd: string) => {
        const cmdStr = typeof cmd === 'string' ? cmd : '';
        if (cmdStr.includes('git checkout')) {
          return Buffer.from('');
        }
        if (cmdStr.includes('pytest')) {
          const err = new Error('test failed') as any;
          err.status = 1;
          err.stdout = Buffer.from('FAILED test_sql_injection - AssertionError');
          err.stderr = Buffer.from('');
          throw err;
        }
        return Buffer.from('');
      });

      const result = await verifyFixWithValidateRedTest(
        'abc123',
        'def456',
        redTest,
        '/tmp/repo'
      );

      expect(result.isValidFix).toBe(false);
      expect(result.fixedResult.output).toBeDefined();
    });

    it('restores original commit after verification', async () => {
      mockExecSync.mockImplementation((cmd: string) => {
        const cmdStr = typeof cmd === 'string' ? cmd : '';
        if (cmdStr.includes('git checkout') || cmdStr.includes('git rev-parse')) {
          return Buffer.from('original123');
        }
        if (cmdStr.includes('pytest')) {
          return Buffer.from('1 passed');
        }
        return Buffer.from('');
      });

      await verifyFixWithValidateRedTest('abc123', 'def456', redTest, '/tmp/repo');

      // Verify git checkout was called to restore
      const gitCalls = mockExecSync.mock.calls
        .filter((c) => String(c[0]).includes('git checkout'))
        .map((c) => String(c[0]));

      // Should have checkouts for: vulnerable, fixed, and restore
      expect(gitCalls.length).toBeGreaterThanOrEqual(2);
    });
  });
});
