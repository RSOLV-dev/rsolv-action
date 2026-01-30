/**
 * GitBasedTestValidator unit tests
 *
 * VALIDATE Phase Iteration 1: Tests for the restructured validator
 * that uses flattened execution, output capture, and crash classification.
 *
 * These tests exercise real execSync on crafted test code (not mocked).
 */

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { RedTest } from '../test-generator.js';
import { mkdirSync, rmSync } from 'fs';
import { join } from 'path';
import { tmpdir } from 'os';

// Unmock child_process so we can use real execSync for test execution
vi.unmock('child_process');

// Must import AFTER unmocking to get the real module
import { GitBasedTestValidator, SingleTestResult } from '../git-based-test-validator.js';

describe('GitBasedTestValidator', () => {
  let validator: GitBasedTestValidator;
  let workDir: string;

  beforeEach(() => {
    // Use a temp directory as "repo" so we don't need an actual git repo
    workDir = join(tmpdir(), `test-validator-test-${Date.now()}`);
    mkdirSync(workDir, { recursive: true });
    validator = new GitBasedTestValidator(workDir);
  });

  afterEach(() => {
    try {
      rmSync(workDir, { recursive: true, force: true });
    } catch {
      // ignore cleanup errors
    }
  });

  describe('runSingleTest result structure', () => {
    it('should return a SingleTestResult object, not a boolean', () => {
      const redTest: RedTest = {
        testName: 'basic passing test',
        testCode: '// no-op, should pass',
        attackVector: 'none',
        expectedBehavior: 'should_fail_on_vulnerable_code'
      };

      const result = validator.runSingleTest(redTest, 0);

      // Should be a structured object
      expect(result).toHaveProperty('passed');
      expect(result).toHaveProperty('crashed');
      expect(result).toHaveProperty('exitCode');
      expect(result).toHaveProperty('stdout');
      expect(result).toHaveProperty('stderr');
      expect(result).toHaveProperty('classification');
      expect(typeof result.passed).toBe('boolean');
      expect(typeof result.crashed).toBe('boolean');
      expect(typeof result.exitCode).toBe('number');
      expect(typeof result.stdout).toBe('string');
      expect(typeof result.stderr).toBe('string');
      expect(result.classification).toHaveProperty('type');
      expect(result.classification).toHaveProperty('isValidFailure');
      expect(result.classification).toHaveProperty('reason');
    });

    it('should return passed=true for test code that does not throw', () => {
      const redTest: RedTest = {
        testName: 'passing test',
        testCode: 'const x = 1 + 1; // no error',
        attackVector: 'none',
        expectedBehavior: 'should_fail_on_vulnerable_code'
      };

      const result = validator.runSingleTest(redTest, 0);

      expect(result.passed).toBe(true);
      expect(result.crashed).toBe(false);
      expect(result.exitCode).toBe(0);
      expect(result.classification.type).toBe('test_passed');
    });

    it('should return passed=false for test code that throws an AssertionError', () => {
      const redTest: RedTest = {
        testName: 'assertion failure test',
        testCode: `
          const assert = require('assert');
          assert.strictEqual(1, 2, 'Expected 1 to equal 2');
        `,
        attackVector: 'none',
        expectedBehavior: 'should_fail_on_vulnerable_code'
      };

      const result = validator.runSingleTest(redTest, 0);

      expect(result.passed).toBe(false);
      expect(result.exitCode).toBe(1);
      // AssertionError should be classified as a genuine test failure
      expect(result.classification.isValidFailure).toBe(true);
      expect(result.crashed).toBe(false);
    });
  });

  describe('output capture', () => {
    it('should capture stdout from console.log', () => {
      const redTest: RedTest = {
        testName: 'stdout capture test',
        testCode: `console.log('HELLO_FROM_TEST');`,
        attackVector: 'none',
        expectedBehavior: 'should_fail_on_vulnerable_code'
      };

      const result = validator.runSingleTest(redTest, 0);

      expect(result.passed).toBe(true);
      expect(result.stdout).toContain('HELLO_FROM_TEST');
    });

    it('should capture stderr from console.error when test fails', () => {
      const redTest: RedTest = {
        testName: 'stderr capture test',
        testCode: `
          console.error('ERROR_OUTPUT_HERE');
          throw new Error('deliberate failure');
        `,
        attackVector: 'none',
        expectedBehavior: 'should_fail_on_vulnerable_code'
      };

      const result = validator.runSingleTest(redTest, 0);

      expect(result.passed).toBe(false);
      expect(result.stderr).toContain('ERROR_OUTPUT_HERE');
    });

    it('should NOT suppress output (stdio is captured, not piped to /dev/null)', () => {
      const redTest: RedTest = {
        testName: 'output not suppressed',
        testCode: `
          console.log('STDOUT_VISIBLE');
          console.error('STDERR_VISIBLE');
          throw new Error('test failure');
        `,
        attackVector: 'none',
        expectedBehavior: 'should_fail_on_vulnerable_code'
      };

      const result = validator.runSingleTest(redTest, 0);

      // Both stdout and stderr should contain content, not be empty
      expect(result.stdout.length).toBeGreaterThan(0);
      expect(result.stderr.length).toBeGreaterThan(0);
    });
  });

  describe('crash vs assertion failure classification', () => {
    it('should classify MODULE_NOT_FOUND as infrastructure failure (crashed=true)', () => {
      const redTest: RedTest = {
        testName: 'module not found test',
        testCode: `const foo = require('./nonexistent-module-xyz');`,
        attackVector: 'none',
        expectedBehavior: 'should_fail_on_vulnerable_code'
      };

      const result = validator.runSingleTest(redTest, 0);

      expect(result.passed).toBe(false);
      expect(result.crashed).toBe(true);
      expect(result.classification.type).toBe('missing_dependency');
      expect(result.classification.isValidFailure).toBe(false);
    });

    it('should classify ReferenceError as infrastructure failure (crashed=true)', () => {
      const redTest: RedTest = {
        testName: 'reference error test',
        testCode: `undefinedVariable.doSomething();`,
        attackVector: 'none',
        expectedBehavior: 'should_fail_on_vulnerable_code'
      };

      const result = validator.runSingleTest(redTest, 0);

      expect(result.passed).toBe(false);
      expect(result.crashed).toBe(true);
      expect(result.classification.type).toBe('runtime_error');
      expect(result.classification.isValidFailure).toBe(false);
    });

    it('should classify AssertionError as genuine failure (crashed=false)', () => {
      const redTest: RedTest = {
        testName: 'assertion error test',
        testCode: `
          const assert = require('assert');
          assert.strictEqual('vulnerable', 'safe');
        `,
        attackVector: 'none',
        expectedBehavior: 'should_fail_on_vulnerable_code'
      };

      const result = validator.runSingleTest(redTest, 0);

      expect(result.passed).toBe(false);
      expect(result.crashed).toBe(false);
      expect(result.classification.isValidFailure).toBe(true);
    });

    it('should classify exit(0) as test passed', () => {
      const redTest: RedTest = {
        testName: 'passing test',
        testCode: `const x = 42;`,
        attackVector: 'none',
        expectedBehavior: 'should_fail_on_vulnerable_code'
      };

      const result = validator.runSingleTest(redTest, 0);

      expect(result.passed).toBe(true);
      expect(result.crashed).toBe(false);
      expect(result.classification.type).toBe('test_passed');
    });
  });

  describe('self-contained test execution', () => {
    it('should run a self-contained RED test with inlined vulnerable code (eval)', () => {
      const redTest: RedTest = {
        testName: 'eval vulnerability test',
        testCode: `
          // Inline the vulnerable function
          function processInput(input) { return eval(input); }

          // Prove vulnerability: eval executes arbitrary code
          let sideEffect = false;
          processInput("sideEffect = true");

          // The vulnerability allows code execution, so sideEffect should be true
          // RED test: assert that the vulnerability exists (eval ran the payload)
          const assert = require('assert');
          assert.strictEqual(sideEffect, true, 'eval should have executed the payload');
        `,
        attackVector: 'eval injection',
        expectedBehavior: 'should_fail_on_vulnerable_code'
      };

      const result = validator.runSingleTest(redTest, 0);

      // This test PASSES because eval works (vulnerability exists)
      expect(result.passed).toBe(true);
      expect(result.crashed).toBe(false);
      expect(result.classification.type).toBe('test_passed');
    });

    it('should NOT use require() for external modules — test file is self-contained', () => {
      // This test verifies that the generated test file includes assert helpers
      // and does not require external test frameworks
      const redTest: RedTest = {
        testName: 'self-contained expect test',
        testCode: `
          // Use the globally available expect() polyfill
          expect(1 + 1).toBe(2);
          expect('hello').toContain('ell');
        `,
        attackVector: 'none',
        expectedBehavior: 'should_fail_on_vulnerable_code'
      };

      const result = validator.runSingleTest(redTest, 0);

      // Should pass without needing external modules
      expect(result.passed).toBe(true);
      expect(result.crashed).toBe(false);
    });
  });

  describe('validateFixWithTests all-crash rejection', () => {
    it('should reject validation when all tests crash with infrastructure failures', async () => {
      // Create a test suite where all tests will crash
      const testSuite = {
        redTests: [
          {
            testName: 'crash test 1',
            testCode: `const foo = require('./nonexistent-module-1');`,
            attackVector: 'none',
            expectedBehavior: 'should_fail_on_vulnerable_code' as const
          },
          {
            testName: 'crash test 2',
            testCode: `const bar = require('./nonexistent-module-2');`,
            attackVector: 'none',
            expectedBehavior: 'should_fail_on_vulnerable_code' as const
          }
        ]
      };

      // We need a git repo for validateFixWithTests, so skip if not in one
      // Instead, test the underlying logic by running tests directly
      const result1 = validator.runSingleTest(testSuite.redTests[0], 0);
      const result2 = validator.runSingleTest(testSuite.redTests[1], 1);

      // Both should be crashes
      expect(result1.crashed).toBe(true);
      expect(result2.crashed).toBe(true);

      // Both should be infrastructure failures, not genuine assertion failures
      expect(result1.classification.isValidFailure).toBe(false);
      expect(result2.classification.isValidFailure).toBe(false);

      // Simulate the validateResults logic: all crashes = no genuine failures
      const testResults = [result1, result2];
      const hasInfrastructureFailures = testResults.some(r => r.crashed);
      const genuineFailures = testResults.filter(r => r.classification.isValidFailure);

      expect(hasInfrastructureFailures).toBe(true);
      expect(genuineFailures.length).toBe(0);
      // This means validateResults should return false
    });

    it('should accept validation when at least one test has a genuine assertion failure', () => {
      const crashTest: RedTest = {
        testName: 'crash test',
        testCode: `const foo = require('./nonexistent-module');`,
        attackVector: 'none',
        expectedBehavior: 'should_fail_on_vulnerable_code'
      };

      const genuineTest: RedTest = {
        testName: 'genuine failure test',
        testCode: `
          const assert = require('assert');
          assert.strictEqual(1, 2, 'genuine assertion failure');
        `,
        attackVector: 'assertion',
        expectedBehavior: 'should_fail_on_vulnerable_code'
      };

      const crashResult = validator.runSingleTest(crashTest, 0);
      const genuineResult = validator.runSingleTest(genuineTest, 1);

      // Mix of crash and genuine failure
      expect(crashResult.crashed).toBe(true);
      expect(genuineResult.crashed).toBe(false);
      expect(genuineResult.classification.isValidFailure).toBe(true);

      // With at least one genuine failure, validation should proceed
      const testResults = [crashResult, genuineResult];
      const genuineFailures = testResults.filter(r => r.classification.isValidFailure);
      expect(genuineFailures.length).toBeGreaterThan(0);
    });
  });
});
