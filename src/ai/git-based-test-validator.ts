/**
 * GitBasedTestValidator - RFC-060 Compatible Implementation
 *
 * Validates that vulnerability fixes actually work by running generated RED tests
 * against both vulnerable and fixed versions of the code using git.
 *
 * RFC-060: Only RED tests are generated - tests that prove vulnerability exists
 *
 * VALIDATE Phase Iteration 1: Flattened execution, output capture, crash detection.
 * - Single self-contained test file (no triple-nested scripts)
 * - stdout/stderr captured (not suppressed)
 * - classifyTestResult() used to distinguish crashes from genuine failures
 * - All-crash scenarios rejected as invalid validation
 */

import { execSync } from 'child_process';
import { writeFileSync, unlinkSync, mkdirSync, rmSync } from 'fs';
import { join, dirname } from 'path';
import { tmpdir } from 'os';
import { VulnerabilityTestSuite, RedTest } from './test-generator.js';
import { logger } from '../utils/logger.js';
import { classifyTestResult, type TestResultClassification } from '../utils/test-result-classifier.js';

// RFC-060: Extract RED tests helper
function extractRedTests(testSuite: VulnerabilityTestSuite): RedTest[] {
  if (testSuite.redTests && Array.isArray(testSuite.redTests)) {
    return testSuite.redTests;
  }
  if (testSuite.red) {
    return [testSuite.red];
  }
  return [];
}

/**
 * Result of running a single RED test.
 * Replaces the previous bare boolean return.
 */
export interface SingleTestResult {
  passed: boolean;
  crashed: boolean;
  exitCode: number;
  stdout: string;
  stderr: string;
  classification: TestResultClassification;
}

export interface CommitTestResults {
  redTestsPassed: boolean[];
  allPassed: boolean;
  testResults: SingleTestResult[];
  hasInfrastructureFailures: boolean;
}

export interface ValidationResult {
  success: boolean;
  vulnerableCommit: CommitTestResults;
  fixedCommit: CommitTestResults;
  isValidFix: boolean;
  error?: string;
}

export class GitBasedTestValidator {
  private workDir: string;

  constructor(private repoPath: string = process.cwd()) {
    this.workDir = join(tmpdir(), `test-validator-${Date.now()}`);
  }

  /**
   * Validate a vulnerability fix by running tests on both commits
   */
  async validateFixWithTests(
    vulnerableCommit: string,
    fixedCommit: string,
    testSuite: VulnerabilityTestSuite
  ): Promise<ValidationResult> {
    try {
      logger.info(`Validating fix: ${vulnerableCommit} -> ${fixedCommit}`);

      // RFC-060: Extract RED tests
      const redTests = extractRedTests(testSuite);
      if (redTests.length === 0) {
        throw new Error('No RED tests found in test suite');
      }

      logger.info(`Running ${redTests.length} RED test(s) for validation`);

      // Ensure work directory exists
      mkdirSync(this.workDir, { recursive: true });

      // Test on vulnerable commit
      const vulnerableResults = await this.runTestsOnCommit(
        vulnerableCommit,
        testSuite
      );

      // Test on fixed commit
      const fixedResults = await this.runTestsOnCommit(
        fixedCommit,
        testSuite
      );

      // Clean up
      try {
        rmSync(this.workDir, { recursive: true, force: true });
      } catch (e) {
        // Ignore cleanup errors
      }

      // Validate results
      const isValidFix = this.validateResults(vulnerableResults, fixedResults);

      return {
        success: true,
        vulnerableCommit: vulnerableResults,
        fixedCommit: fixedResults,
        isValidFix,
        error: isValidFix ? undefined : 'Fix validation failed - tests do not confirm vulnerability was fixed'
      };
    } catch (error) {
      logger.error('Test validation failed', error as Error);
      return {
        success: false,
        vulnerableCommit: {
          redTestsPassed: [],
          allPassed: false,
          testResults: [],
          hasInfrastructureFailures: false
        },
        fixedCommit: {
          redTestsPassed: [],
          allPassed: false,
          testResults: [],
          hasInfrastructureFailures: false
        },
        isValidFix: false,
        error: error instanceof Error ? error.message : 'Unknown error'
      };
    }
  }

  /**
   * Run tests on a specific commit
   */
  private async runTestsOnCommit(
    commit: string,
    testSuite: VulnerabilityTestSuite
  ): Promise<CommitTestResults> {
    // RFC-060: Extract RED tests
    const redTests = extractRedTests(testSuite);

    // Store current branch
    const currentBranch = execSync('git rev-parse --abbrev-ref HEAD', {
      cwd: this.repoPath,
      encoding: 'utf-8'
    }).trim();

    try {
      // Checkout commit
      execSync(`git checkout ${commit} --quiet`, { cwd: this.repoPath });

      // Run each RED test individually
      const testResults = redTests.map((redTest, index) =>
        this.runSingleTest(redTest, index)
      );

      const redTestsPassed = testResults.map(r => r.passed);
      const allPassed = redTestsPassed.every(passed => passed);
      const hasInfrastructureFailures = testResults.some(r => r.crashed);

      return {
        redTestsPassed,
        allPassed,
        testResults,
        hasInfrastructureFailures
      };
    } finally {
      // Restore original branch
      execSync(`git checkout ${currentBranch} --quiet`, { cwd: this.repoPath });
    }
  }

  /**
   * Run a single RED test directly as a self-contained script.
   *
   * Flattened from the previous triple-nested approach:
   * - Writes a single .js file with inlined assert helpers + test code
   * - Captures stdout and stderr (not suppressed)
   * - Uses classifyTestResult() to distinguish crashes from assertion failures
   */
  runSingleTest(redTest: RedTest, testIndex: number): SingleTestResult {
    const testFilePath = join(this.workDir, `red_test_${testIndex}_${Date.now()}.js`);

    try {
      // Escape backticks and dollar signs in test code for template literal safety
      const escapedTestCode = redTest.testCode
        .replace(/\\/g, '\\\\')
        .replace(/`/g, '\\`')
        .replace(/\$/g, '\\$');

      // Build a single self-contained test file
      const testFileContent = `
'use strict';
const assert = require('assert');

// Minimal expect() polyfill for test assertions
function expect(actual) {
  return {
    toBe: (expected) => assert.strictEqual(actual, expected),
    toEqual: (expected) => assert.deepStrictEqual(actual, expected),
    toBeTruthy: () => assert.ok(actual),
    toBeFalsy: () => assert.ok(!actual),
    toBeNull: () => assert.strictEqual(actual, null),
    toBeUndefined: () => assert.strictEqual(actual, undefined),
    toBeDefined: () => assert.notStrictEqual(actual, undefined),
    toBeNaN: () => assert.ok(Number.isNaN(actual)),
    toContain: (item) => {
      if (typeof actual === 'string') assert.ok(actual.includes(item), \`Expected "\${actual}" to contain "\${item}"\`);
      else assert.ok(actual.indexOf(item) !== -1, \`Expected array to contain \${item}\`);
    },
    toMatch: (pattern) => assert.match(String(actual), pattern instanceof RegExp ? pattern : new RegExp(pattern)),
    toThrow: (errorType) => {
      let threw = false;
      try { actual(); } catch(e) { threw = true; if (errorType && !(e instanceof errorType)) throw e; }
      assert.ok(threw, 'Expected function to throw');
    },
    not: {
      toBe: (expected) => assert.notStrictEqual(actual, expected),
      toEqual: (expected) => assert.notDeepStrictEqual(actual, expected),
      toContain: (item) => {
        if (typeof actual === 'string') assert.ok(!actual.includes(item), \`Expected "\${actual}" not to contain "\${item}"\`);
        else assert.ok(actual.indexOf(item) === -1, \`Expected array not to contain \${item}\`);
      },
      toMatch: (pattern) => {
        const re = pattern instanceof RegExp ? pattern : new RegExp(pattern);
        assert.ok(!re.test(String(actual)), \`Expected "\${actual}" not to match \${pattern}\`);
      },
      toBeTruthy: () => assert.ok(!actual),
      toBeFalsy: () => assert.ok(actual),
    }
  };
}

// Make expect globally available
global.expect = expect;

// Execute the test
(async () => {
  try {
    ${redTest.testCode}
    // If we reach here without error, test passed
    console.log('TEST_RESULT: PASSED');
    process.exit(0);
  } catch (error) {
    // Output structured info for classification
    console.error('TEST_RESULT: FAILED');
    console.error(error.name + ': ' + error.message);
    if (error.stack) console.error(error.stack);
    process.exit(1);
  }
})();
`;

      mkdirSync(dirname(testFilePath), { recursive: true });
      writeFileSync(testFilePath, testFileContent);

      // Execute with output capture (not suppressed)
      const stdout = execSync(`node ${testFilePath}`, {
        cwd: this.repoPath,
        encoding: 'utf8',
        timeout: 30000,
        stdio: ['pipe', 'pipe', 'pipe']
      });

      // Test passed (exit 0)
      const classification = classifyTestResult(0, stdout, '');

      // Clean up
      try { unlinkSync(testFilePath); } catch { /* ignore */ }

      return {
        passed: true,
        crashed: false,
        exitCode: 0,
        stdout,
        stderr: '',
        classification
      };
    } catch (error: unknown) {
      const execError = error as { stdout?: Buffer | string; stderr?: Buffer | string; status?: number };
      const stdout = execError.stdout?.toString() || '';
      const stderr = execError.stderr?.toString() || '';
      const exitCode = execError.status ?? 1;

      // Use classifyTestResult to determine if this was a genuine failure or crash
      const classification = classifyTestResult(exitCode, stdout, stderr);
      const crashed = !classification.isValidFailure && classification.type !== 'test_passed';

      logger.debug(`RED test ${testIndex} result: ${classification.type} (exitCode=${exitCode}, crashed=${crashed})`);
      if (stdout) logger.debug(`  stdout: ${stdout.slice(0, 200)}`);
      if (stderr) logger.debug(`  stderr: ${stderr.slice(0, 200)}`);

      // Clean up
      try { unlinkSync(testFilePath); } catch { /* ignore */ }

      return {
        passed: false,
        crashed,
        exitCode,
        stdout,
        stderr,
        classification
      };
    }
  }

  /**
   * RFC-060: Create a test file from the test suite (RED tests only)
   */
  private createTestFile(testSuite: VulnerabilityTestSuite): string {
    // Escape backticks in test code to prevent template literal issues
    const escapeTestCode = (code: string) => code.replace(/`/g, '\\`').replace(/\$/g, '\\$');

    // RFC-060: Extract RED tests
    const redTests = extractRedTests(testSuite);

    // Generate test objects
    const testObjects = redTests.map((redTest, _index) => `  {
    testName: "${redTest.testName}",
    testCode: \`${escapeTestCode(redTest.testCode)}\`,
    attackVector: "${redTest.attackVector || ''}",
    expectedBehavior: "${redTest.expectedBehavior}"
  }`).join(',\n');

    return `
// RFC-060: Generated RED test file for vulnerability validation
const assert = require('assert');

module.exports = {
  redTests: [
${testObjects}
  ]
};

// Export for direct execution
if (require.main === module) {
  (async () => {
    console.log('Running vulnerability validation tests (RED only)...');

    // Run all RED tests
    for (let i = 0; i < module.exports.redTests.length; i++) {
      const test = module.exports.redTests[i];
      console.log(\`Running RED test \${i + 1}: \${test.testName}\`);
      try {
        await eval(test.testCode);
        console.log(\`✓ RED test \${i + 1} passed\`);
      } catch (error) {
        console.log(\`✗ RED test \${i + 1} failed: \${error.message}\`);
      }
    }
  })();
}
`;
  }

  /**
   * RFC-060: Validate that the test results confirm the fix
   *
   * Expected behavior:
   * - On vulnerable code: RED tests should FAIL (prove vulnerability exists)
   * - On fixed code: RED tests should PASS (prove vulnerability fixed)
   *
   * VALIDATE Phase Iteration 1: Rejects all-crash scenarios.
   * If every "failure" was actually an infrastructure crash (MODULE_NOT_FOUND,
   * SyntaxError, etc.), the validation is not meaningful.
   */
  private validateResults(
    vulnerableResults: CommitTestResults,
    fixedResults: CommitTestResults
  ): boolean {
    // Reject if every "failure" was actually an infrastructure crash
    if (vulnerableResults.hasInfrastructureFailures) {
      const genuineFailures = vulnerableResults.testResults
        .filter(r => r.classification.isValidFailure);
      if (genuineFailures.length === 0 && !vulnerableResults.allPassed) {
        logger.warn('All test failures were infrastructure crashes, not genuine assertions');
        logger.warn('Test results:');
        for (const r of vulnerableResults.testResults) {
          logger.warn(`  - ${r.classification.type}: ${r.classification.reason} (exit ${r.exitCode})`);
        }
        return false;
      }
    }

    // On vulnerable commit: RED tests should FAIL (proves vulnerability exists)
    const vulnerableValid = !vulnerableResults.allPassed;

    // On fixed commit: RED tests should PASS (proves vulnerability fixed)
    const fixedValid = fixedResults.allPassed;

    const isValid = vulnerableValid && fixedValid;

    if (!isValid) {
      logger.warn('Validation failed:');
      logger.warn(`  Vulnerable code - RED tests failed (expected): ${vulnerableValid}`);
      logger.warn(`  Fixed code - RED tests passed (expected): ${fixedValid}`);
    }

    return isValid;
  }
}
