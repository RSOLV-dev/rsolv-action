/**
 * GitBasedTestValidator - RFC-060 Compatible Implementation
 *
 * Validates that vulnerability fixes actually work by running generated RED tests
 * against both vulnerable and fixed versions of the code using git.
 *
 * RFC-060: Only RED tests are generated - tests that prove vulnerability exists
 */

import { execSync } from 'child_process';
import { writeFileSync, unlinkSync, mkdirSync, rmSync } from 'fs';
import { join, dirname } from 'path';
import { tmpdir } from 'os';
import { VulnerabilityTestSuite, RedTest } from './test-generator.js';
import { logger } from '../utils/logger.js';

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

export interface ValidationResult {
  success: boolean;
  vulnerableCommit: {
    redTestsPassed: boolean[];  // Each should fail (vulnerability exists)
    allPassed: boolean;         // Should be false on vulnerable code
  };
  fixedCommit: {
    redTestsPassed: boolean[];  // Each should pass (vulnerability fixed)
    allPassed: boolean;         // Should be true on fixed code
  };
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

      // Create temporary test file
      const testFile = this.createTestFile(testSuite);
      const testPath = join(this.workDir, 'validation.test.js');

      // Ensure directory exists
      mkdirSync(dirname(testPath), { recursive: true });
      writeFileSync(testPath, testFile);

      // Test on vulnerable commit
      const vulnerableResults = await this.runTestsOnCommit(
        vulnerableCommit,
        testPath,
        testSuite
      );

      // Test on fixed commit
      const fixedResults = await this.runTestsOnCommit(
        fixedCommit,
        testPath,
        testSuite
      );

      // Clean up
      try {
        unlinkSync(testPath);
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
          allPassed: false
        },
        fixedCommit: {
          redTestsPassed: [],
          allPassed: false
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
    testPath: string,
    testSuite: VulnerabilityTestSuite
  ): Promise<{
    redTestsPassed: boolean[];
    allPassed: boolean;
  }> {
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
      const redTestsPassed = redTests.map((_, index) =>
        this.runSingleTest(testPath, index)
      );

      const allPassed = redTestsPassed.every(passed => passed);

      return {
        redTestsPassed,
        allPassed
      };
    } finally {
      // Restore original branch
      execSync(`git checkout ${currentBranch} --quiet`, { cwd: this.repoPath });
    }
  }

  /**
   * Run a single RED test by index
   */
  private runSingleTest(testPath: string, testIndex: number): boolean {
    try {
      // Create a minimal test runner that executes the test code
      const testWrapper = `
        const { execSync } = require('child_process');
        const fs = require('fs');
        const path = require('path');

        // Load test suite
        const testSuite = require('${testPath}');
        const test = testSuite.redTests[${testIndex}];

        if (!test) {
          console.error('Test not found at index ${testIndex}');
          process.exit(1);
        }

        // Create a proper test file with the test framework
        const testFileContent = \`
          // Minimal test runner for validation
          const assert = require('assert');

          // Mock test function if not available
          if (typeof test === 'undefined') {
            global.test = async (name, fn) => {
              console.log('Running test:', name);
              try {
                await fn();
                console.log('✓ Test passed');
              } catch (error) {
                console.error('✗ Test failed:', error.message);
                throw error;
              }
            };
          }

          // Mock expect if not available
          if (typeof expect === 'undefined') {
            global.expect = (actual) => ({
              toBe: (expected) => assert.strictEqual(actual, expected),
              toBeTruthy: () => assert.ok(actual),
              toBeFalsy: () => assert.ok(!actual),
              toContain: (substring) => assert.ok(actual.includes(substring)),
              not: {
                toBe: (expected) => assert.notStrictEqual(actual, expected),
                toContain: (substring) => assert.ok(!actual.includes(substring))
              }
            });
          }

          // Execute the test
          (async () => {
            try {
              \${test.testCode}
              process.exit(0);
            } catch (error) {
              console.error('Test execution failed:', error.message);
              process.exit(1);
            }
          })();
        \`;

        // Write and execute test file
        const tempTestFile = '${testPath.replace('.test.js', '')}.red_${testIndex}.runner.js';
        fs.writeFileSync(tempTestFile, testFileContent);

        try {
          execSync(\`node \${tempTestFile}\`, {
            cwd: '${this.repoPath}',
            stdio: 'pipe'
          });
          fs.unlinkSync(tempTestFile);
          process.exit(0);
        } catch (error) {
          fs.unlinkSync(tempTestFile);
          process.exit(1);
        }
      `;

      const wrapperPath = testPath.replace('.test.js', `.red_${testIndex}.wrapper.js`);
      writeFileSync(wrapperPath, testWrapper);

      execSync(`node ${wrapperPath}`, {
        cwd: this.repoPath,
        stdio: 'pipe' // Suppress output
      });

      unlinkSync(wrapperPath);
      return true;
    } catch (error) {
      logger.debug(`RED test ${testIndex} failed:`, error);
      return false;
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
    const testObjects = redTests.map((redTest, index) => `  {
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
   */
  private validateResults(
    vulnerableResults: { redTestsPassed: boolean[]; allPassed: boolean },
    fixedResults: { redTestsPassed: boolean[]; allPassed: boolean }
  ): boolean {
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
