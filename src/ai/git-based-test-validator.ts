/**
 * GitBasedTestValidator - Phase 5E Implementation
 * 
 * Validates that vulnerability fixes actually work by running generated tests
 * against both vulnerable and fixed versions of the code using git.
 */

import { execSync } from 'child_process';
import { writeFileSync, unlinkSync, mkdirSync, rmSync } from 'fs';
import { join, dirname } from 'path';
import { tmpdir } from 'os';
import { VulnerabilityTestSuite } from './test-generator.js';
import { logger } from '../utils/logger.js';

export interface ValidationResult {
  success: boolean;
  vulnerableCommit: {
    redTestPassed: boolean;  // Should fail (vulnerability exists)
    greenTestPassed: boolean; // Should fail (fix not applied)
    refactorTestPassed: boolean; // Should pass (functionality works)
  };
  fixedCommit: {
    redTestPassed: boolean;  // Should pass (vulnerability fixed)
    greenTestPassed: boolean; // Should pass (fix applied)
    refactorTestPassed: boolean; // Should pass (functionality maintained)
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
          redTestPassed: false,
          greenTestPassed: false,
          refactorTestPassed: false
        },
        fixedCommit: {
          redTestPassed: false,
          greenTestPassed: false,
          refactorTestPassed: false
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
    redTestPassed: boolean;
    greenTestPassed: boolean;
    refactorTestPassed: boolean;
  }> {
    // Store current branch
    const currentBranch = execSync('git rev-parse --abbrev-ref HEAD', {
      cwd: this.repoPath,
      encoding: 'utf-8'
    }).trim();

    try {
      // Checkout commit
      execSync(`git checkout ${commit} --quiet`, { cwd: this.repoPath });

      // Run each test individually to get specific results
      const results = {
        redTestPassed: this.runSingleTest(testPath, 'red'),
        greenTestPassed: this.runSingleTest(testPath, 'green'),
        refactorTestPassed: this.runSingleTest(testPath, 'refactor')
      };

      return results;
    } finally {
      // Restore original branch
      execSync(`git checkout ${currentBranch} --quiet`, { cwd: this.repoPath });
    }
  }

  /**
   * Run a single test and return whether it passed
   */
  private runSingleTest(testPath: string, testType: 'red' | 'green' | 'refactor'): boolean {
    try {
      // Create a wrapper that only runs the specific test
      const testWrapper = `
        const testSuite = require('${testPath}');
        const test = testSuite.${testType};
        
        // Simple test runner
        (async () => {
          try {
            await eval(test.testCode);
            process.exit(0);
          } catch (error) {
            console.error('Test failed:', error.message);
            process.exit(1);
          }
        })();
      `;

      const wrapperPath = testPath.replace('.test.js', `.${testType}.js`);
      writeFileSync(wrapperPath, testWrapper);

      execSync(`node ${wrapperPath}`, { 
        cwd: this.repoPath,
        stdio: 'pipe' // Suppress output
      });

      unlinkSync(wrapperPath);
      return true;
    } catch (error) {
      return false;
    }
  }

  /**
   * Create a test file from the test suite
   */
  private createTestFile(testSuite: VulnerabilityTestSuite): string {
    return `
// Generated test file for vulnerability validation
const assert = require('assert');

module.exports = {
  red: {
    testName: "${testSuite.red.testName}",
    testCode: \`${testSuite.red.testCode}\`,
    expectedBehavior: "${testSuite.red.expectedBehavior}"
  },
  green: {
    testName: "${testSuite.green.testName}",
    testCode: \`${testSuite.green.testCode}\`,
    expectedBehavior: "${testSuite.green.expectedBehavior}"
  },
  refactor: {
    testName: "${testSuite.refactor.testName}",
    testCode: \`${testSuite.refactor.testCode}\`,
    expectedBehavior: "${testSuite.refactor.expectedBehavior}"
  }
};

// Export for direct execution
if (require.main === module) {
  (async () => {
    console.log('Running vulnerability validation tests...');
    
    // Run all tests
    for (const [type, test] of Object.entries(module.exports)) {
      console.log(\`Running \${type} test: \${test.testName}\`);
      try {
        await eval(test.testCode);
        console.log(\`✓ \${type} test passed\`);
      } catch (error) {
        console.log(\`✗ \${type} test failed: \${error.message}\`);
      }
    }
  })();
}
`;
  }

  /**
   * Validate that the test results confirm the fix
   */
  private validateResults(
    vulnerableResults: any,
    fixedResults: any
  ): boolean {
    // On vulnerable commit:
    // - Red test should FAIL (vulnerability exists, so test that checks for it fails)
    // - Green test should FAIL (fix not applied yet)
    // - Refactor test should PASS (functionality works)

    // On fixed commit:
    // - Red test should PASS (vulnerability no longer exists)
    // - Green test should PASS (fix is applied)
    // - Refactor test should PASS (functionality still works)

    const vulnerableValid = 
      !vulnerableResults.redTestPassed &&     // Red fails (vuln exists)
      !vulnerableResults.greenTestPassed &&   // Green fails (no fix)
      vulnerableResults.refactorTestPassed;   // Refactor passes

    const fixedValid = 
      fixedResults.redTestPassed &&          // Red passes (vuln fixed)
      fixedResults.greenTestPassed &&        // Green passes (fix applied)
      fixedResults.refactorTestPassed;       // Refactor still passes

    return vulnerableValid && fixedValid;
  }
}