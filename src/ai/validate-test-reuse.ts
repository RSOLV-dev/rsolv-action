/**
 * MITIGATE: Validate Branch RED Test Reuse
 *
 * When VALIDATE proves a vulnerability with a behavioral RED test,
 * MITIGATE should reuse that exact test with an ecosystem-native runner
 * (pytest, rspec, vitest) instead of generating a brand-new JS-only
 * test suite via TestGeneratingSecurityAnalyzer / GitBasedTestValidator.
 *
 * Data flow:
 *   VALIDATE stores: { validation: { "issue-N": { redTests, framework, testResults } } }
 *   MITIGATE reads: extractValidateRedTest(validationData, issueNumber)
 *   MITIGATE runs:  verifyFixWithValidateRedTest(vulnerableCommit, fixedCommit, redTest, cwd)
 */

import { execSync } from 'child_process';
import { writeFileSync, unlinkSync, existsSync, mkdirSync } from 'fs';
import { join, dirname } from 'path';
import { logger } from '../utils/logger.js';

// --- Types ---

export interface ValidateRedTest {
  testCode: string;
  testFile: string;
  framework: string;
  branchName: string;
}

export interface RunTestResult {
  passed: boolean;
  output: string;
  exitCode: number;
  infrastructureFailure?: boolean;
}

export interface RedTestVerificationResult {
  isValidFix: boolean;
  vulnerableResult: RunTestResult;
  fixedResult: RunTestResult;
  error?: string;
}

// --- Framework → command map ---

/**
 * Map framework name to the native test command.
 * Intentionally simple — 8 lines, no TestRunner instantiation overhead.
 */
function getTestCommand(framework: string, testFile: string): string {
  switch (framework.toLowerCase()) {
    case 'pytest':
      return `pytest "${testFile}" -x -v`;
    case 'rspec':
      return `bundle exec rspec "${testFile}" --format documentation`;
    case 'vitest':
      return `npx vitest run "${testFile}"`;
    case 'jest':
      return `npx jest "${testFile}" --no-coverage`;
    case 'mocha':
      return `npx mocha "${testFile}"`;
    case 'minitest':
      return `ruby "${testFile}"`;
    case 'phpunit':
      return `./vendor/bin/phpunit "${testFile}"`;
    case 'exunit':
      return `mix test "${testFile}"`;
    default:
      // Fallback: try running with the framework name as command
      return `${framework} "${testFile}"`;
  }
}

// --- Core functions ---

/**
 * Extract the proven RED test from VALIDATE phase data.
 *
 * Looks for validation data under both `validation` and `validate` keys
 * (PhaseDataClient may remap during storage/retrieval).
 *
 * Returns null if no usable RED test is found.
 */
export function extractValidateRedTest(
  validationData: Record<string, unknown> | null | undefined,
  issueNumber: number
): ValidateRedTest | null {
  if (!validationData) {
    return null;
  }

  const issueKey = `issue-${issueNumber}`;

  // PhaseDataClient stores under 'validation' or remaps to 'validate'
  const validation =
    (validationData as Record<string, Record<string, unknown>>)?.validation?.[issueKey] ||
    (validationData as Record<string, Record<string, unknown>>)?.validate?.[issueKey];

  if (!validation) {
    logger.debug(`[MITIGATE] No validation entry found for ${issueKey}`);
    return null;
  }

  const data = validation as Record<string, unknown>;

  // Extract framework
  const framework = data.framework as string | undefined;
  if (!framework) {
    logger.debug(`[MITIGATE] No framework in validation data for ${issueKey}`);
    return null;
  }

  // Extract RED test code from redTests structure
  const redTests = data.redTests as Record<string, unknown> | undefined;
  if (!redTests) {
    logger.debug(`[MITIGATE] No redTests in validation data for ${issueKey}`);
    return null;
  }

  let testCode: string | undefined;

  // Handle array format: redTests.redTests[]
  const redTestsArray = redTests.redTests as Array<Record<string, unknown>> | undefined;
  if (redTestsArray && Array.isArray(redTestsArray) && redTestsArray.length > 0) {
    testCode = redTestsArray[0].testCode as string;
  }

  // Handle single format: redTests.red
  if (!testCode) {
    const singleRed = redTests.red as Record<string, unknown> | undefined;
    if (singleRed) {
      testCode = singleRed.testCode as string;
    }
  }

  if (!testCode) {
    logger.debug(`[MITIGATE] No test code found in redTests for ${issueKey}`);
    return null;
  }

  // Extract test file path from testResults
  const testResults = data.testResults as Record<string, unknown> | undefined;
  const testFile = (testResults?.testFile as string) || getDefaultTestFile(framework);

  // Extract branch name
  const branchName = (data.branchName as string) || `rsolv/validate/${issueKey}`;

  return {
    testCode,
    testFile,
    framework,
    branchName,
  };
}

/**
 * Run a RED test with the ecosystem-native runner.
 *
 * Writes the test code to the specified file, runs the framework command,
 * and cleans up the file after execution.
 */
export async function runRedTestForVerification(
  testCode: string,
  testFile: string,
  framework: string,
  workingDir: string
): Promise<RunTestResult> {
  const fullPath = join(workingDir, testFile);

  try {
    // Ensure parent directory exists
    const dir = dirname(fullPath);
    if (!existsSync(dir)) {
      mkdirSync(dir, { recursive: true });
    }

    // Write the RED test to disk
    writeFileSync(fullPath, testCode, 'utf-8');

    // Build and run the native test command
    const command = getTestCommand(framework, testFile);
    logger.info(`[MITIGATE] Running RED test: ${command}`);

    const output = execSync(command, {
      cwd: workingDir,
      encoding: 'utf-8',
      timeout: 60000,
      stdio: ['pipe', 'pipe', 'pipe'],
    });

    return {
      passed: true,
      output: String(output),
      exitCode: 0,
    };
  } catch (error: unknown) {
    const execError = error as {
      status?: number;
      stdout?: Buffer | string;
      stderr?: Buffer | string;
      message?: string;
    };

    const exitCode = execError.status ?? 1;
    const stdout = execError.stdout
      ? typeof execError.stdout === 'string' ? execError.stdout : execError.stdout.toString()
      : '';
    const stderr = execError.stderr
      ? typeof execError.stderr === 'string' ? execError.stderr : execError.stderr.toString()
      : '';
    const output = `${stdout}\n${stderr}`.trim();

    // Exit code 127 = command not found (infrastructure failure)
    if (exitCode === 127) {
      logger.warn(`[MITIGATE] Test runner not found for ${framework}: ${stderr}`);
      return {
        passed: false,
        output,
        exitCode,
        infrastructureFailure: true,
      };
    }

    // Normal test failure (exit code 1 or 2)
    return {
      passed: false,
      output,
      exitCode,
    };
  } finally {
    // Clean up the test file
    try {
      if (existsSync(fullPath)) {
        unlinkSync(fullPath);
      }
    } catch {
      // Ignore cleanup errors
    }
  }
}

/**
 * Verify a fix by running the proven RED test on both the vulnerable
 * and fixed commits.
 *
 * Expected behavior:
 * - Vulnerable commit: RED test FAILS (vulnerability exists)
 * - Fixed commit: RED test PASSES (vulnerability is fixed)
 *
 * If both fail, the fix didn't work.
 * If both pass, the test doesn't detect the vulnerability (test is wrong).
 */
export async function verifyFixWithValidateRedTest(
  vulnerableCommit: string,
  fixedCommit: string,
  redTest: ValidateRedTest,
  workingDir: string
): Promise<RedTestVerificationResult> {
  // Save current HEAD to restore later
  let originalHead: string;
  try {
    originalHead = execSync('git rev-parse HEAD', {
      cwd: workingDir,
      encoding: 'utf-8',
    }).trim();
  } catch {
    originalHead = fixedCommit; // fallback
  }

  let vulnerableResult: RunTestResult;
  let fixedResult: RunTestResult;

  try {
    // Step 1: Checkout vulnerable commit and run RED test (expect FAIL)
    logger.info(`[MITIGATE] Checking out vulnerable commit ${vulnerableCommit.substring(0, 8)} for RED test verification`);
    execSync(`git checkout ${vulnerableCommit} --quiet`, {
      cwd: workingDir,
      encoding: 'utf-8',
    });

    vulnerableResult = await runRedTestForVerification(
      redTest.testCode,
      redTest.testFile,
      redTest.framework,
      workingDir
    );

    logger.info(`[MITIGATE] RED test on vulnerable commit: ${vulnerableResult.passed ? 'PASSED (unexpected)' : 'FAILED (expected)'}`);

    // Step 2: Checkout fixed commit and run RED test (expect PASS)
    logger.info(`[MITIGATE] Checking out fixed commit ${fixedCommit.substring(0, 8)} for RED test verification`);
    execSync(`git checkout ${fixedCommit} --quiet`, {
      cwd: workingDir,
      encoding: 'utf-8',
    });

    fixedResult = await runRedTestForVerification(
      redTest.testCode,
      redTest.testFile,
      redTest.framework,
      workingDir
    );

    logger.info(`[MITIGATE] RED test on fixed commit: ${fixedResult.passed ? 'PASSED (expected)' : 'FAILED (unexpected)'}`);
  } finally {
    // Restore original HEAD
    try {
      execSync(`git checkout ${originalHead} --quiet`, {
        cwd: workingDir,
        encoding: 'utf-8',
      });
    } catch {
      // Best effort restore
      logger.warn('[MITIGATE] Failed to restore original HEAD after verification');
    }
  }

  // Determine if fix is valid:
  // Valid: vulnerable FAILS (test catches vuln) AND fixed PASSES (vuln is gone)
  const isValidFix = !vulnerableResult.passed && fixedResult.passed;

  if (vulnerableResult.passed) {
    logger.warn('[MITIGATE] RED test passed on vulnerable code — test may not detect the vulnerability');
  }
  if (!fixedResult.passed) {
    logger.warn('[MITIGATE] RED test failed on fixed code — fix did not resolve the vulnerability');
  }

  return {
    isValidFix,
    vulnerableResult,
    fixedResult,
  };
}

// --- Helpers ---

function getDefaultTestFile(framework: string): string {
  switch (framework.toLowerCase()) {
    case 'pytest':
      return 'tests/test_vulnerability_validation.py';
    case 'rspec':
      return 'spec/vulnerability_validation_spec.rb';
    case 'vitest':
    case 'jest':
      return '__tests__/vulnerability_validation.test.ts';
    case 'mocha':
      return 'test/vulnerability_validation.test.js';
    case 'minitest':
      return 'test/test_vulnerability_validation.rb';
    case 'phpunit':
      return 'tests/VulnerabilityValidationTest.php';
    case 'exunit':
      return 'test/vulnerability_validation_test.exs';
    default:
      return 'test_vulnerability_validation.txt';
  }
}
