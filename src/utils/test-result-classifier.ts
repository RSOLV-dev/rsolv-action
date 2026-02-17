/**
 * Test Result Classifier
 *
 * Extracted from ValidationMode (RFC-060-AMENDMENT-001).
 * Classifies test execution results to distinguish real test failures
 * (vulnerability proven) from infrastructure errors (syntax, missing deps, etc.).
 *
 * Used by both GitBasedTestValidator and ValidationMode.
 */

export interface TestResultClassification {
  type: 'test_passed' | 'test_failed' | 'syntax_error' | 'runtime_error' |
        'missing_dependency' | 'command_not_found' | 'oom_killed' | 'terminated' | 'unknown';
  isValidFailure: boolean;
  reason: string;
}

/**
 * Classify a test execution result based on exit code and output.
 *
 * Distinguishes between valid test failures (vulnerability proven) and
 * errors (syntax errors, missing dependencies, etc.) that don't prove anything.
 *
 * Priority order: exit code specials > error patterns > test failure patterns > unknown
 */
export function classifyTestResult(exitCode: number, stdout: string, stderr: string): TestResultClassification {
  const combined = stdout + stderr;

  // Check exit code first
  if (exitCode === 0) {
    return { type: 'test_passed', isValidFailure: false, reason: 'Tests passed - vulnerability not proven' };
  }
  if (exitCode === 127) {
    return { type: 'command_not_found', isValidFailure: false, reason: 'Test runner not installed' };
  }
  if (exitCode === 137) {
    return { type: 'oom_killed', isValidFailure: false, reason: 'Process killed - out of memory' };
  }
  if (exitCode === 143 || exitCode === 130) {
    return { type: 'terminated', isValidFailure: false, reason: 'Process terminated or interrupted' };
  }

  // Check for error patterns FIRST (take priority over failure markers)
  if (/SyntaxError|Unexpected token|unexpected end of|syntax error/i.test(combined)) {
    return { type: 'syntax_error', isValidFailure: false, reason: 'Syntax error in test file' };
  }
  if (/ReferenceError|is not defined/i.test(combined)) {
    return { type: 'runtime_error', isValidFailure: false, reason: 'Reference error - undefined variable' };
  }
  if (/TypeError:.*is not a function/i.test(combined)) {
    return { type: 'runtime_error', isValidFailure: false, reason: 'Type error - function not found' };
  }
  if (/Cannot find module|ModuleNotFoundError|No module named|cannot load such file|LoadError|GemNotFound|Could not find.*in locally installed gems/i.test(combined)) {
    return { type: 'missing_dependency', isValidFailure: false, reason: 'Missing dependency or module' };
  }
  if (/command not found|ENOENT/i.test(combined)) {
    return { type: 'command_not_found', isValidFailure: false, reason: 'Command or file not found' };
  }
  // Vitest/Jest: "No test files found" — test file name doesn't match include pattern
  if (/No test files found/i.test(combined)) {
    return { type: 'runtime_error', isValidFailure: false, reason: 'No test files found — file naming may not match framework include pattern' };
  }

  // RFC-101 v3.8.71: Database unavailable patterns (infrastructure errors)
  // Elixir/Ecto: "The database for ... couldn't be created: killed"
  // PostgreSQL: "could not connect to server" or "Connection refused"
  // MySQL: "Can't connect to MySQL server" or "Access denied"
  if (/database.*couldn't be created|couldn't be created.*killed/i.test(combined)) {
    return { type: 'runtime_error', isValidFailure: false, reason: 'Database unavailable - PostgreSQL service required' };
  }
  if (/could not connect to server|Connection refused.*postgres|ECONNREFUSED.*5432/i.test(combined)) {
    return { type: 'runtime_error', isValidFailure: false, reason: 'PostgreSQL connection refused - service not running' };
  }
  if (/Can't connect to MySQL server|Access denied for user.*@/i.test(combined)) {
    return { type: 'runtime_error', isValidFailure: false, reason: 'MySQL unavailable - service not running or access denied' };
  }

  // Maven/Java compilation errors (version mismatch, missing symbols, etc.)
  if (/Fatal error compiling|release version \d+ not supported/i.test(combined)) {
    return { type: 'runtime_error', isValidFailure: false, reason: 'Java compilation error - version mismatch or unsupported release' };
  }
  // Gradle class version mismatch: "Unsupported class file major version 65" (Java 21 on old Gradle)
  if (/Unsupported class file major version/i.test(combined)) {
    return { type: 'runtime_error', isValidFailure: false, reason: 'Gradle version incompatible with installed Java - upgrade Gradle wrapper required' };
  }
  // Gradle cache permissions: "Could not open settings generic class cache" (root cause #31)
  if (/Could not open settings generic class cache/i.test(combined)) {
    return { type: 'runtime_error', isValidFailure: false, reason: 'Gradle cache permissions error - set GRADLE_USER_HOME to a writable directory' };
  }
  // PHP Fatal errors (version mismatch, incompatible code)
  if (/PHP Fatal error/i.test(combined)) {
    return { type: 'runtime_error', isValidFailure: false, reason: 'PHP fatal error - version or compatibility issue' };
  }

  // Check for empty test runs BEFORE failure patterns — "0 examples, 0 failures" in RSpec
  // or "0 passing" in Mocha should NOT be classified as valid failures
  if (/0 examples?,\s*0 failures?/i.test(combined)) {
    return { type: 'runtime_error', isValidFailure: false, reason: 'No test examples executed (RSpec error outside examples)' };
  }
  // RFC-103: Detect module-level assertions — "0 passing" WITH assertion errors means
  // assertions ran at module load time (outside it() blocks), not inside test callbacks.
  // IMPORTANT: Exclude cases where "N failing" (N>=1) is present — that means mocha
  // DID discover and run tests. "0 passing, 1 failing" is a genuine test failure, not
  // module-level assertions. Module-level assertions produce "0 passing" with NO "failing" count.
  if (/0 passing|0 tests?\b|no tests? found|test suite empty/i.test(combined) &&
      !/[1-9]\d*\s+(passing|pass|passed)/i.test(combined) &&
      !/[1-9]\d*\s+failing/i.test(combined)) {
    if (/AssertionError|assert\.|expect\(|should\./i.test(combined)) {
      return {
        type: 'runtime_error',
        isValidFailure: false,
        reason: 'Module-level assertions detected: Assertions ran at load time outside it() blocks. Move ALL assertions inside it() callback functions.'
      };
    }
    return { type: 'runtime_error', isValidFailure: false, reason: 'No tests found or executed in test file' };
  }

  // Check for valid test failure patterns
  if (/AssertionError/i.test(combined)) {
    return { type: 'test_failed', isValidFailure: true, reason: 'Assertion failed - vulnerability proven' };
  }
  // Jest/Vitest "Expected:/Received:" output patterns
  if (/Expected:.*\n.*Received:/i.test(combined) ||
      /Received:.*\n.*Expected:/i.test(combined)) {
    return { type: 'test_failed', isValidFailure: true, reason: 'Jest/Vitest assertion failed - vulnerability proven' };
  }
  // Chai/RSpec "expected ... to" patterns
  if (/expected\s+.*\s+to\s+(be|equal|match|include|contain)/i.test(combined)) {
    return { type: 'test_failed', isValidFailure: true, reason: 'Assertion failed - vulnerability proven' };
  }
  // Checkmark failure symbols
  if (/[✗✖]/.test(combined) && exitCode === 1) {
    return { type: 'test_failed', isValidFailure: true, reason: 'Test failed (checkmark) - vulnerability proven' };
  }

  // === FRAMEWORK-SPECIFIC PATTERNS (RFC-101 iteration 11) ===

  // pytest: "FAILED test_file.py::test_name" or "E       assert"
  if (/FAILED\s+\S+\.py::/i.test(combined) ||
      /^E\s+assert/m.test(combined)) {
    return { type: 'test_failed', isValidFailure: true, reason: 'pytest assertion failed - vulnerability proven' };
  }

  // ExUnit (Elixir): "** (ExUnit.AssertionError)" or "Assertion with == failed" or "1) test"
  if (/\(ExUnit\.AssertionError\)/i.test(combined) ||
      /Assertion with (==|!=|=~) failed/i.test(combined) ||
      /^\s*\d+\)\s+test\s+/m.test(combined)) {
    return { type: 'test_failed', isValidFailure: true, reason: 'ExUnit assertion failed - vulnerability proven' };
  }

  // PHPUnit: "Failed asserting" or "FAILURES!" or "Failures: N"
  if (/Failed asserting that/i.test(combined) ||
      /FAILURES!/i.test(combined) ||
      /Failures:\s*\d+/i.test(combined)) {
    return { type: 'test_failed', isValidFailure: true, reason: 'PHPUnit assertion failed - vulnerability proven' };
  }

  // JUnit/Maven: "AssertionFailedError" or "expected:<...> but was:<...>" or "BUILD FAILURE" with test context
  if (/AssertionFailedError/i.test(combined) ||
      /expected:<.*?>\s+but was:<.*?>/i.test(combined) ||
      /java\.lang\.AssertionError/i.test(combined)) {
    return { type: 'test_failed', isValidFailure: true, reason: 'JUnit assertion failed - vulnerability proven' };
  }

  // Mocha: "N failing" with exit code 1 and actual failure (not just syntax error)
  if (/\d+\s+failing/i.test(combined) && exitCode === 1) {
    return { type: 'test_failed', isValidFailure: true, reason: 'Mocha test failed - vulnerability proven' };
  }

  // FAIL marker with failure indicators
  if (/(FAIL|FAILED|Failures:|failed)/i.test(combined) && exitCode === 1) {
    if (/(tests?|examples?|specs?).*fail/i.test(combined) ||
        /\d+\s+(failed|failure)/i.test(combined)) {
      return { type: 'test_failed', isValidFailure: true, reason: 'Test failed - vulnerability proven' };
    }
  }

  // Unknown exit code 1 - could be test failure or error
  return { type: 'unknown', isValidFailure: false, reason: 'Exit code 1 without clear failure pattern - manual review needed' };
}

/**
 * RFC-103 B4: Infrastructure failure types — these indicate the validation
 * infrastructure couldn't run, NOT that the vulnerability is a false positive.
 */
const INFRASTRUCTURE_FAILURE_TYPES: TestResultClassification['type'][] = [
  'runtime_error',
  'missing_dependency',
  'command_not_found',
  'oom_killed',
  'terminated',
];

/**
 * RFC-103 B4: Check if a test result classification represents an infrastructure
 * failure rather than a genuine false positive.
 *
 * When validation fails due to infrastructure issues (wrong runtime version,
 * missing database, etc.), the vulnerability may still be real — we just
 * couldn't prove it. These should be labeled 'rsolv:validation-inconclusive'
 * instead of 'rsolv:false-positive'.
 */
export function isInfrastructureFailure(result: TestResultClassification): boolean {
  return INFRASTRUCTURE_FAILURE_TYPES.includes(result.type);
}

/**
 * Parse test output to extract pass/fail counts.
 * Handles Mocha, Jest/Vitest, pytest, and RSpec output formats.
 */
export function parseTestOutputCounts(output: string): { passed: number; failed: number; total: number } {
  // Mocha: "N passing" + "N failing"
  const mochaPass = output.match(/(\d+)\s+passing/i);
  const mochaFail = output.match(/(\d+)\s+failing/i);
  if (mochaPass || mochaFail) {
    const passed = mochaPass ? parseInt(mochaPass[1], 10) : 0;
    const failed = mochaFail ? parseInt(mochaFail[1], 10) : 0;
    return { passed, failed, total: passed + failed };
  }

  // Jest/Vitest: "Tests: N failed, N passed, N total"
  const jestMatch = output.match(/Tests:\s+(?:(\d+)\s+failed,?\s*)?(?:(\d+)\s+passed,?\s*)?(\d+)\s+total/i);
  if (jestMatch) {
    return {
      failed: parseInt(jestMatch[1] || '0', 10),
      passed: parseInt(jestMatch[2] || '0', 10),
      total: parseInt(jestMatch[3], 10)
    };
  }

  // pytest: "N passed, N failed" or "N failed"
  const pytestPass = output.match(/(\d+)\s+passed/i);
  const pytestFail = output.match(/(\d+)\s+failed/i);
  if (pytestPass || pytestFail) {
    const passed = pytestPass ? parseInt(pytestPass[1], 10) : 0;
    const failed = pytestFail ? parseInt(pytestFail[1], 10) : 0;
    return { passed, failed, total: passed + failed };
  }

  // RSpec: "N examples, N failures"
  const rspecMatch = output.match(/(\d+)\s+examples?,\s+(\d+)\s+failures?/i);
  if (rspecMatch) {
    const total = parseInt(rspecMatch[1], 10);
    const failed = parseInt(rspecMatch[2], 10);
    return { passed: total - failed, failed, total };
  }

  // Fallback
  return { passed: 0, failed: 0, total: 0 };
}
