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
  if (/Cannot find module|ModuleNotFoundError|No module named|LoadError.*cannot load such file/i.test(combined)) {
    return { type: 'missing_dependency', isValidFailure: false, reason: 'Missing dependency or module' };
  }
  if (/command not found|ENOENT/i.test(combined)) {
    return { type: 'command_not_found', isValidFailure: false, reason: 'Command or file not found' };
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
