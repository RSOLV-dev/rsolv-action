/**
 * Validation phase data types (RFC-041, RFC-058, RFC-060)
 *
 * This module contains types for data generated during the VALIDATE phase
 * and consumed by the MITIGATE phase for creating educational pull requests.
 *
 * @see {@link https://github.com/RSOLV-dev/RSOLV-action/blob/main/docs/rfcs/RFC-041-THREE-PHASE-ARCHITECTURE.md RFC-041: Three-Phase Architecture}
 * @see {@link https://github.com/RSOLV-dev/RSOLV-action/blob/main/docs/rfcs/RFC-058-VALIDATION-BRANCH-PERSISTENCE.md RFC-058: Validation Branch Persistence}
 * @see {@link https://github.com/RSOLV-dev/RSOLV-action/blob/main/docs/rfcs/RFC-060-ENHANCED-VALIDATION-TEST-PERSISTENCE.md RFC-060: Enhanced Validation}
 */

/**
 * Individual test within a test suite
 */
export interface GeneratedTest {
  /** The actual test code */
  testCode: string;

  /** Test framework used (e.g., 'jest', 'mocha', 'rspec') */
  framework: string;

  /** Optional path where test was/will be written */
  testPath?: string;

  /** Optional test language */
  language?: string;
}

/**
 * Complete test suite generated during validation
 */
export interface TestSuite {
  /** Array of generated tests */
  tests: GeneratedTest[];

  /** Primary test framework for the suite */
  framework: string;

  /** Programming language of the tests */
  language: string;

  /** Optional RED test code (test that fails on vulnerable code) */
  redTest?: string;

  /** Optional GREEN test code (test that passes after fix) */
  greenTest?: string;
}

/**
 * Test execution results from validation phase
 */
export interface TestResults {
  /** Number of tests that passed */
  passed?: number;

  /** Number of tests that failed */
  failed?: number;

  /** Total number of tests run */
  total?: number;

  /** Raw test output */
  output?: string;

  /** Exit code from test runner */
  exitCode?: number;

  /** Duration of test execution in milliseconds */
  duration?: number;
}

/**
 * Validated vulnerability with specific location information
 */
export interface ValidatedVulnerability {
  /** Type of vulnerability (e.g., 'XSS', 'SQLi', 'CSRF') */
  type?: string;

  /** File path where vulnerability was found */
  file?: string;

  /** Line number of vulnerable code */
  line?: number;

  /** Human-readable description */
  description?: string;

  /** CWE identifier (e.g., 'CWE-89') */
  cwe?: string;

  /** Severity level */
  severity?: 'low' | 'medium' | 'high' | 'critical';

  /** Confidence level of detection */
  confidence?: number;
}

/**
 * Complete validation data from VALIDATE phase
 *
 * This data is generated during the VALIDATE phase and used by the MITIGATE
 * phase to create educational pull requests with test-driven evidence.
 *
 * @example
 * ```typescript
 * const validationData: ValidationData = {
 *   branchName: 'rsolv/validate/issue-123',
 *   redTests: {
 *     tests: [{
 *       testCode: 'test("should fail on XSS", ...)',
 *       framework: 'jest',
 *       language: 'javascript'
 *     }],
 *     framework: 'jest',
 *     language: 'javascript'
 *   },
 *   testResults: {
 *     passed: 0,
 *     failed: 3,
 *     total: 3
 *   },
 *   vulnerabilities: [{
 *     type: 'XSS',
 *     file: 'app.js',
 *     line: 42,
 *     severity: 'high'
 *   }],
 *   timestamp: '2025-11-09T12:00:00Z'
 * };
 * ```
 */
export interface ValidationData {
  /**
   * RFC-058: Validation branch name (e.g., "rsolv/validate/issue-123")
   *
   * This branch contains RED tests that fail on vulnerable code
   * and pass after the fix is applied.
   */
  branchName?: string;

  /**
   * Generated RED tests that prove the vulnerability exists
   *
   * These tests are designed to fail when run against the vulnerable
   * code, demonstrating that the vulnerability is real.
   */
  redTests?: TestSuite;

  /**
   * Test execution results from VALIDATE phase
   *
   * Shows how many tests failed (proving vulnerability) before fix.
   */
  testResults?: TestResults;

  /**
   * Specific vulnerabilities identified and validated
   *
   * Each vulnerability includes location, type, and severity information.
   */
  vulnerabilities?: ValidatedVulnerability[];

  /**
   * Timestamp when validation was performed (ISO 8601 format)
   */
  timestamp?: string;

  /**
   * Optional commit hash from validation phase
   */
  commitHash?: string;

  /**
   * Optional confidence level of validation
   */
  confidence?: 'high' | 'medium' | 'low';
}

/**
 * Type guard to check if an object is valid ValidationData
 */
export function isValidationData(obj: unknown): obj is ValidationData {
  if (!obj || typeof obj !== 'object') return false;

  const data = obj as Partial<ValidationData>;

  // At least one field should be present
  return !!(
    data.branchName ||
    data.redTests ||
    data.testResults ||
    data.vulnerabilities ||
    data.timestamp
  );
}

/**
 * Type guard to check if ValidationData has test results
 */
export function hasTestResults(data: ValidationData): data is ValidationData & { testResults: TestResults } {
  return !!data.testResults && typeof data.testResults === 'object';
}

/**
 * Type guard to check if ValidationData has validation branch
 */
export function hasValidationBranch(data: ValidationData): data is ValidationData & { branchName: string } {
  return !!data.branchName && typeof data.branchName === 'string';
}
