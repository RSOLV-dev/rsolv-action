/**
 * Validation data helper utilities
 *
 * Provides helper functions for working with validation data across
 * the three-phase architecture (SCAN → VALIDATE → MITIGATE).
 */

import { IssueContext } from '../types/index.js';
import { ValidationData, isValidationData } from '../types/validation.js';
import { logger } from './logger.js';

/**
 * Safely extracts validation data from an issue context
 *
 * This helper ensures type safety and provides logging for debugging
 * data flow issues in the three-phase architecture.
 *
 * @param issue - Issue context that may contain validation data
 * @returns Validated ValidationData object or undefined
 *
 * @example
 * ```typescript
 * const validationData = extractValidationData(issue);
 * if (validationData) {
 *   console.log('Using validation branch:', validationData.branchName);
 * }
 * ```
 */
export function extractValidationData(issue: IssueContext): ValidationData | undefined {
  if (!issue.validationData) {
    logger.debug(`[ValidationHelper] No validation data found for issue #${issue.number}`);
    return undefined;
  }

  if (!isValidationData(issue.validationData)) {
    logger.warn(`[ValidationHelper] Invalid validation data structure for issue #${issue.number}`);
    return undefined;
  }

  logger.info(`[ValidationHelper] Extracted validation data for issue #${issue.number}`, {
    hasBranch: !!issue.validationData.branchName,
    hasTests: !!issue.validationData.redTests,
    hasResults: !!issue.validationData.testResults,
    vulnerabilityCount: issue.validationData.vulnerabilities?.length || 0
  });

  return {
    branchName: issue.validationData.branchName,
    redTests: issue.validationData.redTests,
    testResults: issue.validationData.testResults,
    vulnerabilities: issue.validationData.vulnerabilities,
    timestamp: issue.validationData.timestamp,
    commitHash: issue.validationData.commitHash,
    confidence: issue.validationData.confidence
  };
}

/**
 * Validates that validation data contains the minimum required fields
 *
 * @param data - Validation data to check
 * @returns True if data has at least branch name or test results
 */
export function hasMinimumValidationData(data: ValidationData | undefined): boolean {
  if (!data) return false;
  return !!(data.branchName || data.testResults);
}

/**
 * Creates a summary string of validation data for logging
 *
 * @param data - Validation data to summarize
 * @returns Human-readable summary string
 *
 * @example
 * ```typescript
 * const summary = summarizeValidationData(validationData);
 * // Returns: "branch: rsolv/validate/issue-123, tests: 3 failed/3 total, vulns: 1"
 * ```
 */
export function summarizeValidationData(data: ValidationData | undefined): string {
  if (!data) return 'none';

  const parts: string[] = [];

  if (data.branchName) {
    parts.push(`branch: ${data.branchName}`);
  }

  if (data.testResults) {
    const { failed = 0, total = 0 } = data.testResults;
    parts.push(`tests: ${failed} failed/${total} total`);
  }

  if (data.vulnerabilities) {
    parts.push(`vulns: ${data.vulnerabilities.length}`);
  }

  if (data.timestamp) {
    parts.push(`validated: ${new Date(data.timestamp).toISOString()}`);
  }

  return parts.join(', ');
}
