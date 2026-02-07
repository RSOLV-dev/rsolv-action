/**
 * Retry Feedback Functions
 * RFC-103: RED Test Generation Quality Improvements
 *
 * Provides specific feedback when retry happens, explaining WHY the previous attempt failed.
 */

import { getAssertionTemplate } from '../prompts/vulnerability-assertion-templates.js';

interface RetryGuidance {
  feedback: string;
  behavioral_hint: string;
  few_shot_example: string | null;
}

interface PreviousAttempt {
  attempt: number;
  error: string;
  errorMessage?: string;
  generatedCode?: string;
  testOutput?: string;
  /** RFC-103 Phase 4: Platform retry guidance when test classified as static */
  retryGuidance?: RetryGuidance;
}

interface Vulnerability {
  type?: string;
  cweId?: string;
}

/**
 * Extract the name of the missing module from an error message.
 * Supports Node, Python, Ruby, PHP, and Java error formats.
 *
 * @param errorMessage - The error message from test execution
 * @returns The module name, or 'unknown' if not extractable
 */
export function extractMissingModule(errorMessage: string): string {
  if (!errorMessage) return 'unknown';

  // Node: Cannot find module 'chai'
  const nodeMatch = errorMessage.match(/Cannot find module '([^']+)'/);
  if (nodeMatch) return nodeMatch[1];

  // Python: ModuleNotFoundError: No module named 'X' or ImportError: No module named 'X'
  const pythonMatch = errorMessage.match(/No module named '([^']+)'/);
  if (pythonMatch) return pythonMatch[1];

  // Ruby: cannot load such file -- X or LoadError: cannot load such file -- X
  const rubyMatch = errorMessage.match(/cannot load such file -- (\S+)/);
  if (rubyMatch) return rubyMatch[1];

  // PHP: Class 'X' not found
  const phpMatch = errorMessage.match(/Class '([^']+)' not found/);
  if (phpMatch) return phpMatch[1];

  // Java: java.lang.ClassNotFoundException: X
  const javaMatch = errorMessage.match(/ClassNotFoundException: (\S+)/);
  if (javaMatch) return javaMatch[1];

  return 'unknown';
}

/**
 * Build specific retry feedback based on the error type and vulnerability context.
 *
 * @param attempt - The previous attempt details
 * @param vulnerability - The vulnerability being tested
 * @param availableLibraries - List of available test libraries in the project
 * @returns Formatted feedback string to include in the next prompt
 */
export function buildRetryFeedback(
  attempt: PreviousAttempt,
  vulnerability: Vulnerability,
  availableLibraries: string[]
): string {
  let feedback = '';

  // Handle test-passed-unexpectedly with detailed guidance
  if (attempt.error === 'TestPassedUnexpectedly') {
    feedback += `\n## WHY YOUR PREVIOUS TEST FAILED TO PROVE THE VULNERABILITY\n`;
    feedback += `Your test checked that the function RUNS, not that it's VULNERABLE.\n`;
    feedback += `The ${vulnerability.type || 'vulnerability'} occurs because user input is not sanitized.\n`;
    feedback += `Write a test that captures the vulnerable behavior, not just the function output.\n`;

    // Include assertion template guidance if available
    if (vulnerability.cweId) {
      const template = getAssertionTemplate(vulnerability.cweId);
      if (template) {
        feedback += `\n## ASSERTION STRATEGY FOR ${template.name}\n`;
        feedback += `Goal: ${template.assertionGoal}\n`;
        feedback += `Attack payload to use: ${template.attackPayload}\n`;
        feedback += `Strategy: ${template.testStrategy}\n`;
      }
    }
  }

  // Handle syntax errors with specific error location
  if (attempt.error === 'SyntaxError') {
    feedback += `\n## SYNTAX ERROR IN PREVIOUS ATTEMPT\n`;
    feedback += `Error: ${attempt.errorMessage || 'Unknown syntax error'}\n`;
    feedback += `Fix the syntax error and ensure the test file is valid code.\n`;
  }

  // Handle missing dependency errors
  const isMissingDep =
    attempt.error === 'MissingDependency' ||
    (attempt.error === 'runtime_error' && attempt.errorMessage?.includes('Cannot find module')) ||
    (attempt.error === 'TestExecutionError' && attempt.errorMessage?.includes('MODULE_NOT_FOUND'));

  if (isMissingDep) {
    const missingModule = extractMissingModule(attempt.errorMessage || '');
    feedback += `\n## MISSING DEPENDENCY IN PREVIOUS ATTEMPT\n`;
    feedback += `You used '${missingModule}' which is not available in this project.\n`;

    if (availableLibraries.length > 0) {
      feedback += `\nAvailable libraries: ${availableLibraries.join(', ')}\n`;
      feedback += `Use ONLY these libraries or the language's built-in assertions.\n`;
    } else {
      feedback += `Use ONLY the language's built-in assertions (e.g., Node's assert module).\n`;
    }
  }

  // Handle static test rejection with platform-provided guidance
  if (attempt.error === 'StaticTestNotAcceptable') {
    if (attempt.retryGuidance) {
      feedback += `\n## STATIC TEST REJECTED — GENERATE A BEHAVIORAL TEST\n`;
      feedback += `${attempt.retryGuidance.feedback}\n`;
      feedback += `\n### BEHAVIORAL HINT\n`;
      feedback += `${attempt.retryGuidance.behavioral_hint}\n`;
      if (attempt.retryGuidance.few_shot_example) {
        feedback += `\n### EXAMPLE BEHAVIORAL TEST\n`;
        feedback += `\`\`\`\n${attempt.retryGuidance.few_shot_example}\n\`\`\`\n`;
      }
    } else {
      feedback += `\n## STATIC TEST REJECTED — GENERATE A BEHAVIORAL TEST\n`;
      feedback += `Your test reads source files and pattern-matches for code patterns. ` +
        `This only proves the pattern exists, NOT that it's exploitable.\n`;
      feedback += `Generate a BEHAVIORAL test that imports the vulnerable module, ` +
        `calls it with malicious input, and asserts on the runtime behavior.\n`;
      feedback += `DO NOT read source files. DO NOT use fs.readFileSync, open(), File.read, ` +
        `or any file-reading approach.\n`;
    }
  }

  // Generic fallback for other error types
  if (!feedback) {
    feedback += `\n## PREVIOUS ATTEMPT FAILED\n`;
    feedback += `Error type: ${attempt.error}\n`;
    feedback += `Error message: ${attempt.errorMessage || 'Unknown error'}\n`;
    feedback += `Fix the error and ensure tests can run to completion.\n`;
  }

  return feedback;
}
