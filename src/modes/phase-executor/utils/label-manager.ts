/**
 * Label Manager — Shared validation label management (RFC-096 Phase F.2 Step 3)
 *
 * Extracts label management logic from PhaseExecutor into a reusable function
 * that works with backend classification strings.
 *
 * Classification → Label mapping:
 *   validated            → add rsolv:validated, remove rsolv:detected
 *   false_positive       → add rsolv:false-positive, remove rsolv:detected
 *   infrastructure_failure → add rsolv:validation-inconclusive, keep rsolv:detected
 *   inconclusive         → add rsolv:validation-inconclusive, keep rsolv:detected
 *   no_test_framework    → add rsolv:validation-unavailable, keep rsolv:detected
 *   max_turns_exceeded   → add rsolv:validation-inconclusive, keep rsolv:detected
 */

import { addLabels, removeLabel } from '../../../github/api.js';
import { logger } from '../../../utils/logger.js';

export interface LabelIssueInfo {
  owner: string;
  repo: string;
  issueNumber: number;
  currentLabels: string[];
}

/**
 * Apply GitHub labels based on backend validation classification.
 *
 * Non-throwing: label failures are logged but do not propagate.
 */
export async function applyValidationLabels(
  issue: LabelIssueInfo,
  classification: string | undefined
): Promise<void> {
  if (!classification) return;

  try {
    const { owner, repo, issueNumber, currentLabels } = issue;

    switch (classification) {
      case 'validated':
        logger.info(`[LABELS] Adding 'rsolv:validated' to issue #${issueNumber}`);
        await addLabels(owner, repo, issueNumber, ['rsolv:validated']);
        if (currentLabels.includes('rsolv:detected')) {
          logger.info(`[LABELS] Removing 'rsolv:detected' from issue #${issueNumber}`);
          await removeLabel(owner, repo, issueNumber, 'rsolv:detected');
        }
        break;

      case 'false_positive':
        logger.info(`[LABELS] Adding 'rsolv:false-positive' to issue #${issueNumber}`);
        await addLabels(owner, repo, issueNumber, ['rsolv:false-positive']);
        if (currentLabels.includes('rsolv:detected')) {
          logger.info(`[LABELS] Removing 'rsolv:detected' from issue #${issueNumber}`);
          await removeLabel(owner, repo, issueNumber, 'rsolv:detected');
        }
        break;

      case 'infrastructure_failure':
        logger.info(`[LABELS] Adding 'rsolv:validation-inconclusive' to issue #${issueNumber} (infrastructure)`);
        await addLabels(owner, repo, issueNumber, ['rsolv:validation-inconclusive']);
        // Keep rsolv:detected — vulnerability may be real
        break;

      case 'inconclusive':
        logger.info(`[LABELS] Adding 'rsolv:validation-inconclusive' to issue #${issueNumber} (static test)`);
        await addLabels(owner, repo, issueNumber, ['rsolv:validation-inconclusive']);
        // Keep rsolv:detected — behavioral test needed
        break;

      case 'no_test_framework':
        logger.info(`[LABELS] Adding 'rsolv:validation-unavailable' to issue #${issueNumber} (no test framework)`);
        await addLabels(owner, repo, issueNumber, ['rsolv:validation-unavailable']);
        // Keep rsolv:detected — vulnerability may be real
        break;

      case 'max_turns_exceeded':
        logger.info(`[LABELS] Adding 'rsolv:validation-inconclusive' to issue #${issueNumber} (max turns exceeded)`);
        await addLabels(owner, repo, issueNumber, ['rsolv:validation-inconclusive']);
        // Keep rsolv:detected — vulnerability likely real, just ran out of turns
        break;

      default:
        logger.warn(`[LABELS] Unknown classification '${classification}' for issue #${issueNumber}, skipping labels`);
        break;
    }
  } catch (error) {
    logger.warn(`[LABELS] Failed to update labels for issue #${issue.issueNumber}:`, error);
    // Non-fatal — don't fail validation if label update fails
  }
}
