/**
 * Label Manager — Shared validation label management (RFC-096 Phase F.2 Step 3)
 *
 * Extracts label management logic from PhaseExecutor into a reusable function
 * that works with backend classification strings.
 *
 * Classification → Label mapping:
 *   validated   → add rsolv:validated, remove rsolv:detected
 *   anything else (false_positive*, inconclusive, infrastructure_failure, …)
 *               → add rsolv:unconfirmed (+ a detail label where one exists), keep rsolv:detected
 *
 * The Action never applies rsolv:false-positive: scans skip issues carrying it,
 * so applying it to an unproven finding hides that finding for good. Only a
 * human dismisses a finding.
 */

import { addLabels, removeLabel } from '../../../github/api.js';
import { logger } from '../../../utils/logger.js';

async function withRetry<T>(fn: () => Promise<T>, label: string, maxAttempts = 3): Promise<T> {
  for (let attempt = 1; attempt <= maxAttempts; attempt++) {
    try {
      return await fn();
    } catch (error) {
      if (attempt === maxAttempts) throw error;
      const delay = attempt * 1000;
      logger.warn(`[LABELS] ${label} failed (attempt ${attempt}/${maxAttempts}), retrying in ${delay}ms`);
      await new Promise(resolve => setTimeout(resolve, delay));
    }
  }
  throw new Error('unreachable');
}

const DETAIL_LABELS: ReadonlyMap<string, string> = new Map([
  ['infrastructure_failure', 'rsolv:validation-inconclusive'],
  ['inconclusive', 'rsolv:validation-inconclusive'],
  ['max_turns_exceeded', 'rsolv:validation-inconclusive'],
  ['test_passed_unexpectedly', 'rsolv:validation-inconclusive'],
  ['static_test', 'rsolv:validation-inconclusive'],
  ['no_test_framework', 'rsolv:validation-unavailable'],
]);

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

    if (classification === 'validated') {
      logger.info(`[LABELS] Adding 'rsolv:validated' to issue #${issueNumber}`);
      await withRetry(() => addLabels(owner, repo, issueNumber, ['rsolv:validated']), `addLabels(rsolv:validated, #${issueNumber})`);
      if (currentLabels.includes('rsolv:detected')) {
        logger.info(`[LABELS] Removing 'rsolv:detected' from issue #${issueNumber}`);
        await withRetry(() => removeLabel(owner, repo, issueNumber, 'rsolv:detected'), `removeLabel(rsolv:detected, #${issueNumber})`);
      }
      return;
    }

    const detail = DETAIL_LABELS.get(classification);
    const labels = detail ? ['rsolv:unconfirmed', detail] : ['rsolv:unconfirmed'];
    logger.info(`[LABELS] Adding ${labels.join(', ')} to issue #${issueNumber} (${classification})`);
    await withRetry(() => addLabels(owner, repo, issueNumber, labels), `addLabels(${labels.join(',')}, #${issueNumber})`);
  } catch (error) {
    logger.warn(`[LABELS] Failed to update labels for issue #${issue.issueNumber}:`, error);
    // Non-fatal — don't fail validation if label update fails
  }
}
