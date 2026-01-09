/**
 * Billing Mode Handler (RFC-091)
 *
 * This mode is triggered when a PR is merged to ensure billing occurs.
 * It calls the platform's /fix-attempts/:id/billing endpoint.
 *
 * Flow:
 * 1. Get PR information from GitHub event context
 * 2. Find the fix attempt for this PR
 * 3. Call billing endpoint (idempotent - safe to call multiple times)
 *
 * This provides:
 * - Primary billing mechanism (Action-initiated)
 * - Guaranteed execution (GitHub Actions SLA)
 * - Customer visibility in workflow logs
 */

import { logger } from '../utils/logger.js';

export interface BillingConfig {
  apiUrl: string;
  apiKey: string;
}

export interface BillingResult {
  success: boolean;
  message: string;
  billingStatus?: string;
  fixAttemptId?: number;
  skipped?: boolean;
  reason?: string;
}

export interface PRContext {
  owner: string;
  repo: string;
  prNumber: number;
  merged: boolean;
  mergedAt?: string;
  mergedBy?: string;
  mergeCommitSha?: string;
}

/**
 * Execute billing mode for a merged PR
 */
export async function executeBillingMode(
  config: BillingConfig,
  prContext: PRContext
): Promise<BillingResult> {
  logger.info('RFC-091: Starting billing mode');
  logger.info(`PR Context: ${prContext.owner}/${prContext.repo}#${prContext.prNumber}`);

  // Only process merged PRs
  if (!prContext.merged) {
    logger.info('PR not merged, skipping billing');
    return {
      success: true,
      message: 'PR not merged - no billing needed',
      skipped: true,
      reason: 'PR not merged',
    };
  }

  // Find the fix attempt for this PR
  const fixAttempt = await findFixAttempt(config, prContext);
  if (!fixAttempt) {
    logger.info('No fix attempt found for this PR, skipping');
    return {
      success: true,
      message: 'No RSOLV fix attempt tracked for this PR',
      skipped: true,
      reason: 'No fix attempt found',
    };
  }

  logger.info(`Found fix attempt ID: ${fixAttempt.id}`);

  // Call billing endpoint
  const billingResult = await callBillingEndpoint(config, fixAttempt.id);

  return billingResult;
}

/**
 * Find fix attempt for a PR from the platform API
 */
async function findFixAttempt(
  config: BillingConfig,
  prContext: PRContext
): Promise<{ id: number } | null> {
  const url = new URL('/api/v1/fix-attempts', config.apiUrl);
  url.searchParams.set('github_org', prContext.owner);
  url.searchParams.set('repo_name', prContext.repo);
  url.searchParams.set('pr_number', prContext.prNumber.toString());

  logger.debug(`Looking up fix attempt: ${url.toString()}`);

  try {
    const response = await fetch(url.toString(), {
      method: 'GET',
      headers: {
        'x-api-key': config.apiKey,
        'Content-Type': 'application/json',
      },
    });

    if (!response.ok) {
      if (response.status === 404) {
        return null;
      }
      logger.warn(`Fix attempt lookup failed: ${response.status}`);
      return null;
    }

    const data = await response.json();
    // The API may return the fix attempt directly or in an array
    if (data.id) {
      return { id: data.id };
    }
    if (Array.isArray(data) && data.length > 0 && data[0].id) {
      return { id: data[0].id };
    }
    if (data.fix_attempts && data.fix_attempts.length > 0) {
      return { id: data.fix_attempts[0].id };
    }

    return null;
  } catch (error) {
    logger.error('Failed to lookup fix attempt', error);
    return null;
  }
}

/**
 * Call the billing endpoint for a fix attempt
 */
async function callBillingEndpoint(
  config: BillingConfig,
  fixAttemptId: number
): Promise<BillingResult> {
  const url = `${config.apiUrl}/api/v1/fix-attempts/${fixAttemptId}/billing`;

  logger.info(`Calling billing endpoint: POST ${url}`);

  try {
    const response = await fetch(url, {
      method: 'POST',
      headers: {
        'x-api-key': config.apiKey,
        'Content-Type': 'application/json',
      },
    });

    if (!response.ok) {
      const errorText = await response.text();
      logger.error(`Billing request failed: ${response.status} - ${errorText}`);

      // Don't fail the workflow for billing errors - log and continue
      return {
        success: false,
        message: `Billing request failed: ${response.status}`,
        fixAttemptId,
      };
    }

    const data = await response.json();

    const alreadyBilled = data.message?.includes('Already') || data.billing_status === 'billed';

    if (alreadyBilled) {
      logger.info('Fix attempt already billed (idempotent)');
    } else {
      logger.info(`Billing processed: ${data.billing_status || 'processing'}`);
    }

    return {
      success: true,
      message: alreadyBilled ? 'Already billed' : 'Billing processed',
      billingStatus: data.billing_status,
      fixAttemptId,
    };
  } catch (error) {
    logger.error('Billing request failed', error);

    // Don't fail the workflow for billing errors
    return {
      success: false,
      message: `Billing request error: ${error instanceof Error ? error.message : String(error)}`,
      fixAttemptId,
    };
  }
}

/**
 * Get PR context from GitHub event payload
 */
export function getPRContextFromEvent(): PRContext | null {
  const eventPath = process.env.GITHUB_EVENT_PATH;
  if (!eventPath) {
    logger.warn('GITHUB_EVENT_PATH not set');
    return null;
  }

  try {
    // Dynamic import for fs to work in ESM
    const fs = require('fs');
    const eventData = JSON.parse(fs.readFileSync(eventPath, 'utf8'));

    if (!eventData.pull_request) {
      logger.warn('Event payload does not contain pull_request');
      return null;
    }

    const pr = eventData.pull_request;
    const repo = pr.base?.repo || eventData.repository;

    return {
      owner: repo?.owner?.login || process.env.GITHUB_REPOSITORY?.split('/')[0] || '',
      repo: repo?.name || process.env.GITHUB_REPOSITORY?.split('/')[1] || '',
      prNumber: pr.number,
      merged: pr.merged === true,
      mergedAt: pr.merged_at,
      mergedBy: pr.merged_by?.login,
      mergeCommitSha: pr.merge_commit_sha,
    };
  } catch (error) {
    logger.error('Failed to parse GitHub event', error);
    return null;
  }
}
