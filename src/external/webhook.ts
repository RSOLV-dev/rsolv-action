import { ExternalWebhookPayload, IssueContext } from '../types';
import { logger } from '../utils/logger';
import { validateApiKey } from '../utils/security';

/**
 * Process an external webhook payload
 */
export async function processWebhookPayload(payload: ExternalWebhookPayload): Promise<IssueContext | null> {
  try {
    // Validate the API key
    const isValidApiKey = await validateApiKey(payload.apiKey);
    if (!isValidApiKey) {
      logger.error('Invalid API key in webhook payload');
      return null;
    }

    // Validate required fields
    if (!payload.source || !payload.issue || !payload.repository) {
      logger.error('Missing required fields in webhook payload');
      return null;
    }

    // Convert to internal issue context format
    const issueContext: IssueContext = {
      id: payload.issue.id,
      source: payload.source as any, // We'll validate this below
      title: payload.issue.title,
      body: payload.issue.description,
      labels: payload.issue.labels || [],
      repository: {
        owner: payload.repository.owner,
        name: payload.repository.name,
        branch: payload.repository.branch,
      },
      metadata: {
        source: payload.source,
        url: payload.issue.url,
      },
      url: payload.issue.url,
    };

    // Validate source
    const validSources = ['jira', 'linear', 'custom'];
    if (!validSources.includes(payload.source)) {
      logger.warning(`Unknown issue source: ${payload.source}. Treating as 'custom'`);
      issueContext.source = 'custom';
    }

    return issueContext;
  } catch (error) {
    logger.error('Error processing webhook payload', error as Error);
    return null;
  }
}

/**
 * Check if a webhook payload is eligible for automation
 */
export function isEligibleForAutomation(issueContext: IssueContext, automationTag: string): boolean {
  // For external sources, we might have different criteria
  // For now, we'll use the same criteria as GitHub issues
  
  // Check if it has the automation tag
  if (!issueContext.labels.includes(automationTag)) {
    return false;
  }
  
  // Check if the issue body is not empty
  if (!issueContext.body || issueContext.body.trim() === '') {
    return false;
  }
  
  // Additional eligibility criteria can be added here
  
  return true;
}