import * as github from '@actions/github';
import { IssueContext } from '../types';
import { logger } from '../utils/logger';

/**
 * Extract issue context from GitHub webhook event
 */
export function extractIssueContextFromEvent(context?: any): IssueContext | null {
  try {
    // Use the provided context or fallback to github.context
    const ctx = context || github.context;

    // Check if this is an issue event with a label
    if (ctx.eventName === 'issues' && ctx.payload.action === 'labeled') {
      const label = ctx.payload.label?.name;
      const issue = ctx.payload.issue;
      
      if (!label || !issue) {
        logger.warning('Missing label or issue in event payload');
        return null;
      }
      
      return {
        id: issue.number.toString(),
        source: 'github',
        title: issue.title,
        body: issue.body || '',
        labels: issue.labels.map((label: any) => 
          typeof label === 'string' ? label : label.name
        ),
        repository: {
          owner: ctx.repo.owner,
          name: ctx.repo.repo,
        },
        metadata: {
          htmlUrl: issue.html_url,
          user: issue.user.login,
          state: issue.state,
          createdAt: issue.created_at,
          updatedAt: issue.updated_at,
        },
        url: issue.html_url,
      };
    }
    
    // Check if this is a manually triggered workflow with issue number
    if (ctx.eventName === 'workflow_dispatch') {
      const issueNumber = ctx.payload.inputs?.issue_number;
      if (!issueNumber) {
        logger.warning('No issue number provided in workflow_dispatch event');
        return null;
      }
      
      // Note: This requires fetching the issue details using the GitHub API
      // This will be implemented in getIssueDetails
      return null;
    }
    
    logger.info(`Event ${ctx.eventName} is not supported for automatic issue detection`);
    return null;
  } catch (error) {
    logger.error('Error extracting issue context from event', error as Error);
    return null;
  }
}

/**
 * Get issue details from GitHub API
 */
export async function getIssueDetails(
  token: string, 
  owner: string, 
  repo: string, 
  issueNumber: number
): Promise<IssueContext | null> {
  try {
    const octokit = github.getOctokit(token);
    
    const { data: issue } = await octokit.rest.issues.get({
      owner,
      repo,
      issue_number: issueNumber,
    });
    
    return {
      id: issue.number.toString(),
      source: 'github',
      title: issue.title,
      body: issue.body || '',
      labels: issue.labels.map((label: any) => 
        typeof label === 'string' ? label : label.name
      ),
      repository: {
        owner,
        name: repo,
      },
      metadata: {
        htmlUrl: issue.html_url,
        user: issue.user.login,
        state: issue.state,
        createdAt: issue.created_at,
        updatedAt: issue.updated_at,
      },
      url: issue.html_url,
    };
  } catch (error) {
    logger.error(`Error fetching issue details for ${owner}/${repo}#${issueNumber}`, error as Error);
    return null;
  }
}

/**
 * Check if an issue has the automation tag
 */
export function hasAutomationTag(issueContext: IssueContext, automationTag: string): boolean {
  return issueContext.labels.includes(automationTag);
}

/**
 * Add a comment to an issue
 */
export async function addIssueComment(
  token: string,
  owner: string,
  repo: string,
  issueNumber: number,
  body: string
): Promise<boolean> {
  try {
    const octokit = github.getOctokit(token);
    
    await octokit.rest.issues.createComment({
      owner,
      repo,
      issue_number: issueNumber,
      body,
    });
    
    return true;
  } catch (error) {
    logger.error(`Error adding comment to issue ${owner}/${repo}#${issueNumber}`, error as Error);
    return false;
  }
}

/**
 * Check if an issue is eligible for automation
 */
export function isEligibleForAutomation(issueContext: IssueContext, automationTag: string): boolean {
  // Check if it has the automation tag
  if (!hasAutomationTag(issueContext, automationTag)) {
    return false;
  }
  
  // Check if the issue body is not empty
  if (!issueContext.body || issueContext.body.trim() === '') {
    return false;
  }
  
  // Additional eligibility criteria can be added here
  
  return true;
}