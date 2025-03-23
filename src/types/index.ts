/**
 * Core types for RSOLV action
 */

/**
 * Supported issue tracking sources
 */
export type IssueSource = 'github' | 'jira' | 'linear' | 'custom';

/**
 * Common issue representation across different sources
 */
export interface IssueContext {
  id: string;
  source: IssueSource;
  title: string;
  body: string;
  labels: string[];
  repository: {
    owner: string;
    name: string;
    branch?: string;
  };
  metadata: Record<string, any>;
  url?: string;
}

/**
 * Configuration for the action
 */
export interface ActionConfig {
  apiKey: string;
  issueTag: string;
  expertReviewCommand: string;
  debug: boolean;
  skipSecurityCheck: boolean;
}

/**
 * Action result status
 */
export enum ActionStatus {
  SUCCESS = 'success',
  FAILURE = 'failure',
  SKIPPED = 'skipped',
}

/**
 * Result of the action execution
 */
export interface ActionResult {
  status: ActionStatus;
  message: string;
  issueContext?: IssueContext;
  error?: Error;
}

/**
 * Webhook payload from external services
 */
export interface ExternalWebhookPayload {
  source: string;
  apiKey: string;
  issue: {
    id: string;
    title: string;
    description: string;
    url: string;
    labels: string[];
  };
  repository: {
    owner: string;
    name: string;
    branch?: string;
  };
}