/**
 * Forge abstraction module (RFC-096 Phase D).
 *
 * Re-exports all forge-related types, adapters, and scanners.
 */

export type {
  ForgeAdapter,
  ForgeIssue,
  ForgePR,
  ForgeTreeEntry,
  PullRequestParams,
  IssueCreateParams,
  IssueUpdateParams,
} from './forge-adapter.js';

export { GitHubAdapter } from './github-adapter.js';
export { GitCliScanner } from './git-cli-scanner.js';
