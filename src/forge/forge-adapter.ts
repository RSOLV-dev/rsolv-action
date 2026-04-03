/**
 * Forge-agnostic interface for git forge operations (RFC-096 Phase D).
 *
 * Implementations: GitHubAdapter (now), GitLabAdapter (future), BitbucketAdapter (future).
 *
 * Used by: IssueCreator, MitigationClient (PR creation), RepositoryScanner (file tree).
 * NOT used by: tool executors (they use filesystem/git CLI, already forge-agnostic).
 */

export interface ForgeIssue {
  number: number;
  title: string;
  url: string;
  labels: string[];
  state: 'open' | 'closed';
}

export interface ForgePR {
  number: number;
  title: string;
  url: string;
  head: string;
  base: string;
}

export interface ForgeTreeEntry {
  path: string;
  type: 'blob' | 'tree';
  sha: string;
  size?: number;
}

export interface PullRequestParams {
  title: string;
  body: string;
  head: string;
  base: string;
}

export interface IssueCreateParams {
  title: string;
  body: string;
  labels: string[];
}

export interface IssueUpdateParams {
  title?: string;
  body?: string;
  state?: 'open' | 'closed';
}

export interface ForgeAdapter {
  // Issue operations (SCAN phase)
  listIssues(
    owner: string,
    repo: string,
    labels: string,
    state: 'open' | 'closed'
  ): Promise<ForgeIssue[]>;

  createIssue(
    owner: string,
    repo: string,
    params: IssueCreateParams
  ): Promise<ForgeIssue>;

  updateIssue(
    owner: string,
    repo: string,
    issueNumber: number,
    updates: IssueUpdateParams
  ): Promise<void>;

  addLabels(
    owner: string,
    repo: string,
    issueNumber: number,
    labels: string[]
  ): Promise<void>;

  removeLabel(
    owner: string,
    repo: string,
    issueNumber: number,
    label: string
  ): Promise<void>;

  createComment(
    owner: string,
    repo: string,
    issueNumber: number,
    body: string
  ): Promise<void>;

  // PR operations (MITIGATE phase)
  createPullRequest(
    owner: string,
    repo: string,
    params: PullRequestParams
  ): Promise<ForgePR>;

  listPullRequests(
    owner: string,
    repo: string,
    head?: string
  ): Promise<ForgePR[]>;

  // Repository/tree operations (SCAN phase)
  getFileTree(
    owner: string,
    repo: string,
    branch: string
  ): Promise<ForgeTreeEntry[]>;

  getFileContent(
    owner: string,
    repo: string,
    path: string,
    ref: string
  ): Promise<string | null>;
}
