/**
 * GitHub implementation of ForgeAdapter (RFC-096 Phase D).
 *
 * Wraps Octokit calls that are currently scattered across issue-creator.ts,
 * repository-scanner.ts, and github/api.ts into a single adapter.
 */

import { Octokit } from '@octokit/rest';
import type {
  ForgeAdapter,
  ForgeIssue,
  ForgePR,
  ForgeTreeEntry,
  PullRequestParams,
  IssueCreateParams,
  IssueUpdateParams,
} from './forge-adapter.js';

export class GitHubAdapter implements ForgeAdapter {
  private octokit: Octokit;

  constructor(token: string) {
    this.octokit = new Octokit({
      auth: token,
      timeZone: 'UTC',
    });
  }

  async listIssues(
    owner: string,
    repo: string,
    labels: string,
    state: 'open' | 'closed'
  ): Promise<ForgeIssue[]> {
    const { data } = await this.octokit.issues.listForRepo({
      owner,
      repo,
      labels,
      state,
    });

    return data.map((issue) => ({
      number: issue.number,
      title: issue.title,
      url: issue.html_url,
      labels: (issue.labels || []).map((l) =>
        typeof l === 'string' ? l : l.name || ''
      ),
      state: issue.state as 'open' | 'closed',
    }));
  }

  async createIssue(
    owner: string,
    repo: string,
    params: IssueCreateParams
  ): Promise<ForgeIssue> {
    const { data } = await this.octokit.issues.create({
      owner,
      repo,
      title: params.title,
      body: params.body,
      labels: params.labels,
    });

    return {
      number: data.number,
      title: data.title,
      url: data.html_url,
      labels: (data.labels || []).map((l) =>
        typeof l === 'string' ? l : l.name || ''
      ),
      state: data.state as 'open' | 'closed',
    };
  }

  async updateIssue(
    owner: string,
    repo: string,
    issueNumber: number,
    updates: IssueUpdateParams
  ): Promise<void> {
    await this.octokit.issues.update({
      owner,
      repo,
      issue_number: issueNumber,
      ...updates,
    });
  }

  async addLabels(
    owner: string,
    repo: string,
    issueNumber: number,
    labels: string[]
  ): Promise<void> {
    await this.octokit.issues.addLabels({
      owner,
      repo,
      issue_number: issueNumber,
      labels,
    });
  }

  async removeLabel(
    owner: string,
    repo: string,
    issueNumber: number,
    label: string
  ): Promise<void> {
    try {
      await this.octokit.request(
        'DELETE /repos/{owner}/{repo}/issues/{issue_number}/labels/{name}',
        {
          owner,
          repo,
          issue_number: issueNumber,
          name: label,
        }
      );
    } catch (err: unknown) {
      // Ignore 404 — label already removed
      if (err && typeof err === 'object' && 'status' in err && err.status === 404) {
        return;
      }
      throw err;
    }
  }

  async createComment(
    owner: string,
    repo: string,
    issueNumber: number,
    body: string
  ): Promise<void> {
    await this.octokit.issues.createComment({
      owner,
      repo,
      issue_number: issueNumber,
      body,
    });
  }

  async createPullRequest(
    owner: string,
    repo: string,
    params: PullRequestParams
  ): Promise<ForgePR> {
    const { data } = await this.octokit.pulls.create({
      owner,
      repo,
      title: params.title,
      body: params.body,
      head: params.head,
      base: params.base,
    });

    return {
      number: data.number,
      title: data.title,
      url: data.html_url,
      head: data.head.ref,
      base: data.base.ref,
    };
  }

  async listPullRequests(
    owner: string,
    repo: string,
    head?: string
  ): Promise<ForgePR[]> {
    const { data } = await this.octokit.pulls.list({
      owner,
      repo,
      state: 'open',
      ...(head ? { head: `${owner}:${head}` } : {}),
    });

    return data.map((pr) => ({
      number: pr.number,
      title: pr.title,
      url: pr.html_url,
      head: pr.head.ref,
      base: pr.base.ref,
    }));
  }

  async getFileTree(
    owner: string,
    repo: string,
    branch: string
  ): Promise<ForgeTreeEntry[]> {
    const { data } = await this.octokit.git.getTree({
      owner,
      repo,
      tree_sha: branch,
      recursive: '1',
    });

    return (data.tree || []).map((entry) => ({
      path: entry.path || '',
      type: entry.type as 'blob' | 'tree',
      sha: entry.sha || '',
      size: entry.size,
    }));
  }

  async getFileContent(
    owner: string,
    repo: string,
    path: string,
    ref: string
  ): Promise<string | null> {
    try {
      const { data } = await this.octokit.repos.getContent({
        owner,
        repo,
        path,
        ref,
      });

      if (!Array.isArray(data) && 'content' in data && data.content && data.encoding === 'base64') {
        return Buffer.from(data.content, 'base64').toString('utf-8');
      }

      return null;
    } catch (err: unknown) {
      if (err && typeof err === 'object' && 'status' in err && err.status === 404) {
        return null;
      }
      throw err;
    }
  }
}
