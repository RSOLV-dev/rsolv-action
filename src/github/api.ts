import * as github from '@actions/github';
import { logger } from '../utils/logger';

/**
 * Helper class for GitHub API operations
 */
export class GitHubApiClient {
  private octokit: ReturnType<typeof github.getOctokit>;
  private owner: string;
  private repo: string;

  constructor(token: string, owner: string, repo: string) {
    this.octokit = github.getOctokit(token);
    this.owner = owner;
    this.repo = repo;
  }

  /**
   * Get the authenticated user
   */
  async getAuthenticatedUser(): Promise<string> {
    try {
      const { data } = await this.octokit.rest.users.getAuthenticated();
      return data.login;
    } catch (error) {
      logger.error('Error getting authenticated user', error as Error);
      throw error;
    }
  }

  /**
   * Get repository details
   */
  async getRepository(): Promise<any> {
    try {
      const { data } = await this.octokit.rest.repos.get({
        owner: this.owner,
        repo: this.repo,
      });
      return data;
    } catch (error) {
      logger.error(`Error getting repository ${this.owner}/${this.repo}`, error as Error);
      throw error;
    }
  }

  /**
   * Create a pull request
   */
  async createPullRequest(
    title: string,
    body: string,
    head: string,
    base: string = 'main'
  ): Promise<number> {
    try {
      const { data } = await this.octokit.rest.pulls.create({
        owner: this.owner,
        repo: this.repo,
        title,
        body,
        head,
        base,
      });
      return data.number;
    } catch (error) {
      logger.error(`Error creating pull request in ${this.owner}/${this.repo}`, error as Error);
      throw error;
    }
  }

  /**
   * Add a label to an issue
   */
  async addIssueLabel(issueNumber: number, labels: string[]): Promise<void> {
    try {
      await this.octokit.rest.issues.addLabels({
        owner: this.owner,
        repo: this.repo,
        issue_number: issueNumber,
        labels,
      });
    } catch (error) {
      logger.error(`Error adding labels to issue ${this.owner}/${this.repo}#${issueNumber}`, error as Error);
      throw error;
    }
  }

  /**
   * Get all issues with a specific label
   */
  async getIssuesWithLabel(label: string): Promise<any[]> {
    try {
      const { data } = await this.octokit.rest.issues.listForRepo({
        owner: this.owner,
        repo: this.repo,
        labels: label,
        state: 'open',
      });
      return data;
    } catch (error) {
      logger.error(`Error getting issues with label ${label} in ${this.owner}/${this.repo}`, error as Error);
      throw error;
    }
  }
}