import * as github from '@actions/github';
import { logger } from '../utils/logger';
import { GitHubApiClient } from './api';
import { GitHubFileManager } from './files';
import { PullRequestSolution } from '../ai/types';
import { IssueContext } from '../types';

/**
 * Helper class for PR generation and management
 */
export class GitHubPRManager {
  private apiClient: GitHubApiClient;
  private fileManager: GitHubFileManager;
  private owner: string;
  private repo: string;
  private token: string;

  constructor(token: string, owner: string, repo: string) {
    this.token = token;
    this.owner = owner;
    this.repo = repo;
    this.apiClient = new GitHubApiClient(token, owner, repo);
    this.fileManager = new GitHubFileManager(token, owner, repo);
  }

  /**
   * Create a PR with the AI-generated solution
   */
  async createPullRequestFromSolution(
    issueContext: IssueContext,
    solution: PullRequestSolution,
    baseBranch: string = 'main'
  ): Promise<{ prNumber: number; prUrl: string }> {
    try {
      // Generate a branch name based on the issue number and title
      const branchName = this.generateBranchName(issueContext);
      
      // Check if branch already exists, if so, use a different name
      const branchExists = await this.fileManager.branchExists(branchName);
      const finalBranchName = branchExists
        ? `${branchName}-${new Date().getTime()}`
        : branchName;
      
      // Get the SHA of the base branch
      const baseSha = await this.fileManager.getReference(`heads/${baseBranch}`);
      
      // Create a new branch from the base branch
      await this.fileManager.createBranch(finalBranchName, baseSha);
      
      // Apply the file changes from the solution
      await this.applyFilesChangesToBranch(solution.files, finalBranchName);
      
      // Format the PR description
      const prDescription = this.formatPRDescription(issueContext, solution);
      
      // Create the pull request
      const prNumber = await this.apiClient.createPullRequest(
        solution.title,
        prDescription,
        finalBranchName,
        baseBranch
      );
      
      // Add a comment to the original issue linking to the PR
      await this.commentOnIssueWithPR(issueContext.id, prNumber);
      
      // Return PR details
      const prUrl = `https://github.com/${this.owner}/${this.repo}/pull/${prNumber}`;
      return { prNumber, prUrl };
    } catch (error) {
      logger.error('Error creating pull request from solution', error as Error);
      throw error;
    }
  }

  /**
   * Apply file changes from the AI solution to the branch
   */
  private async applyFilesChangesToBranch(
    files: Array<{ path: string; changes: string }>,
    branch: string
  ): Promise<void> {
    // Convert the solution files to the format expected by fileManager
    const fileChanges = files.map(file => ({
      path: file.path,
      content: file.changes
    }));
    
    // Apply all file changes in a single commit
    await this.fileManager.updateMultipleFiles(
      fileChanges,
      'Apply AI-generated solution',
      branch
    );
  }

  /**
   * Format the PR description
   */
  private formatPRDescription(issueContext: IssueContext, solution: PullRequestSolution): string {
    let description = `## Issue Summary\n${issueContext.title}\n\n`;
    
    // Add the AI-generated description
    description += `## Changes Made\n${solution.description}\n\n`;
    
    // List modified files
    description += '## Files Changed\n';
    solution.files.forEach(file => {
      description += `- ${file.path}\n`;
    });
    
    // Add tests if available
    if (solution.tests && solution.tests.length > 0) {
      description += '\n## Tests\n';
      solution.tests.forEach(test => {
        description += `- ${test}\n`;
      });
    }
    
    // Add issue reference
    description += `\n## Closes\nCloses #${issueContext.id}\n`;
    
    // Add expert review instructions
    description += `\n## Request Expert Review\nComment with \`/request-expert-review\` to receive expert validation`;
    
    return description;
  }

  /**
   * Generate a branch name based on the issue
   */
  private generateBranchName(issueContext: IssueContext): string {
    // Clean up the title for use in a branch name
    const cleanTitle = issueContext.title
      .toLowerCase()
      .replace(/[^\w\s-]/g, '')  // Remove special chars
      .replace(/\s+/g, '-')      // Replace spaces with hyphens
      .substring(0, 30);         // Limit length
    
    return `fix-${issueContext.id}-${cleanTitle}`;
  }

  /**
   * Add a comment to the original issue with a link to the PR
   */
  private async commentOnIssueWithPR(issueNumber: string, prNumber: number): Promise<void> {
    try {
      const octokit = github.getOctokit(this.token);
      await octokit.rest.issues.createComment({
        owner: this.owner,
        repo: this.repo,
        issue_number: parseInt(issueNumber, 10),
        body: `I've created a pull request with a potential solution: #${prNumber}`
      });
    } catch (error) {
      logger.error(`Error commenting on issue #${issueNumber}`, error as Error);
      // Don't throw here, as the PR was already created successfully
      // This is just a nice-to-have feature
    }
  }

  /**
   * Add expert review request to a PR
   */
  async requestExpertReview(
    prNumber: number, 
    expertGithubUsername?: string
  ): Promise<void> {
    try {
      const octokit = github.getOctokit(this.token);
      
      // Add the expert review label
      await octokit.rest.issues.addLabels({
        owner: this.owner,
        repo: this.repo,
        issue_number: prNumber,
        labels: ['expert-review-requested']
      });
      
      // Create a comment to request review
      await octokit.rest.issues.createComment({
        owner: this.owner,
        repo: this.repo,
        issue_number: prNumber,
        body: `@${expertGithubUsername || 'RSOLV-expert'} An expert review has been requested for this pull request.`
      });
      
      // Assign the PR to the expert if username is provided
      if (expertGithubUsername) {
        await octokit.rest.issues.addAssignees({
          owner: this.owner,
          repo: this.repo,
          issue_number: prNumber,
          assignees: [expertGithubUsername]
        });
      }
      
      // Send notification (this will be implemented in the notification system)
      this.notifyExpertReviewRequested(prNumber);
    } catch (error) {
      logger.error(`Error requesting expert review for PR #${prNumber}`, error as Error);
      throw error;
    }
  }
  
  /**
   * Placeholder for notification system
   * This will be replaced with actual implementation
   */
  private notifyExpertReviewRequested(prNumber: number): void {
    logger.info(`Expert review requested for PR #${prNumber}`);
    // This will be expanded to send emails or other notifications
  }
}