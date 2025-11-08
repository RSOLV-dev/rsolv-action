/**
 * GitHub client for creating pull requests and managing issues
 */

import { Octokit } from '@octokit/rest';
import {
  getCurrentBranch,
  createBranchFromCommit,
  pushBranch,
  safeCheckout
} from './git-operations.js';

export interface PullRequestOptions {
  repository: string; // format: "owner/repo"
  commitSha: string; // SHA of the commit to create the branch from
  issueNumber: number; // Issue number being fixed
  title: string; // PR title
  body: string; // PR body/description
  base: string; // Base branch (e.g., "main" or "master")
}

export interface PullRequestResult {
  number: number;
  url: string;
  title: string;
}

/**
 * Create a pull request with actual GitHub API integration
 *
 * This function:
 * 1. Creates a local branch from the commit SHA
 * 2. Pushes the branch to GitHub (the commit must exist locally)
 * 3. Creates a pull request using GitHub API
 * 4. Applies `rsolv:mitigated` label to the issue
 * 5. Returns PR URL and number
 *
 * Note: The commit SHA must reference a commit that exists in the local Git repository.
 * This is typically created by Claude Code CLI during the mitigation phase.
 */
export async function createPullRequest(options: PullRequestOptions): Promise<PullRequestResult> {
  // Validate that GITHUB_TOKEN is available
  if (!process.env.GITHUB_TOKEN) {
    throw new Error('PR creation failed: GITHUB_TOKEN environment variable is not set');
  }

  const octokit = new Octokit({ auth: process.env.GITHUB_TOKEN });

  try {
    // Extract repo info
    const [owner, repo] = options.repository.split('/');
    const branchName = `rsolv/fix/issue-${options.issueNumber}`;

    // Push the commit to remote by creating and pushing a branch
    // The commit was created locally by Claude Code and needs to be pushed to GitHub
    console.log(`[PR] Creating and pushing branch ${branchName} from commit ${options.commitSha.substring(0, 8)}`);

    // Save current branch to return to it later (more reliable than 'git checkout -')
    const originalBranch = getCurrentBranch();
    if (!originalBranch) {
      console.log('[PR] Warning: Could not determine current branch, will not return to original branch');
    }

    try {
      createBranchFromCommit(branchName, options.commitSha);
      pushBranch(branchName);

      // Return to original branch if we saved it and it's different from the branch we just created
      if (originalBranch && originalBranch !== branchName) {
        safeCheckout(originalBranch, branchName);
      }

      console.log(`[PR] Successfully pushed branch ${branchName}`);
    } catch (pushError) {
      // Clean up: try to return to original branch
      if (originalBranch && originalBranch !== branchName) {
        safeCheckout(originalBranch, branchName);
      }

      const errorMessage = pushError instanceof Error ? pushError.message : String(pushError);
      console.error(`[PR] Failed to push branch: ${errorMessage}`);
      throw new Error(`Failed to push commit to remote: ${errorMessage}`);
    }

    // Create PR
    console.log('[PR] Creating pull request');
    let pr;
    try {
      pr = await octokit.rest.pulls.create({
        owner,
        repo,
        title: options.title,
        body: options.body,
        head: branchName,
        base: options.base
      });
    } catch (prError: any) {
      // Check if PR already exists
      if (prError.status === 422 && prError.message?.includes('pull request already exists')) {
        console.log('[PR] Pull request already exists, fetching existing PR');

        // Find the existing PR
        const { data: existingPrs } = await octokit.rest.pulls.list({
          owner,
          repo,
          head: `${owner}:${branchName}`,
          state: 'open'
        });

        if (existingPrs.length > 0) {
          pr = { data: existingPrs[0] };
          console.log(`[PR] Using existing PR #${pr.data.number}`);
        } else {
          throw new Error('Pull request already exists but could not be found');
        }
      } else {
        throw prError;
      }
    }

    // Apply rsolv:mitigated label to issue
    console.log(`[PR] Applying rsolv:mitigated label to issue #${options.issueNumber}`);
    await octokit.rest.issues.addLabels({
      owner,
      repo,
      issue_number: options.issueNumber,
      labels: ['rsolv:mitigated']
    });

    console.log(`[PR] Created PR #${pr.data.number}: ${pr.data.html_url}`);

    return {
      number: pr.data.number,
      url: pr.data.html_url,
      title: pr.data.title
    };
  } catch (error) {
    console.error('[PR] Failed to create pull request:', error);
    throw new Error(`PR creation failed: ${error instanceof Error ? error.message : String(error)}`);
  }
}

export default { createPullRequest };