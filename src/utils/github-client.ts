/**
 * GitHub client for creating pull requests and managing issues
 */

import { Octokit } from '@octokit/rest';

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
 * 1. Creates a branch with pattern `rsolv/fix/issue-{number}`
 * 2. Pushes commit to remote branch
 * 3. Creates actual PR using GitHub API
 * 4. Applies `rsolv:mitigated` label to issue
 * 5. Returns real PR URL and number
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

    // Create branch from the commit SHA
    console.log(`[PR] Creating branch ${branchName} from commit ${options.commitSha}`);
    await octokit.rest.git.createRef({
      owner,
      repo,
      ref: `refs/heads/${branchName}`,
      sha: options.commitSha
    });

    // Create PR
    console.log(`[PR] Creating pull request`);
    const pr = await octokit.rest.pulls.create({
      owner,
      repo,
      title: options.title,
      body: options.body,
      head: branchName,
      base: options.base
    });

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