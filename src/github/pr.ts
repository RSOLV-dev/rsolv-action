import { IssueContext, ActionConfig, AnalysisData } from '../types/index';
import { logger } from '../utils/logger';
import { getGitHubClient } from './api';
import { buildPrDescriptionPrompt } from '../ai/prompts';
import { getAiClient } from '../ai/client';

/**
 * Result of PR creation
 */
export interface PrResult {
  success: boolean;
  message: string;
  pullRequestUrl?: string;
  pullRequestNumber?: number;
  error?: string;
}

/**
 * Create a pull request with the generated solution
 */
export async function createPullRequest(
  issue: IssueContext,
  changes: Record<string, string>,
  analysisData: AnalysisData,
  config: ActionConfig
): Promise<PrResult> {
  try {
    logger.info(`Creating pull request for issue #${issue.number}`);
    
    // 1. Create a new branch for the changes
    const branchName = await createBranch(issue);
    
    // 2. Apply changes to the branch
    await applyChanges(branchName, changes, issue);
    
    // 3. Generate pull request description with AI
    const prDescription = await generatePrDescription(issue, analysisData, changes, config);
    
    // 4. Create pull request
    const prResult = await createGitHubPR(
      issue,
      branchName,
      prDescription,
      analysisData
    );
    
    logger.info(`Successfully created PR #${prResult.pullRequestNumber} for issue #${issue.number}`);
    return prResult;
  } catch (error) {
    logger.error(`Error creating pull request for issue #${issue.number}`, error);
    return {
      success: false,
      message: `Error creating pull request: ${error instanceof Error ? error.message : String(error)}`,
      error: String(error)
    };
  }
}

/**
 * Create a new branch for the changes
 */
async function createBranch(issue: IssueContext): Promise<string> {
  // Create a branch name based on the issue
  const safeIssueName = issue.title
    .toLowerCase()
    .replace(/[^\w\s-]/g, '')
    .trim()
    .replace(/[\s]+/g, '-')
    .substring(0, 30);
  
  const branchName = `rsolv/${issue.number}-${safeIssueName}`;
  
  try {
    logger.info(`Creating branch: ${branchName}`);
    
    // Get GitHub client
    const github = getGitHubClient();
    const { owner, name: repo } = issue.repository;
    
    // If in test mode, just return the branch name
    if (process.env.NODE_ENV === 'test') {
      logger.info(`Test mode: simulating branch creation for ${branchName}`);
      return branchName;
    }
    
    try {
      // Create branch using GitHub API
      await github.git.createRef({
        owner,
        repo,
        ref: `refs/heads/${branchName}`,
        sha: await getDefaultBranchSha(owner, repo, issue.repository.defaultBranch)
      });
      
      logger.info(`Branch ${branchName} created successfully`);
    } catch (error: any) {
      // Check if branch already exists (422 error)
      if (error.status === 422) {
        logger.warn(`Branch ${branchName} already exists, using existing branch`);
      } else {
        throw error;
      }
    }
    
    return branchName;
  } catch (error) {
    logger.error(`Error creating branch ${branchName}`, error);
    
    // In development mode, simulate branch creation if it fails
    if (process.env.NODE_ENV === 'development') {
      logger.warn('Development mode: continuing with simulated branch');
      return branchName;
    }
    
    throw new Error(`Failed to create branch: ${error instanceof Error ? error.message : String(error)}`);
  }
}

/**
 * Get the SHA of the default branch
 */
async function getDefaultBranchSha(owner: string, repo: string, defaultBranch: string): Promise<string> {
  try {
    const github = getGitHubClient();
    
    // Get the reference to the default branch
    const { data } = await github.git.getRef({
      owner,
      repo,
      ref: `heads/${defaultBranch}`
    });
    
    return data.object.sha;
  } catch (error) {
    logger.error(`Error getting SHA for ${defaultBranch}`, error);
    throw new Error(`Failed to get SHA for ${defaultBranch}: ${error instanceof Error ? error.message : String(error)}`);
  }
}

/**
 * Apply changes to the branch
 */
async function applyChanges(
  branchName: string,
  changes: Record<string, string>,
  issue: IssueContext
): Promise<void> {
  try {
    logger.info(`Applying ${Object.keys(changes).length} file changes to branch ${branchName}`);
    
    // Get GitHub client
    const github = getGitHubClient();
    const { owner, name: repo } = issue.repository;
    
    // If in test mode, just simulate changes
    if (process.env.NODE_ENV === 'test') {
      logger.info('Test mode: simulating file changes');
      await new Promise(resolve => setTimeout(resolve, 100));
      return;
    }
    
    // Process files in batches to avoid rate limiting
    const batchSize = 5;
    const filePaths = Object.keys(changes);
    
    for (let i = 0; i < filePaths.length; i += batchSize) {
      const batch = filePaths.slice(i, i + batchSize);
      
      // Update files in parallel
      await Promise.all(batch.map(async (filePath) => {
        try {
          // Get current file content to check if it exists
          let sha: string | undefined;
          try {
            const response = await github.repos.getContent({
              owner,
              repo,
              path: filePath,
              ref: branchName
            });
            
            // If response is not an array, it's a file and we need its SHA
            if (!Array.isArray(response.data)) {
              sha = response.data.sha;
            }
          } catch (error: any) {
            // 404 error means file doesn't exist yet, which is fine
            if (error.status !== 404) {
              throw error;
            }
          }
          
          // Create or update the file
          await github.repos.createOrUpdateFileContents({
            owner,
            repo,
            path: filePath,
            message: `Update ${filePath} for issue #${issue.number}`,
            content: Buffer.from(changes[filePath]).toString('base64'),
            branch: branchName,
            sha
          });
          
          logger.debug(`Updated file: ${filePath}`);
        } catch (error) {
          logger.error(`Error updating file ${filePath}`, error);
          throw error;
        }
      }));
      
      // Small delay between batches to avoid rate limiting
      if (i + batchSize < filePaths.length) {
        await new Promise(resolve => setTimeout(resolve, 200));
      }
    }
    
    logger.info('All changes applied successfully');
  } catch (error) {
    logger.error('Error applying changes to branch', error);
    
    // In development mode, continue even if changes fail
    if (process.env.NODE_ENV === 'development') {
      logger.warn('Development mode: continuing despite errors in applying changes');
      return;
    }
    
    throw new Error(`Failed to apply changes: ${error instanceof Error ? error.message : String(error)}`);
  }
}

/**
 * Generate pull request description with AI
 */
async function generatePrDescription(
  issue: IssueContext,
  analysisData: AnalysisData,
  changes: Record<string, string>,
  config: ActionConfig
): Promise<string> {
  try {
    logger.info(`Generating PR description for issue #${issue.number}`);
    
    // Get AI client
    const aiClient = getAiClient(config.aiProvider);
    
    // Build PR description prompt
    const prompt = buildPrDescriptionPrompt(issue, analysisData, changes);
    
    // Generate PR description
    const response = await aiClient.complete(prompt, {
      temperature: 0.3,
      maxTokens: 1000,
      model: config.aiProvider.model
    });
    
    // Parse PR description from response
    // For now, just use the raw response
    const prDescription = `${response}\n\nThis PR was automatically generated by [RSOLV](https://rsolv.dev) to address issue #${issue.number}.`;
    
    return prDescription;
  } catch (error) {
    logger.error('Error generating PR description', error);
    
    // Fallback to a basic PR description
    return `Fix for issue #${issue.number}\n\nThis PR addresses the issue "${issue.title}" by making changes to ${Object.keys(changes).length} files.\n\nThis PR was automatically generated by [RSOLV](https://rsolv.dev).`;
  }
}

/**
 * Create a pull request on GitHub
 */
async function createGitHubPR(
  issue: IssueContext,
  branchName: string,
  prDescription: string,
  analysisData: AnalysisData
): Promise<PrResult> {
  try {
    // Generate PR title based on issue
    const prTitle = `[RSOLV] ${issue.title} (fixes #${issue.number})`;
    
    logger.info(`Creating PR: ${prTitle}`);
    
    // Get GitHub client
    const github = getGitHubClient();
    const { owner, name: repo } = issue.repository;
    
    // If in test mode, simulate PR creation
    if (process.env.NODE_ENV === 'test') {
      logger.info('Test mode: simulating PR creation');
      
      // Mock PR number and URL
      const prNumber = Math.floor(Math.random() * 1000) + 1;
      const prUrl = `https://github.com/${issue.repository.fullName}/pull/${prNumber}`;
      
      return {
        success: true,
        message: 'Pull request created successfully (test mode)',
        pullRequestUrl: prUrl,
        pullRequestNumber: prNumber
      };
    }
    
    // Create the pull request using GitHub API
    const { data } = await github.pulls.create({
      owner,
      repo,
      title: prTitle,
      body: prDescription,
      head: branchName,
      base: issue.repository.defaultBranch,
      draft: false, // Set to true if you want to create draft PRs
    });
    
    logger.info(`Pull request created: ${data.html_url}`);
    
    // Add labels to the PR based on the issue type
    await github.issues.addLabels({
      owner,
      repo,
      issue_number: data.number,
      labels: ['rsolv:automated', `type:${analysisData.issueType}`]
    });
    
    // Add a comment to the original issue linking to the PR
    await github.issues.createComment({
      owner,
      repo,
      issue_number: issue.number,
      body: `I've created a pull request to address this issue: ${data.html_url}\n\nThis was automatically generated by [RSOLV](https://rsolv.dev).`
    });
    
    return {
      success: true,
      message: 'Pull request created successfully',
      pullRequestUrl: data.html_url,
      pullRequestNumber: data.number
    };
  } catch (error) {
    logger.error('Error creating GitHub PR', error);
    
    // In development mode, return a mock PR
    if (process.env.NODE_ENV === 'development') {
      logger.warn('Development mode: returning mock PR due to error');
      
      // Mock PR number and URL
      const prNumber = Math.floor(Math.random() * 1000) + 1;
      const prUrl = `https://github.com/${issue.repository.fullName}/pull/${prNumber}`;
      
      return {
        success: true,
        message: 'Pull request created successfully (dev fallback)',
        pullRequestUrl: prUrl,
        pullRequestNumber: prNumber
      };
    }
    
    throw new Error(`Failed to create GitHub PR: ${error instanceof Error ? error.message : String(error)}`);
  }
}