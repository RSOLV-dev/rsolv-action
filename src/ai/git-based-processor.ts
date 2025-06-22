/**
 * Git-based issue processor that uses Claude Code's direct file editing
 * capabilities to create clean, minimal PRs
 */
import { IssueContext, ActionConfig } from '../types/index.js';
import { logger } from '../utils/logger.js';
import { analyzeIssue } from './analyzer.js';
import { GitBasedClaudeCodeAdapter } from './adapters/claude-code-git.js';
import { createPullRequestFromGit } from '../github/pr-git.js';
import { AIConfig } from './types.js';
import { execSync } from 'child_process';

/**
 * Processing result for git-based approach
 */
export interface GitProcessingResult {
  issueId: string;
  success: boolean;
  message: string;
  pullRequestUrl?: string;
  pullRequestNumber?: number;
  filesModified?: string[];
  diffStats?: {
    insertions: number;
    deletions: number;
    filesChanged: number;
  };
  error?: string;
}

/**
 * Process an issue using git-based approach with direct file editing
 */
export async function processIssueWithGit(
  issue: IssueContext,
  config: ActionConfig
): Promise<GitProcessingResult> {
  const startTime = Date.now();
  
  try {
    logger.info(`Processing issue #${issue.number} with git-based approach`);
    
    // Step 1: Ensure clean git state
    const gitStatus = checkGitStatus();
    if (!gitStatus.clean) {
      return {
        issueId: issue.id,
        success: false,
        message: 'Repository has uncommitted changes',
        error: `Uncommitted changes in: ${gitStatus.modifiedFiles.join(', ')}`
      };
    }
    
    // Step 2: Analyze the issue
    logger.info(`Analyzing issue #${issue.number}`);
    const analysisData = await analyzeIssue(issue, config);
    
    if (!analysisData || !analysisData.canBeFixed) {
      return {
        issueId: issue.id,
        success: false,
        message: 'Issue cannot be automatically fixed based on analysis'
      };
    }
    
    // Step 3: Set up Claude Code adapter
    const aiConfig: AIConfig = {
      provider: 'anthropic',
      apiKey: config.aiProvider.apiKey,
      model: config.aiProvider.model,
      temperature: 0.1, // Low temperature for consistent fixes
      maxTokens: config.aiProvider.maxTokens,
      useVendedCredentials: config.aiProvider.useVendedCredentials,
      claudeCodeConfig: {
        verboseLogging: true,
        timeout: 600000, // 10 minutes for exploration and editing
        executablePath: process.env.CLAUDE_CODE_PATH
      }
    };
    
    // Get credential manager if using vended credentials
    let credentialManager;
    if (config.aiProvider.useVendedCredentials && config.rsolvApiKey) {
      const { RSOLVCredentialManager } = await import('../credentials/manager.js');
      credentialManager = new RSOLVCredentialManager();
      await credentialManager.initialize(config.rsolvApiKey);
      logger.info('Using vended credentials for Claude Code');
    }
    
    // Step 4: Execute Claude Code to make direct file edits
    logger.info('Executing Claude Code to fix vulnerabilities...');
    const adapter = new GitBasedClaudeCodeAdapter(aiConfig, process.cwd(), credentialManager);
    const solution = await adapter.generateSolutionWithGit(issue, analysisData);
    
    if (!solution.success) {
      return {
        issueId: issue.id,
        success: false,
        message: solution.message,
        error: solution.error
      };
    }
    
    // Step 5: Create PR from the git commit
    logger.info(`Creating PR from commit ${solution.commitHash?.substring(0, 8)}`);
    const prResult = await createPullRequestFromGit(
      issue,
      solution.commitHash!,
      solution.summary!,
      config,
      solution.diffStats
    );
    
    if (!prResult.success) {
      // Try to undo the commit if PR creation failed
      try {
        execSync('git reset --hard HEAD~1', { encoding: 'utf-8' });
        logger.info('Rolled back commit after PR creation failure');
      } catch (resetError) {
        logger.warn('Failed to rollback commit', resetError);
      }
      
      return {
        issueId: issue.id,
        success: false,
        message: prResult.message,
        error: prResult.error
      };
    }
    
    const processingTime = Date.now() - startTime;
    logger.info(`Successfully processed issue #${issue.number} in ${processingTime}ms`);
    
    return {
      issueId: issue.id,
      success: true,
      message: `Created PR #${prResult.pullRequestNumber}`,
      pullRequestUrl: prResult.pullRequestUrl,
      pullRequestNumber: prResult.pullRequestNumber,
      filesModified: solution.filesModified,
      diffStats: solution.diffStats
    };
    
  } catch (error) {
    logger.error(`Error processing issue #${issue.number}`, error);
    return {
      issueId: issue.id,
      success: false,
      message: 'Error processing issue',
      error: error instanceof Error ? error.message : String(error)
    };
  }
}

/**
 * Check git repository status
 */
function checkGitStatus(): { clean: boolean; modifiedFiles: string[] } {
  try {
    const status = execSync('git status --porcelain', {
      encoding: 'utf-8'
    }).trim();
    
    if (!status) {
      return { clean: true, modifiedFiles: [] };
    }
    
    const modifiedFiles = status
      .split('\n')
      .map(line => line.substring(3).trim())
      .filter(file => file.length > 0);
    
    return { clean: false, modifiedFiles };
    
  } catch (error) {
    logger.error('Failed to check git status', error);
    return { clean: false, modifiedFiles: ['unknown'] };
  }
}

/**
 * Process multiple issues using git-based approach
 */
export async function processIssuesWithGit(
  issues: IssueContext[],
  config: ActionConfig
): Promise<GitProcessingResult[]> {
  logger.info(`Processing ${issues.length} issues with git-based approach`);
  
  const results: GitProcessingResult[] = [];
  
  // Process issues sequentially to avoid git conflicts
  for (const issue of issues) {
    try {
      const result = await processIssueWithGit(issue, config);
      results.push(result);
      
      if (result.success) {
        logger.info(`✅ Issue #${issue.number}: PR ${result.pullRequestUrl}`);
      } else {
        logger.warn(`❌ Issue #${issue.number}: ${result.message}`);
      }
      
    } catch (error) {
      logger.error(`Failed to process issue #${issue.number}`, error);
      results.push({
        issueId: issue.id,
        success: false,
        message: 'Processing failed',
        error: error instanceof Error ? error.message : String(error)
      });
    }
  }
  
  // Summary
  const successful = results.filter(r => r.success).length;
  logger.info(`Processed ${successful}/${issues.length} issues successfully`);
  
  return results;
}