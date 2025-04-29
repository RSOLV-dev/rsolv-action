import * as core from '@actions/core';
import * as github from '@actions/github';

import { loadConfig } from './config';
import { logger } from './utils/logger';
import { checkRepositorySecurity, validateApiKey } from './utils/security';
import { extractIssueContextFromEvent, isEligibleForAutomation, addIssueComment } from './github/issues';
import { IssueContext, ActionStatus, ActionResult } from './types';
import { analyzeIssue } from './ai/analyzer';
import { generateSolution } from './ai/solution';

/**
 * Main function for the RSOLV action
 */
async function run(): Promise<ActionResult> {
  try {
    // Load configuration
    const config = loadConfig();
    
    // Set logger debug mode based on config
    logger.setDebugMode(config.debug);
    
    // Log basic information
    logger.info(`Starting RSOLV Action v0.1.0`);
    logger.info(`Using AI provider: ${config.aiConfig.provider}`);
    logger.info(`Checking for issues with tag: ${config.issueTag}`);
    
    // Validate API key
    const isValidApiKey = await validateApiKey(config.apiKey);
    if (!isValidApiKey) {
      logger.error('Invalid API key provided');
      return {
        status: ActionStatus.FAILURE,
        message: 'Invalid API key provided'
      };
    }
    
    // Perform security checks
    const token = process.env.GITHUB_TOKEN || '';
    if (!token) {
      logger.error('No GitHub token provided');
      return {
        status: ActionStatus.FAILURE,
        message: 'No GitHub token provided'
      };
    }
    
    const isSecure = await checkRepositorySecurity(token, config.skipSecurityCheck);
    if (!isSecure && !config.skipSecurityCheck) {
      logger.error('Repository failed security checks');
      return {
        status: ActionStatus.FAILURE,
        message: 'Repository failed security checks'
      };
    }
    
    // Extract issue context from the event
    const issueContext = extractIssueContextFromEvent();
    if (!issueContext) {
      logger.info('No eligible issue found in the event');
      return {
        status: ActionStatus.SKIPPED,
        message: 'No eligible issue found in the event'
      };
    }
    
    // Check if the issue is eligible for automation
    if (!isEligibleForAutomation(issueContext, config.issueTag)) {
      logger.info(`Issue #${issueContext.id} is not eligible for automation`);
      return {
        status: ActionStatus.SKIPPED,
        message: `Issue #${issueContext.id} is not eligible for automation`,
        issueContext
      };
    }
    
    // Log that we found an eligible issue
    logger.info(`Found eligible issue #${issueContext.id}: ${issueContext.title}`);
    
    // Add a comment to the issue noting that we're working on it
    const { owner, name } = issueContext.repository;
    const issueNumber = parseInt(issueContext.id, 10);
    
    await addIssueComment(
      token,
      owner,
      name,
      issueNumber,
      `🤖 RSOLV has detected this issue as eligible for automated fixing. I'll analyze it and create a pull request soon!`
    );
    
    // Analyze the issue
    logger.info(`Analyzing issue #${issueContext.id}...`);
    const analysis = await analyzeIssue(issueContext, config.aiConfig);
    
    logger.info(`Issue analysis complete. Complexity: ${analysis.complexity}`);
    logger.info(`Estimated time to fix: ${analysis.estimatedTime} minutes`);
    
    // Add analysis as a comment
    await addIssueComment(
      token,
      owner,
      name,
      issueNumber,
      `### RSOLV Analysis
      
**Complexity**: ${analysis.complexity}
**Estimated time**: ${analysis.estimatedTime} minutes

**Summary**: ${analysis.summary}

**Files to modify**:
${analysis.relatedFiles?.map(file => `- ${file}`).join('\n') || 'To be determined'}

**Required changes**:
${analysis.requiredChanges?.map(change => `- ${change}`).join('\n') || 'To be determined'}

**Recommended approach**: ${analysis.recommendedApproach}

I'm now generating a solution based on this analysis...`
    );
    
    // Generate a solution
    logger.info(`Generating solution for issue #${issueContext.id}...`);
    const solution = await generateSolution(issueContext, analysis, config.aiConfig);
    
    logger.info(`Solution generated with ${solution.files.length} file changes`);
    
    // TODO: Implement PR creation (Day 4)
    // For now, we'll just add another comment
    await addIssueComment(
      token,
      owner,
      name,
      issueNumber,
      `### RSOLV Solution Ready
      
I've generated a solution for this issue:

**PR Title**: ${solution.title}

**Description**: ${solution.description}

**Files modified**:
${solution.files.map(file => `- ${file.path}`).join('\n')}

**Tests**:
${solution.tests?.map(test => `- ${test}`).join('\n') || 'No tests specified'}

PR creation will be implemented in the next version.`
    );
    
    return {
      status: ActionStatus.SUCCESS,
      message: `Successfully processed issue #${issueContext.id}`,
      issueContext
    };
    
  } catch (error) {
    const err = error as Error;
    logger.error('Error running RSOLV action', err);
    core.setFailed(err.message);
    
    return {
      status: ActionStatus.FAILURE,
      message: `Error: ${err.message}`,
      error: err
    };
  }
}

// Run the action
run()
  .then((result) => {
    // Set output
    core.setOutput('status', result.status);
    core.setOutput('message', result.message);
    
    // Set exit code based on status
    if (result.status === ActionStatus.FAILURE) {
      core.setFailed(result.message);
    } else {
      logger.info(`Action completed with status: ${result.status}`);
    }
  })
  .catch((error) => {
    logger.error('Unhandled error in action', error as Error);
    core.setFailed((error as Error).message);
  });