import { IssueContext, IssueProcessingResult, ActionConfig, AnalysisData } from '../types/index';
import { logger } from '../utils/logger';
import { analyzeIssue } from './analyzer';
import { generateSolution } from './solution';
import { createPullRequest } from '../github/pr';

/**
 * Process multiple issues with AI analysis and solution generation
 */
export async function processIssues(
  issues: IssueContext[],
  config: ActionConfig
): Promise<IssueProcessingResult[]> {
  logger.info(`Processing ${issues.length} issues with AI`);
  
  const results: IssueProcessingResult[] = [];
  
  for (const issue of issues) {
    try {
      logger.info(`Processing issue #${issue.number}: ${issue.title}`);
      
      const result = await processIssue(issue, config);
      results.push(result);
      
      if (result.success) {
        logger.info(`Successfully processed issue #${issue.number}. PR: ${result.pullRequestUrl}`);
      } else {
        logger.warn(`Failed to process issue #${issue.number}: ${result.message}`);
      }
    } catch (error) {
      logger.error(`Error processing issue #${issue.number}`, error);
      results.push({
        issueId: issue.id,
        success: false,
        message: `Error processing issue: ${error instanceof Error ? error.message : String(error)}`,
        error: String(error)
      });
    }
  }
  
  return results;
}

/**
 * Process a single issue with AI analysis and solution generation
 */
async function processIssue(
  issue: IssueContext,
  config: ActionConfig
): Promise<IssueProcessingResult> {
  try {
    // Step 1: Analyze the issue with AI
    logger.info(`Analyzing issue #${issue.number}`);
    const analysisData = await analyzeIssue(issue, config);
    
    // Step 2: Generate solution based on analysis
    logger.info(`Generating solution for issue #${issue.number}`);
    const solutionResult = await generateSolution(issue, analysisData, config);
    
    if (!solutionResult.success) {
      return {
        issueId: issue.id,
        success: false,
        message: `Failed to generate solution: ${solutionResult.message}`,
        analysisData,
        error: solutionResult.error
      };
    }
    
    // Step 3: Create a pull request with the changes
    logger.info(`Creating pull request for issue #${issue.number}`);
    const prResult = await createPullRequest(issue, solutionResult.changes, analysisData, config);
    
    return {
      issueId: issue.id,
      success: true,
      message: 'Issue processed successfully',
      pullRequestUrl: prResult.pullRequestUrl,
      analysisData
    };
  } catch (error) {
    logger.error(`Error processing issue #${issue.number}`, error);
    return {
      issueId: issue.id,
      success: false,
      message: `Error processing issue: ${error instanceof Error ? error.message : String(error)}`,
      error: String(error)
    };
  }
}