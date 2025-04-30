import { IssueContext } from '../types';
import { IssueAnalysis, PullRequestSolution, AIConfig } from './types';
import { getAIClient } from './client';
import { logger } from '../utils/logger';

/**
 * Generate a solution for an issue
 */
export async function generateSolution(
  issueContext: IssueContext,
  analysis: IssueAnalysis,
  aiConfig: AIConfig
): Promise<PullRequestSolution> {
  try {
    logger.info(`Generating solution for issue: ${issueContext.id}`);
    
    // Get the AI client
    const aiClient = getAIClient(aiConfig);
    
    // Extract repository context
    const repoContext = {
      owner: issueContext.repository.owner,
      repo: issueContext.repository.name,
      branch: issueContext.repository.branch,
      source: issueContext.source,
    };
    
    // Generate the solution
    const solution = await aiClient.generateSolution(
      issueContext.title,
      issueContext.body,
      analysis,
      repoContext
    );
    
    logger.info(`Solution generated with ${solution.files?.length || 0} file changes`);
    
    return solution;
    
  } catch (error) {
    logger.error('Error generating solution', error as Error);
    throw error;
  }
}