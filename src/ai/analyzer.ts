import { IssueContext } from '../types';
import { IssueAnalysis, AIConfig } from './types';
import { getAIClient } from './client';
import { logger } from '../utils/logger';

/**
 * Analyze an issue using AI to determine appropriate fixes
 */
export async function analyzeIssue(
  issueContext: IssueContext,
  aiConfig: AIConfig
): Promise<IssueAnalysis> {
  try {
    logger.info(`Analyzing issue: ${issueContext.id}`);
    
    // Get the AI client
    const aiClient = getAIClient(aiConfig);
    
    // Extract repository context for better analysis
    const repoContext = {
      owner: issueContext.repository.owner,
      repo: issueContext.repository.name,
      branch: issueContext.repository.branch,
      source: issueContext.source,
    };
    
    // Perform the analysis
    const analysis = await aiClient.analyzeIssue(
      issueContext.title,
      issueContext.body,
      repoContext
    );
    
    logger.info(`Analysis complete. Complexity: ${analysis.complexity}`);
    logger.info(`Estimated time: ${analysis.estimatedTime} minutes`);
    
    if (analysis.relatedFiles && analysis.relatedFiles.length > 0) {
      logger.info(`Related files: ${analysis.relatedFiles.join(', ')}`);
    }
    
    return analysis;
    
  } catch (error) {
    logger.error('Error analyzing issue', error as Error);
    throw error;
  }
}