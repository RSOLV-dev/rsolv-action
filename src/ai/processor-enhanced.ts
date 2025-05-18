/**
 * Enhanced processor with deep context gathering using Claude Code
 */
import { IssueContext, IssueProcessingResult, ActionConfig } from '../types/index.js';
import { logger } from '../utils/logger.js';
import { analyzeIssue } from './analyzer.js';
import { generateSolution } from './solution.js';
import { createPullRequest } from '../github/pr.js';
import { EnhancedClaudeCodeAdapter } from './adapters/claude-code-enhanced.js';
import { AIConfig } from './types.js';

/**
 * Processing result with enhanced context
 */
export interface EnhancedProcessingResult extends IssueProcessingResult {
  contextGatheringTime?: number;
  deepContext?: any;
  enhancedSolution?: boolean;
}

/**
 * Process an issue with enhanced context gathering
 */
export async function processIssueWithEnhancedContext(
  issue: IssueContext,
  config: ActionConfig
): Promise<EnhancedProcessingResult> {
  const aiConfig: AIConfig = {
    provider: config.aiProvider as any,
    apiKey: config.aiApiKey,
    model: config.aiModel,
    temperature: config.aiTemperature,
    maxTokens: config.aiMaxTokens,
    claudeCodeConfig: {
      ...config.claudeCodeConfig,
      enableDeepContext: true,
      enableUltraThink: true,
      contextDepth: 'ultra',
      contextGatheringTimeout: 300000, // 5 minutes
      verboseLogging: true
    }
  };
  
  const startTime = Date.now();
  
  try {
    // Step 1: Initial analysis
    logger.info(`Starting enhanced analysis for issue #${issue.number}`);
    const analysisData = await analyzeIssue(issue, config);
    
    // Step 2: Deep context gathering with Claude Code
    if (config.aiProvider === 'claude-code' && aiConfig.claudeCodeConfig?.enableDeepContext) {
      logger.info('Starting deep context gathering with Claude Code...');
      const contextStartTime = Date.now();
      
      const adapter = new EnhancedClaudeCodeAdapter(aiConfig, issue.repository.path);
      const deepContext = await adapter.gatherDeepContext(issue, {
        enableUltraThink: true,
        maxExplorationTime: aiConfig.claudeCodeConfig.contextGatheringTimeout || 300000,
        contextDepth: aiConfig.claudeCodeConfig.contextDepth || 'ultra',
        includeArchitectureAnalysis: true,
        includeTestPatterns: true,
        includeStyleGuide: true,
        includeDependencyAnalysis: true
      });
      
      const contextTime = Date.now() - contextStartTime;
      logger.info(`Deep context gathering completed in ${contextTime}ms`);
      
      // Step 3: Generate enhanced solution with deep context
      logger.info('Generating enhanced solution with deep context...');
      const solution = await adapter.generateEnhancedSolution(issue, analysisData);
      
      // Step 4: Create pull request
      logger.info(`Creating pull request for issue #${issue.number}`);
      const prResult = await createPullRequest(issue, solution, analysisData, config);
      
      const totalTime = Date.now() - startTime;
      
      return {
        issueId: issue.id,
        success: true,
        message: 'Issue processed successfully with enhanced context',
        pullRequestUrl: prResult.pullRequestUrl,
        analysisData,
        contextGatheringTime: contextTime,
        deepContext,
        enhancedSolution: true,
        processingTime: totalTime
      };
    } else {
      // Fallback to standard processing
      logger.info('Using standard processing (deep context not enabled)');
      const solutionResult = await generateSolution(issue, analysisData, config);
      
      if (!solutionResult.success) {
        return {
          issueId: issue.id,
          success: false,
          message: `Failed to generate solution: ${solutionResult.message}`,
          analysisData,
          error: solutionResult.error,
          enhancedSolution: false
        };
      }
      
      const prResult = await createPullRequest(issue, solutionResult.changes, analysisData, config);
      
      return {
        issueId: issue.id,
        success: true,
        message: 'Issue processed successfully',
        pullRequestUrl: prResult.pullRequestUrl,
        analysisData,
        enhancedSolution: false,
        processingTime: Date.now() - startTime
      };
    }
  } catch (error) {
    logger.error(`Error processing issue #${issue.number} with enhanced context`, error);
    return {
      issueId: issue.id,
      success: false,
      message: `Error processing issue: ${error instanceof Error ? error.message : String(error)}`,
      error: String(error),
      enhancedSolution: false,
      processingTime: Date.now() - startTime
    };
  }
}

/**
 * Process multiple issues with enhanced context gathering
 */
export async function processIssuesWithEnhancedContext(
  issues: IssueContext[],
  config: ActionConfig
): Promise<EnhancedProcessingResult[]> {
  logger.info(`Processing ${issues.length} issues with enhanced context gathering`);
  
  const results: EnhancedProcessingResult[] = [];
  
  // Process issues sequentially to avoid overwhelming the system
  for (const issue of issues) {
    try {
      logger.info(`Processing issue #${issue.number} with enhanced context`);
      
      const result = await processIssueWithEnhancedContext(issue, config);
      results.push(result);
      
      if (result.success) {
        logger.info(`Successfully processed issue #${issue.number} with enhanced context. PR: ${result.pullRequestUrl}`);
        if (result.contextGatheringTime) {
          logger.info(`Context gathering took ${result.contextGatheringTime}ms`);
        }
      } else {
        logger.warn(`Failed to process issue #${issue.number}: ${result.message}`);
      }
    } catch (error) {
      logger.error(`Error processing issue #${issue.number}`, error);
      results.push({
        issueId: issue.id,
        success: false,
        message: `Error processing issue: ${error instanceof Error ? error.message : String(error)}`,
        error: String(error),
        enhancedSolution: false
      });
    }
  }
  
  // Log summary statistics
  const successful = results.filter(r => r.success).length;
  const enhanced = results.filter(r => r.enhancedSolution).length;
  const avgContextTime = results
    .filter(r => r.contextGatheringTime)
    .reduce((acc, r) => acc + (r.contextGatheringTime || 0), 0) / enhanced || 0;
  
  logger.info(`Processing complete. Success: ${successful}/${issues.length}, Enhanced: ${enhanced}, Avg context time: ${avgContextTime}ms`);
  
  return results;
}