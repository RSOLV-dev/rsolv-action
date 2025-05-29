import { IssueContext, IssueProcessingResult, ActionConfig } from '../types/index.js';
import { logger } from '../utils/logger.js';
import { analyzeIssue } from './analyzer.js';
import { SecurityAwareAnalyzer } from './security-analyzer.js';
import { generateSolution } from './solution.js';
import { createPullRequest } from '../github/pr.js';
// import { getAiClient } from './client.js';
import { EnhancedClaudeCodeAdapter } from './adapters/claude-code-enhanced.js';
import { AIConfig } from './types.js';

/**
 * Processing options for the unified processor
 */
export interface ProcessingOptions {
  enableEnhancedContext?: boolean;
  enableSecurityAnalysis?: boolean;
  contextDepth?: 'basic' | 'standard' | 'deep' | 'ultra';
  contextGatheringTimeout?: number;
  verboseLogging?: boolean;
}

/**
 * Enhanced processing result with optional metadata
 */
export interface UnifiedProcessingResult extends IssueProcessingResult {
  contextGatheringTime?: number;
  deepContext?: any;
  enhancedSolution?: boolean;
  securityAnalysis?: any;
}

/**
 * Process multiple issues with configurable AI analysis and solution generation
 */
export async function processIssues(
  issues: IssueContext[],
  config: ActionConfig,
  options: ProcessingOptions = {},
  injectedDeps?: {
    aiClient?: any;
    fileGetter?: any;
    prCreator?: any;
    logger?: any;
  }
): Promise<UnifiedProcessingResult[]> {
  logger.info(`Processing ${issues.length} issues with AI`);
  
  const results: UnifiedProcessingResult[] = [];
  
  for (const issue of issues) {
    try {
      logger.info(`Processing issue #${issue.number}: ${issue.title}`);
      
      const result = await processIssue(issue, config, options, injectedDeps);
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
 * Process a single issue with configurable AI analysis and solution generation
 */
async function processIssue(
  issue: IssueContext,
  config: ActionConfig,
  options: ProcessingOptions = {},
  injectedDeps?: {
    aiClient?: any;
    fileGetter?: any;
    prCreator?: any;
    logger?: any;
  }
): Promise<UnifiedProcessingResult> {
  const startTime = Date.now();
  
  try {
    // Step 1: Analysis (with optional security analysis)
    logger.info(`Analyzing issue #${issue.number}`);
    
    let analysisData;
    let securityAnalysis;
    
    if (options.enableSecurityAnalysis && config.enableSecurityAnalysis !== false) {
      logger.info(`Using security-aware analysis for issue #${issue.number}`);
      const analyzer = new SecurityAwareAnalyzer();
      const result = await analyzer.analyzeWithSecurity(issue, config);
      analysisData = result.analysis;
      securityAnalysis = result.securityAnalysis;
    } else {
      analysisData = await analyzeIssue(issue, config, injectedDeps?.aiClient);
    }
    
    if (!analysisData || !analysisData.canBeFixed) {
      return {
        issueId: issue.id,
        success: false,
        message: 'Issue cannot be automatically fixed based on analysis'
      };
    }
    
    // Step 2: Solution generation (with optional enhanced context)
    logger.info(`Generating solution for issue #${issue.number}`);
    
    let solution;
    let contextGatheringTime;
    let deepContext;
    
    if (options.enableEnhancedContext && config.aiProvider === 'claude-code') {
      // Use enhanced context gathering
      const aiConfig: AIConfig = {
        provider: config.aiProvider as any,
        apiKey: config.aiApiKey,
        model: config.aiModel,
        temperature: config.aiTemperature,
        maxTokens: config.aiMaxTokens,
        claudeCodeConfig: {
          ...config.claudeCodeConfig,
          enableDeepContext: true,
          enableUltraThink: options.contextDepth === 'ultra',
          contextDepth: options.contextDepth || 'deep',
          contextGatheringTimeout: options.contextGatheringTimeout || 300000,
          verboseLogging: options.verboseLogging || false
        }
      };
      
      const contextStart = Date.now();
      const adapter = new EnhancedClaudeCodeAdapter(aiConfig);
      
      // Gather deep context
      deepContext = await adapter.gatherDeepContext(issue, analysisData);
      contextGatheringTime = Date.now() - contextStart;
      
      // Generate solution with enhanced context
      solution = await generateSolution(issue, analysisData, config, injectedDeps?.aiClient, injectedDeps?.fileGetter);
    } else {
      // Standard solution generation
      solution = await generateSolution(issue, analysisData, config, injectedDeps?.aiClient, injectedDeps?.fileGetter);
    }
    
    if (!solution || !solution.success || !solution.changes || Object.keys(solution.changes).length === 0) {
      return {
        issueId: issue.id,
        success: false,
        message: solution?.message || 'No solution generated'
      };
    }
    
    // Step 3: Create pull request
    logger.info(`Creating pull request for issue #${issue.number}`);
    const prResult = await createPullRequest(issue, solution.changes!, analysisData, config);
    
    // const _processingTime = Date.now() - startTime;
    
    return {
      issueId: issue.id,
      success: prResult.success,
      pullRequestUrl: prResult.pullRequestUrl,
      message: prResult.message,
      analysisData,
      contextGatheringTime,
      deepContext: options.verboseLogging ? deepContext : undefined,
      enhancedSolution: options.enableEnhancedContext,
      securityAnalysis
    };
  } catch (error) {
    logger.error(`Error processing issue #${issue.number}`, error);
    return {
      issueId: issue.id,
      success: false,
      message: `Error processing issue: ${error instanceof Error ? error.message : String(error)}`,
      error: String(error),
      processingTime: Date.now() - startTime
    };
  }
}

/**
 * Legacy export for backward compatibility
 */
export { processIssue as processIssueWithEnhancedContext };