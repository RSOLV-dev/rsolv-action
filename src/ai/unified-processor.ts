import { IssueContext, IssueProcessingResult, ActionConfig } from '../types/index.js';
import { logger } from '../utils/logger.js';
import { analyzeIssue } from './analyzer.js';
import { SecurityAwareAnalyzer } from './security-analyzer.js';
import { generateSolution } from './solution.js';
import { createPullRequest } from '../github/pr.js';
// import { getAiClient } from './client.js';
import { EnhancedClaudeCodeAdapter } from './adapters/claude-code-enhanced.js';
import { AIConfig } from './types.js';
import { sanitizeErrorMessage } from '../utils/error-sanitizer.js';

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
        message: sanitizeErrorMessage(`Error processing issue: ${error instanceof Error ? error.message : String(error)}`),
        error: sanitizeErrorMessage(String(error))
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
      analysisData = result;  // Fixed: analyzeWithSecurity returns the analysis data directly
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
    logger.info(`Config aiProvider:`, JSON.stringify(config.aiProvider));
    
    let solution;
    let contextGatheringTime;
    let deepContext;
    
    if (options.enableEnhancedContext && config.aiProvider.provider === 'claude-code') {
      // Use enhanced context gathering
      const aiConfig: AIConfig = {
        provider: config.aiProvider.provider as any,
        apiKey: config.aiProvider.apiKey,
        model: config.aiProvider.model,
        temperature: config.aiProvider.temperature,
        maxTokens: config.aiProvider.maxTokens,
        useVendedCredentials: config.aiProvider.useVendedCredentials,
        claudeCodeConfig: {
          ...config.claudeCodeConfig,
          enableDeepContext: true,
          enableUltraThink: options.contextDepth === 'ultra',
          contextDepth: options.contextDepth || 'deep',
          contextGatheringTimeout: options.contextGatheringTimeout || 600000, // 10 minutes for deep context gathering
          verboseLogging: options.verboseLogging || false
        }
      };
      
      // Get credential manager if using vended credentials
      let credentialManager;
      logger.info(`Enhanced context setup - useVendedCredentials: ${config.aiProvider.useVendedCredentials}, rsolvApiKey: ${config.rsolvApiKey ? 'present' : 'missing'}`);
      
      if (config.aiProvider.useVendedCredentials && config.rsolvApiKey) {
        logger.info('Creating credential manager for vended credentials');
        const { RSOLVCredentialManager } = await import('../credentials/manager.js');
        credentialManager = new RSOLVCredentialManager();
        await credentialManager.initialize(config.rsolvApiKey);
        logger.info('Credential manager initialized successfully');
      } else {
        logger.info(`Skipping credential manager - useVended: ${config.aiProvider.useVendedCredentials}, apiKey: ${config.rsolvApiKey ? 'present' : 'missing'}`);
      }
      
      const contextStart = Date.now();
      logger.info(`Creating EnhancedClaudeCodeAdapter with credentialManager: ${!!credentialManager}`);
      const adapter = new EnhancedClaudeCodeAdapter(aiConfig, process.cwd(), credentialManager);
      
      // Gather deep context
      deepContext = await adapter.gatherDeepContext(issue, {
        contextDepth: options.contextDepth || 'standard',
        maxExplorationTime: options.contextGatheringTimeout || 600000, // 10 minutes default
        includeTests: true,
        includeStyleGuide: true
      });
      contextGatheringTime = Date.now() - contextStart;
      
      // Generate solution with enhanced context
      solution = await generateSolution(issue, analysisData, config, injectedDeps?.aiClient, injectedDeps?.fileGetter, securityAnalysis);
    } else {
      // Standard solution generation
      solution = await generateSolution(issue, analysisData, config, injectedDeps?.aiClient, injectedDeps?.fileGetter, securityAnalysis);
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
    const prResult = await createPullRequest(issue, solution.changes!, analysisData, config, securityAnalysis, solution.explanations);
    
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
      message: sanitizeErrorMessage(`Error processing issue: ${error instanceof Error ? error.message : String(error)}`),
      error: sanitizeErrorMessage(String(error)),
      processingTime: Date.now() - startTime
    };
  }
}

/**
 * Legacy export for backward compatibility
 */
export { processIssue as processIssueWithEnhancedContext };