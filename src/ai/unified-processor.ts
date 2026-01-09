import { IssueContext, IssueProcessingResult, ActionConfig } from '../types/index.js';
import { logger } from '../utils/logger.js';
import { extractValidationData, summarizeValidationData } from '../utils/validation-helpers.js';
import { analyzeIssue } from './analyzer.js';
import { SecurityAwareAnalyzer } from './security-analyzer.js';
import { generateSolution } from './solution.js';
import { createPullRequest } from '../github/pr.js';
import { createPullRequestFromGit } from '../github/pr-git.js';
// import { getAiClient } from './client.js';
// RFC-095: Use new unified ClaudeAgentSDKAdapter (replaces EnhancedClaudeCodeAdapter, GitBasedClaudeCodeAdapter, SinglePassClaudeCodeAdapter)
import { ClaudeAgentSDKAdapter, createClaudeAgentSDKAdapter } from './adapters/claude-agent-sdk.js';
import { processIssueWithGit } from './git-based-processor.js';
import { AIConfig, IssueAnalysis } from './types.js';
import { sanitizeErrorMessage } from '../utils/error-sanitizer.js';

/**
 * Processing options for the unified processor
 */
export interface ProcessingOptions {
  enableEnhancedContext?: boolean;
  enableSecurityAnalysis?: boolean;
  contextDepth?: 'shallow' | 'medium' | 'deep' | 'ultra';
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
    // Use git-based processing if enabled (ADR-012)
    if (config.useGitBasedEditing) {
      logger.info(`Using git-based in-place editing for issue #${issue.number}`);

      try {
        // RFC-041: Extract validation data for educational PR generation
        const validationData = extractValidationData(issue);

        if (validationData) {
          logger.info(`[UnifiedProcessor] Using validation data: ${summarizeValidationData(validationData)}`);
        }

        const gitResult = await processIssueWithGit(issue, config, validationData);
        return {
          issueId: issue.id,
          success: gitResult.success,
          message: gitResult.message,
          pullRequestUrl: gitResult.pullRequestUrl,
          error: gitResult.error,
          enhancedSolution: true
        };
      } catch (error) {
        logger.error('Git-based processing failed, falling back to standard processing', error);
        // Continue with standard processing below
      }
    }
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
    logger.info('Config aiProvider:', JSON.stringify(config.aiProvider));
    
    let solution;
    let contextGatheringTime;
    let deepContext;
    
    // Check if we should use Claude Code single-pass mode
    if (!options.enableEnhancedContext && config.aiProvider.provider === 'claude-code') {
      // Use single-pass Claude Code adapter for optimized token usage
      logger.info('Using single-pass Claude Code adapter for optimized processing');
      
      const aiConfig: AIConfig = {
        provider: config.aiProvider.provider as any,
        apiKey: config.aiProvider.providerApiKey,
        model: config.aiProvider.model,
        temperature: config.aiProvider.temperature,
        maxTokens: config.aiProvider.maxTokens,
        useVendedCredentials: config.aiProvider.useVendedCredentials,
        claudeCodeConfig: {
          ...config.claudeCodeConfig,
          enableDeepContext: false,
          contextDepth: 'shallow',
          timeout: 420000, // 7 minutes for single-pass
          verboseLogging: options.verboseLogging || false
        }
      };
      
      // Get credential manager if using vended credentials
      let credentialManager;
      if (config.aiProvider.useVendedCredentials && config.rsolvApiKey) {
        // Set RSOLV_API_KEY environment variable for AI client
        process.env.RSOLV_API_KEY = config.rsolvApiKey;
        logger.info('Set RSOLV_API_KEY environment variable for vended credentials');
        
        logger.info('Getting credential manager singleton for vended credentials');
        const { CredentialManagerSingleton } = await import('../credentials/singleton.js');
        credentialManager = await CredentialManagerSingleton.getInstance(config.rsolvApiKey);
      }
      
      const contextStart = Date.now();
      // RFC-095: Use new unified ClaudeAgentSDKAdapter
      const adapter = createClaudeAgentSDKAdapter({
        repoPath: process.cwd(),
        credentialManager,
        useVendedCredentials: aiConfig.useVendedCredentials,
        maxTurns: 5, // Extra turns for single-pass context gathering
        model: aiConfig.model,
        testFilePatterns: ['test/', 'tests/', 'spec/', '__tests__/', '.test.', '.spec.'],
        verbose: options.verboseLogging
      });
      
      // Convert AnalysisData to IssueAnalysis
      const issueAnalysis: IssueAnalysis = {
        summary: `${analysisData.issueType} issue requiring ${analysisData.estimatedComplexity} fix`,
        complexity: analysisData.estimatedComplexity === 'simple' ? 'low' : 
          analysisData.estimatedComplexity === 'complex' ? 'high' : 'medium',
        estimatedTime: 60, // default estimate
        potentialFixes: [analysisData.suggestedApproach],
        recommendedApproach: analysisData.suggestedApproach,
        relatedFiles: analysisData.filesToModify
      };
      
      // Generate solution with integrated context gathering
      // RFC-095: This returns GitSolutionResult with filesModified (not SolutionResult with changes)
      const gitSolution = await adapter.generateSolutionWithContext(issue, issueAnalysis, undefined, securityAnalysis);
      contextGatheringTime = Date.now() - contextStart;

      logger.info(`Single-pass processing completed in ${contextGatheringTime}ms`);

      // GitSolutionResult already has files modified in-place, return directly
      // (unlike standard SolutionResult which requires PR creation with changes map)
      return {
        issueId: issue.id,
        success: gitSolution.success,
        message: gitSolution.message,
        error: gitSolution.error,
        contextGatheringTime,
        enhancedSolution: true
      };
    }
    else if (options.enableEnhancedContext && config.aiProvider.provider === 'claude-code') {
      // Use enhanced context gathering (existing code)
      const aiConfig: AIConfig = {
        provider: config.aiProvider.provider as any,
        apiKey: config.aiProvider.providerApiKey,
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
        // Set RSOLV_API_KEY environment variable for AI client
        process.env.RSOLV_API_KEY = config.rsolvApiKey;
        logger.info('Set RSOLV_API_KEY environment variable for vended credentials');
        
        logger.info('Getting credential manager singleton for vended credentials');
        const { CredentialManagerSingleton } = await import('../credentials/singleton.js');
        credentialManager = await CredentialManagerSingleton.getInstance(config.rsolvApiKey);
        logger.info('Credential manager singleton retrieved successfully');
      } else {
        logger.info(`Skipping credential manager - useVended: ${config.aiProvider.useVendedCredentials}, apiKey: ${config.rsolvApiKey ? 'present' : 'missing'}`);
      }
      
      const contextStart = Date.now();
      // RFC-095: Use new unified ClaudeAgentSDKAdapter
      logger.info(`Creating ClaudeAgentSDKAdapter with credentialManager: ${!!credentialManager}`);
      const adapter = createClaudeAgentSDKAdapter({
        repoPath: process.cwd(),
        credentialManager,
        useVendedCredentials: aiConfig.useVendedCredentials,
        maxTurns: options.contextDepth === 'ultra' ? 7 : 5, // More turns for deeper context
        model: aiConfig.model,
        testFilePatterns: ['test/', 'tests/', 'spec/', '__tests__/', '.test.', '.spec.'],
        verbose: options.verboseLogging
      });
      
      // Gather deep context
      deepContext = await adapter.gatherDeepContext(issue, {
        contextDepth: options.contextDepth || 'medium',
        maxExplorationTime: options.contextGatheringTimeout || 600000, // 10 minutes default
        enableUltraThink: options.contextDepth === 'ultra',
        includeArchitectureAnalysis: true,
        includeTestPatterns: true,
        includeStyleGuide: true,
        includeDependencyAnalysis: true
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
      error: sanitizeErrorMessage(String(error))
    };
  }
}

/**
 * Legacy export for backward compatibility
 */
export { processIssue as processIssueWithEnhancedContext };