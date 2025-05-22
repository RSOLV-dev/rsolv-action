import { IssueContext, IssueProcessingResult, ActionConfig } from '../types/index.js';
import { logger } from '../utils/logger.js';
import { analyzeIssue } from './analyzer.js';
import { SecurityAwareAnalyzer } from './security-analyzer.js';
import { generateSolution } from './solution.js';
import { createPullRequest } from '../github/pr.js';

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
    // Step 1: Analyze the issue with AI (and security if enabled)
    logger.info(`Analyzing issue #${issue.number}`);
    let analysisData;
    
    if (config.enableSecurityAnalysis && shouldUseSecurityAnalysis(issue)) {
      logger.info(`Using security-aware analysis for issue #${issue.number}`);
      const securityAnalyzer = new SecurityAwareAnalyzer();
      const codebaseFiles = extractCodebaseFiles(issue);
      analysisData = await securityAnalyzer.analyzeWithSecurity(issue, config, codebaseFiles);
    } else {
      analysisData = await analyzeIssue(issue, config);
    }
    
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

/**
 * Determine if security analysis should be used for this issue
 */
function shouldUseSecurityAnalysis(issue: IssueContext): boolean {
  const title = issue.title.toLowerCase();
  const body = issue.body.toLowerCase();
  const combined = `${title} ${body}`;
  
  // Check labels first
  for (const label of issue.labels) {
    if (label.toLowerCase().includes('security')) {
      return true;
    }
  }
  
  // Check content for security-related keywords
  const securityKeywords = [
    'security', 'vulnerability', 'vulnerab', 'exploit', 'attack',
    'injection', 'xss', 'csrf', 'authentication', 'authorization',
    'sql injection', 'cross-site', 'insecure', 'hack', 'breach'
  ];
  
  return securityKeywords.some(keyword => combined.includes(keyword));
}

/**
 * Extract codebase files from issue context
 */
function extractCodebaseFiles(issue: IssueContext): Map<string, string> | undefined {
  // Try to get files from metadata first
  if (issue.metadata && issue.metadata.files instanceof Map) {
    return issue.metadata.files;
  }
  
  // If no files in metadata, return undefined to let SecurityAwareAnalyzer handle it
  return undefined;
}