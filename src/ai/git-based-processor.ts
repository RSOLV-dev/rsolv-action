/**
 * Enhanced Git-based issue processor with fix validation
 * Implements RFC-020: Fix Validation Integration
 */
import { IssueContext, ActionConfig } from '../types/index.js';
import { logger } from '../utils/logger.js';
import { analyzeIssue } from './analyzer.js';
import { GitBasedClaudeCodeAdapter } from './adapters/claude-code-git.js';
import { createPullRequestFromGit } from '../github/pr-git.js';
import { AIConfig, IssueAnalysis } from './types.js';
import { execSync } from 'child_process';
import { TestGeneratingSecurityAnalyzer, AnalysisWithTestsResult } from './test-generating-security-analyzer.js';
import { GitBasedTestValidator, ValidationResult } from './git-based-test-validator.js';
import { VulnerabilityType } from '../security/types.js';

/**
 * Get maximum iterations based on configuration hierarchy
 */
export function getMaxIterations(
  issue: IssueContext,
  config: ActionConfig
): number {
  // Priority order (first non-null wins):
  // 1. Issue-specific override (from labels)
  const labelMatch = issue.labels.find(label => label.startsWith('fix-validation-max-'));
  if (labelMatch) {
    const maxFromLabel = parseInt(labelMatch.replace('fix-validation-max-', ''));
    if (!isNaN(maxFromLabel)) return maxFromLabel;
  }
  
  // 2. Vulnerability type specific (future enhancement)
  if (config.fixValidation?.maxIterationsByType) {
    const vulnType = detectVulnerabilityType(issue);
    const vulnTypeConfig = config.fixValidation.maxIterationsByType[vulnType];
    if (vulnTypeConfig !== undefined) return vulnTypeConfig;
  }
  
  // 3. Customer tier specific (future enhancement)
  if (config.customerTier && config.fixValidation?.maxIterationsByTier) {
    const tierConfig = config.fixValidation.maxIterationsByTier[config.customerTier];
    if (tierConfig !== undefined) return tierConfig;
  }
  
  // 4. Global configuration
  if (config.fixValidation?.maxIterations !== undefined) {
    return config.fixValidation.maxIterations;
  }
  
  // 5. Default fallback
  return 3;
}

/**
 * Detect vulnerability type from issue content
 */
function detectVulnerabilityType(issue: IssueContext): string {
  const content = `${issue.title} ${issue.body}`.toLowerCase();
  
  if (content.includes('sql injection')) return 'sql-injection';
  if (content.includes('xss') || content.includes('cross-site scripting')) return 'xss';
  if (content.includes('command injection')) return 'command-injection';
  if (content.includes('path traversal')) return 'path-traversal';
  if (content.includes('xxe') || content.includes('xml external entity')) return 'xxe';
  
  return 'unknown';
}

/**
 * Create enhanced issue context with test failure information
 */
function createEnhancedIssueWithTestFailure(
  issue: IssueContext,
  validation: ValidationResult,
  testResults: AnalysisWithTestsResult,
  iteration: number,
  maxIterations: number
): IssueContext {
  const testCode = testResults.generatedTests?.tests?.[0]?.testCode || '';
  const framework = testResults.generatedTests?.tests?.[0]?.framework || 'unknown';
  
  return {
    ...issue,
    body: `${issue.body}

## Previous Fix Attempt Failed

The previous fix did not pass the generated security tests:

### Test Results:
- Red Test (vulnerability should be fixed): ${validation.fixedCommit.redTestPassed ? '✅ PASSED' : '❌ FAILED'}
- Green Test (fix should work): ${validation.fixedCommit.greenTestPassed ? '✅ PASSED' : '❌ FAILED'}  
- Refactor Test (functionality maintained): ${validation.fixedCommit.refactorTestPassed ? '✅ PASSED' : '❌ FAILED'}

### Generated Test Code:
\`\`\`${framework}
${testCode}
\`\`\`

Please fix the vulnerability again, ensuring the fix passes all three tests.

### Why the Previous Fix Failed:
${explainTestFailure(validation)}

### Specific Requirements:
1. The vulnerability must be completely fixed (RED test must pass)
2. The fix must be correctly implemented (GREEN test must pass)  
3. Original functionality must be preserved (REFACTOR test must pass)

This is attempt ${iteration + 1} of ${maxIterations}.`
  };
}

/**
 * Explain why tests failed
 */
function explainTestFailure(validation: ValidationResult): string {
  const failures = [];
  
  if (!validation.fixedCommit.redTestPassed) {
    failures.push('- The vulnerability still exists (RED test failed)');
  }
  if (!validation.fixedCommit.greenTestPassed) {
    failures.push('- The fix was not properly applied (GREEN test failed)');
  }
  if (!validation.fixedCommit.refactorTestPassed) {
    failures.push('- The fix broke existing functionality (REFACTOR test failed)');
  }
  
  return failures.join('\n');
}

/**
 * Get the last commit before fix attempts
 */
function getLastCommitBeforeFix(): string {
  try {
    return execSync('git rev-parse HEAD', { encoding: 'utf-8' }).trim();
  } catch (error) {
    logger.error('Failed to get current commit', error);
    throw new Error('Cannot determine current commit');
  }
}

/**
 * Process result for git-based approach
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
 * Process an issue using git-based approach with fix validation
 */
export async function processIssueWithGit(
  issue: IssueContext,
  config: ActionConfig
): Promise<GitProcessingResult> {
  const startTime = Date.now();
  const beforeFixCommit = getLastCommitBeforeFix();
  
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

    // Step 2.5: Generate tests if test generation or fix validation is enabled
    let testResults: AnalysisWithTestsResult | undefined;
    if ((config.testGeneration?.enabled || config.fixValidation?.enabled !== false) && config.enableSecurityAnalysis) {
      logger.info(`Generating tests for issue #${issue.number}`);
      const testAnalyzer = new TestGeneratingSecurityAnalyzer();
      
      // Get codebase files for test generation
      const codebaseFiles = new Map<string, string>();
      // TODO: Populate with actual files based on analysis
      
      testResults = await testAnalyzer.analyzeWithTestGeneration(
        issue,
        config,
        codebaseFiles
      );
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
    
    // Step 4: Execute Claude Code with validation loop
    let solution;
    let iteration = 0;
    const maxIterations = getMaxIterations(issue, config);
    let currentIssue = issue;
    
    while (iteration < maxIterations) {
      logger.info(`Executing Claude Code to fix vulnerabilities (attempt ${iteration + 1}/${maxIterations})...`);
      const adapter = new GitBasedClaudeCodeAdapter(aiConfig, process.cwd(), credentialManager);
      
      // Pass test results and validation context to adapter
      const validationContext = iteration > 0 ? {
        current: iteration + 1,
        max: maxIterations
      } : undefined;
      
      // Convert AnalysisData to IssueAnalysis
      const issueAnalysis: IssueAnalysis = {
        summary: `${analysisData.issueType} issue analysis`,
        complexity: analysisData.estimatedComplexity === 'simple' ? 'low' : 
                   analysisData.estimatedComplexity === 'complex' ? 'high' : 'medium',
        estimatedTime: 60, // default estimate
        potentialFixes: [analysisData.suggestedApproach],
        recommendedApproach: analysisData.suggestedApproach,
        relatedFiles: analysisData.filesToModify
      };
      
      solution = await adapter.generateSolutionWithGit(
        currentIssue, 
        issueAnalysis,
        undefined, // no enhanced prompt
        testResults,
        undefined, // validation result is embedded in enhanced issue
        validationContext
      );
      
      if (!solution.success) {
        return {
          issueId: issue.id,
          success: false,
          message: solution.message,
          error: solution.error
        };
      }
      
      // Step 4.5: Validate fix if enabled and tests were generated
      if ((config.testGeneration?.validateFixes || config.fixValidation?.enabled !== false) && 
          testResults?.generatedTests?.success && 
          testResults.generatedTests.testSuite) {
        
        logger.info(`Validating fix with generated tests...`);
        const validator = new GitBasedTestValidator();
        const validation = await validator.validateFixWithTests(
          beforeFixCommit,
          solution.commitHash!,
          testResults.generatedTests.testSuite
        );
        
        if (validation.isValidFix) {
          logger.info('✅ Fix validated successfully');
          break; // Exit loop, fix is good
        }
        
        // Step 5b: Fix failed validation, prepare for retry
        iteration++;
        if (iteration >= maxIterations) {
          // Rollback all attempts
          logger.warn(`Fix validation failed after ${maxIterations} attempts, rolling back`);
          execSync(`git reset --hard ${beforeFixCommit}`, { encoding: 'utf-8' });
          
          return {
            issueId: issue.id,
            success: false,
            message: `Fix validation failed after ${maxIterations} attempts`,
            error: explainTestFailure(validation)
          };
        }
        
        logger.info(`Fix iteration ${iteration}: Previous fix failed validation`);
        
        // Reset to before the failed fix
        execSync(`git reset --hard ${beforeFixCommit}`, { encoding: 'utf-8' });
        
        // Enhance issue context with test failure information
        currentIssue = createEnhancedIssueWithTestFailure(
          issue,
          validation,
          testResults,
          iteration,
          maxIterations
        );
        
        // Loop back to Step 3
        continue;
      }
      
      // No validation needed or validation passed
      break;
    }
    
    // Step 5: Create PR from the git commit
    logger.info(`Creating PR from commit ${solution!.commitHash?.substring(0, 8)}`);
    const prResult = await createPullRequestFromGit(
      issue,
      solution!.commitHash!,
      solution!.summary!,
      config,
      solution!.diffStats
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
      filesModified: solution!.filesModified,
      diffStats: solution!.diffStats
    };
    
  } catch (error) {
    logger.error(`Error processing issue #${issue.number}`, error);
    
    // Try to rollback to clean state
    try {
      execSync(`git reset --hard ${beforeFixCommit}`, { encoding: 'utf-8' });
    } catch (resetError) {
      logger.warn('Failed to rollback after error', resetError);
    }
    
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