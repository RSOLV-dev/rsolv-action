/**
 * Claude Code SDK adapter for the RSOLV AI integration
 * This class provides a wrapper around the Claude Code TypeScript SDK
 * for enhanced context-gathering in repository analysis and solution generation.
 */
import { query, type SDKMessage } from '@anthropic-ai/claude-code';
import path from 'path';
import fs from 'fs';
import { logger } from '../../utils/logger.js';
import { IssueContext } from '../../types/index.js';
import { PullRequestSolution, AIConfig, ClaudeCodeConfig } from '../types.js';
import { IssueAnalysis } from '../types.js';

/**
 * Analytics data for Claude Code usage
 */
interface UsageData {
  startTime: number;
  endTime?: number;
  issueId: string;
  successful: boolean;
  solutionGenerationTime?: number;
  cost?: number;
  errorType?: string;
  retryCount?: number;
}

/**
 * Claude Code SDK adapter class
 */
export class ClaudeCodeAdapter {
  private repoPath: string;
  private config: AIConfig;
  private claudeConfig: ClaudeCodeConfig;
  private tempDir: string;
  private usageData: UsageData[] = [];
  private credentialManager?: any;
  
  /**
   * Create a new Claude Code SDK adapter
   */
  constructor(config: AIConfig, repoPath: string = process.cwd(), credentialManager?: any) {
    this.config = config;
    this.repoPath = repoPath;
    this.credentialManager = credentialManager;
    
    // Initialize Claude Code config with defaults
    this.claudeConfig = config.claudeCodeConfig || {};
    this.tempDir = this.claudeConfig.tempDir || path.join(process.cwd(), 'temp');
    
    // Ensure temp directory exists
    if (!fs.existsSync(this.tempDir)) {
      try {
        fs.mkdirSync(this.tempDir, { recursive: true });
      } catch (error) {
        logger.warn(`Failed to create temp directory: ${error}`);
      }
    }
    
    if (this.claudeConfig.verboseLogging) {
      logger.info('Claude Code SDK adapter initialized with config:', JSON.stringify({
        tempDir: this.tempDir,
        contextOptions: this.claudeConfig.contextOptions,
        retryOptions: this.claudeConfig.retryOptions,
        timeout: this.claudeConfig.timeout
      }, null, 2));
    }
  }

  /**
   * Check if Claude Code SDK is available
   */
  async isAvailable(): Promise<boolean> {
    try {
      // Check if the SDK is installed by trying to import it
      return true; // If we got here, the import succeeded
    } catch (error) {
      logger.error('Claude Code SDK not available', error as Error);
      return false;
    }
  }

  /**
   * Generate a solution for an issue using Claude Code SDK
   */
  async generateSolution(
    issueContext: IssueContext, 
    analysis: IssueAnalysis,
    enhancedPrompt?: string
  ): Promise<{ success: boolean; message: string; changes?: Record<string, string>; error?: string }> {
    let errorRetryCount = 0;
    const maxRetries = this.claudeConfig.retryOptions?.maxRetries ?? 2;
    const timeout = this.claudeConfig.timeout ?? 900000; // 15 minutes default
    
    // Initialize usage tracking
    const usageEntry: UsageData = {
      startTime: Date.now(),
      issueId: issueContext.id,
      successful: false
    };
    
    try {
      logger.info(`Generating solution using Claude Code SDK for issue: ${issueContext.id}`);
      
      // Check if Claude Code SDK is available
      const available = await this.isAvailable();
      if (!available) {
        logger.warn('Claude Code SDK not available');
        usageEntry.errorType = 'sdk_not_available';
        this.trackUsage(usageEntry);
        
        return {
          success: false,
          message: 'Claude Code SDK not available',
          error: 'Claude Code SDK not available. Please ensure @anthropic-ai/claude-code is installed.'
        };
      }
      
      // Construct the prompt
      const prompt = this.constructPrompt(issueContext, analysis, enhancedPrompt);
      
      // Set up API key
      let apiKey = this.config.apiKey;
      
      if (this.config.useVendedCredentials && this.credentialManager) {
        try {
          apiKey = this.credentialManager.getCredential('anthropic');
          logger.info('Using vended Anthropic credential for Claude Code SDK');
        } catch (error) {
          logger.warn('Failed to get vended credential, falling back to config API key', error);
        }
      }
      
      // Set API key in environment
      process.env.ANTHROPIC_API_KEY = apiKey;
      
      // Execute query with timeout
      const abortController = new AbortController();
      const timeoutId = setTimeout(() => {
        abortController.abort();
      }, timeout);
      
      try {
        const messages: SDKMessage[] = [];
        let solution: PullRequestSolution | null = null;
        
        for await (const message of query({
          prompt,
          abortController,
          cwd: this.repoPath,
          options: {
            maxTurns: 10, // Allow multiple turns for complex solutions
            nonInteractive: true,
          },
        })) {
          messages.push(message);
          
          // Try to extract solution from text messages
          if (message.type === 'text' && message.text) {
            const potentialSolution = this.extractSolutionFromText(message.text);
            if (potentialSolution) {
              solution = potentialSolution;
            }
          }
        }
        
        clearTimeout(timeoutId);
        
        // Track usage
        usageEntry.endTime = Date.now();
        usageEntry.solutionGenerationTime = usageEntry.endTime - usageEntry.startTime;
        
        if (solution) {
          usageEntry.successful = true;
          this.trackUsage(usageEntry);
          
          // Convert to expected format
          const changes: Record<string, string> = {};
          solution.files.forEach(file => {
            changes[file.path] = file.changes;
          });
          
          return {
            success: true,
            message: 'Solution generated with Claude Code SDK',
            changes
          };
        } else {
          logger.warn('No solution found in Claude Code SDK response');
          usageEntry.errorType = 'no_solution_found';
          this.trackUsage(usageEntry);
          
          return {
            success: false,
            message: 'No solution found in response',
            error: 'Claude Code SDK did not generate a valid solution. Please check logs for details.'
          };
        }
      } catch (queryError) {
        const errorMessage = (queryError as Error).message || String(queryError);
        if ((queryError as Error).name === 'AbortError' || errorMessage.includes('AbortError')) {
          logger.error(`Claude Code SDK execution timed out after ${timeout/1000} seconds`);
          usageEntry.errorType = 'timeout';
          
          usageEntry.endTime = Date.now();
          this.trackUsage(usageEntry);
          
          return {
            success: false,
            message: 'Claude Code SDK execution failed',
            error: `Claude Code SDK execution timed out after ${timeout/1000} seconds`
          };
        } else {
          logger.error('Claude Code SDK query failed', queryError as Error);
          usageEntry.errorType = 'query_error';
          
          usageEntry.endTime = Date.now();
          this.trackUsage(usageEntry);
          
          return {
            success: false,
            message: 'Claude Code SDK execution failed',
            error: `Claude Code SDK execution failed: ${errorMessage}`
          };
        }
      } finally {
        clearTimeout(timeoutId);
      }
    } catch (error) {
      logger.error('Unexpected error generating solution with Claude Code SDK', error as Error);
      usageEntry.errorType = 'unexpected_error';
      usageEntry.endTime = Date.now();
      this.trackUsage(usageEntry);
      
      return {
        success: false,
        message: 'Unexpected error using Claude Code SDK',
        error: error instanceof Error ? error.message : String(error)
      };
    }
  }
  
  /**
   * Track usage data for analytics
   */
  private trackUsage(data: UsageData): void {
    if (this.claudeConfig.trackUsage !== false) {
      this.usageData.push(data);
      
      // Save analytics locally
      const analyticsPath = path.join(this.tempDir, 'claude-code-analytics.json');
      try {
        if (this.claudeConfig.verboseLogging) {
          logger.debug(`Saving analytics to: ${analyticsPath}`);
        }
        let existingData: UsageData[] = [];
        if (fs.existsSync(analyticsPath)) {
          existingData = JSON.parse(fs.readFileSync(analyticsPath, 'utf-8'));
        }
        
        existingData.push(data);
        
        // Keep only last 100 entries
        if (existingData.length > 100) {
          existingData = existingData.slice(-100);
        }
        
        fs.writeFileSync(analyticsPath, JSON.stringify(existingData, null, 2));
        
        if (this.claudeConfig.verboseLogging) {
          logger.debug(`Analytics saved successfully with ${existingData.length} entries`);
        }
      } catch (error) {
        logger.warn('Error saving analytics data', error as Error);
      }
      
      if (this.claudeConfig.verboseLogging) {
        const durationSeconds = data.endTime ? (data.endTime - data.startTime) / 1000 : 0;
        logger.info(`Usage stats for issue ${data.issueId}: ` +
          `${data.successful ? 'Success' : 'Failed'} in ${durationSeconds.toFixed(1)}s`);
      }
    }
  }
  
  /**
   * Construct the prompt for Claude Code SDK
   */
  private constructPrompt(
    issueContext: IssueContext, 
    analysis: IssueAnalysis,
    enhancedPrompt?: string
  ): string {
    if (enhancedPrompt) {
      return enhancedPrompt;
    }
    
    return `You are an expert developer tasked with fixing issues in a codebase.
      
Issue Title: ${issueContext.title}
Issue Description: ${issueContext.body}

Complexity: ${analysis.complexity}
Estimated Time: ${analysis.estimatedTime} minutes

Related Files:
${analysis.relatedFiles?.join('\n') || 'To be determined by context analysis'}

Generate a solution for this issue including:
1. Code changes with file paths
2. Tests to validate the fix
3. A clear explanation of the approach

Format your response as a JSON object with the following structure:
{
  "title": "Brief title for the PR",
  "description": "Detailed description of the solution",
  "files": [
    {
      "path": "path/to/file",
      "changes": "The complete new content for the file"
    }
  ],
  "tests": [
    "Description of test 1",
    "Description of test 2"
  ]
}`;
  }
  
  /**
   * Extract solution from text response
   */
  private extractSolutionFromText(text: string): PullRequestSolution | null {
    try {
      // Try to find JSON in code blocks
      const jsonBlockMatch = text.match(/```(?:json)?\s*([\s\S]*?)\s*```/);
      if (jsonBlockMatch) {
        const solution = JSON.parse(jsonBlockMatch[1]);
        
        if (solution.title && solution.description && Array.isArray(solution.files)) {
          logger.debug('Successfully extracted solution from JSON code block');
          return {
            title: solution.title,
            description: solution.description,
            files: solution.files,
            tests: solution.tests || []
          };
        }
      }
      
      // Try to parse the entire text as JSON
      const solution = JSON.parse(text);
      if (solution.title && solution.description && Array.isArray(solution.files)) {
        logger.debug('Successfully parsed solution directly from text');
        return {
          title: solution.title,
          description: solution.description,
          files: solution.files,
          tests: solution.tests || []
        };
      }
    } catch (error) {
      // Not JSON or invalid format
      logger.debug('Could not extract JSON solution from text');
    }
    
    return null;
  }
  
  /**
   * Get usage analytics data
   */
  getUsageData(): UsageData[] {
    return this.usageData;
  }
  
  /**
   * Get analytics summary
   */
  getAnalyticsSummary(): object {
    const total = this.usageData.length;
    if (total === 0) {
      return { total: 0 };
    }
    
    const successful = this.usageData.filter(d => d.successful).length;
    const successRate = (successful / total) * 100;
    
    const avgDuration = this.usageData
      .filter(d => d.endTime !== undefined)
      .map(d => (d.endTime! - d.startTime) / 1000)
      .reduce((a, b) => a + b, 0) / total;
    
    const totalCost = this.usageData
      .filter(d => d.cost !== undefined)
      .map(d => d.cost!)
      .reduce((a, b) => a + b, 0);
    
    const errorTypes = this.usageData
      .filter(d => d.errorType)
      .reduce((acc, d) => {
        const type = d.errorType!;
        acc[type] = (acc[type] || 0) + 1;
        return acc;
      }, {} as Record<string, number>);
    
    return {
      total,
      successful,
      successRate: successRate.toFixed(1) + '%',
      avgDuration: avgDuration.toFixed(1) + 's',
      totalCost: '$' + totalCost.toFixed(4),
      errorTypes
    };
  }
}