/**
 * Claude Code CLI adapter with retry mechanism and development mode support
 * Implements RFC-048: Claude Code Max Development Mode and Retry Mechanism
 */

import { ClaudeCodeCLIAdapter } from './claude-code-cli.js';
import type { CLISolutionResult } from './claude-code-cli.js';
import { IssueContext } from '../../types/index.js';
import { AIConfig } from '../types.js';
import { IssueAnalysis } from '../types.js';
import { logger } from '../../utils/logger.js';

export interface RetryConfig {
  maxAttempts: number;
  initialDelayMs: number;
  maxDelayMs: number;
  backoffMultiplier: number;
  retryableErrors: string[];
}

/**
 * Check if running in development mode
 */
export function isDevelopmentMode(): boolean {
  return process.env.RSOLV_DEV_MODE === 'true' || 
         process.env.USE_CLAUDE_CODE_MAX === 'true';
}

/**
 * Enhanced Claude Code CLI adapter with retry mechanism
 */
export class RetryableClaudeCodeCLI extends ClaudeCodeCLIAdapter {
  private defaultRetryConfig: RetryConfig = {
    maxAttempts: parseInt(process.env.RSOLV_RETRY_MAX_ATTEMPTS || '3'),
    initialDelayMs: parseInt(process.env.RSOLV_RETRY_INITIAL_DELAY_MS || '1000'),
    maxDelayMs: parseInt(process.env.RSOLV_RETRY_MAX_DELAY_MS || '30000'),
    backoffMultiplier: parseFloat(process.env.RSOLV_RETRY_BACKOFF_MULTIPLIER || '2'),
    retryableErrors: [
      'rate_limit',
      'overloaded',
      'timeout',
      'network',
      'ECONNRESET',
      'ETIMEDOUT',
      'ENOTFOUND',
      'EHOSTUNREACH',
      'Claude CLI exited with code'
    ]
  };

  /**
   * Generate solution with retry mechanism and dev mode support
   */
  async generateSolution(
    issueContext: IssueContext,
    analysis: IssueAnalysis,
    enhancedPrompt?: string
  ): Promise<CLISolutionResult> {
    try {
      logger.info('Using RetryableClaudeCodeCLI for file editing...');
      
      // Check for development mode
      const isDev = isDevelopmentMode();
      
      // Get appropriate API key
      const apiKey = this.getApiKey(isDev);
      
      if (!apiKey) {
        return {
          success: false,
          message: 'No API key available',
          error: isDev 
            ? 'Claude Code Max API key not configured for development mode. Set CLAUDE_CODE_MAX_API_KEY or ANTHROPIC_API_KEY'
            : 'No API key or vended credentials available'
        };
      }
      
      // CRITICAL: Set the API key in process.env for Claude CLI to use
      // This ensures the CLI can authenticate properly
      process.env.ANTHROPIC_API_KEY = apiKey;
      
      logger.info(`Using ${isDev ? 'Claude Code Max (dev)' : 'production'} API`);
      
      // Create prompt
      const prompt = enhancedPrompt || this.constructPrompt(issueContext, analysis);
      
      logger.info(`Working directory: ${this.repoPath}`);
      logger.info(`Prompt length: ${prompt.length} characters`);
      
      // Use retry mechanism
      const result = await this.executeWithRetry(prompt, {
        cwd: this.repoPath,
        env: {
          ...process.env,
          ANTHROPIC_API_KEY: apiKey
        }
      });
      
      if (!result.success) {
        return result;
      }
      
      // Check for file modifications using git
      const modifiedFiles = this.getModifiedFiles();
      
      if (modifiedFiles.length === 0) {
        return {
          success: false,
          message: 'No files were modified by Claude Code CLI',
          error: 'Claude Code CLI did not make any file changes'
        };
      }
      
      logger.info(`Files modified by Claude Code CLI: ${modifiedFiles.join(', ')}`);
      
      // Build changes map
      const changes: Record<string, string> = {};
      for (const file of modifiedFiles) {
        changes[file] = `Modified by Claude Code CLI`;
      }
      
      return {
        success: true,
        message: `Successfully modified ${modifiedFiles.length} file(s)`,
        changes
      };
      
    } catch (error) {
      logger.error('Failed to generate solution with retry:', error);
      return {
        success: false,
        message: 'Failed to generate solution',
        error: error instanceof Error ? error.message : String(error)
      };
    }
  }

  /**
   * Execute CLI with retry mechanism
   */
  async executeWithRetry(
    prompt: string,
    options: any,
    retryConfig?: Partial<RetryConfig>
  ): Promise<CLISolutionResult> {
    const config = { ...this.defaultRetryConfig, ...retryConfig };
    let lastError: Error | null = null;
    
    for (let attempt = 1; attempt <= config.maxAttempts; attempt++) {
      try {
        logger.info(`Attempt ${attempt}/${config.maxAttempts}: Executing Claude Code CLI`);
        
        const result = await this.executeCLI(prompt, options);
        
        if (result.success) {
          if (attempt > 1) {
            logger.info(`Succeeded on attempt ${attempt} after ${attempt - 1} retry(ies)`);
          }
          return {
            success: true,
            message: result.output || 'Operation completed successfully'
          };
        }
        
        // Check if error is retryable
        if (!this.isRetryableError(result.error, config.retryableErrors)) {
          logger.warn(`Non-retryable error: ${result.error}`);
          return {
            success: false,
            message: result.error || 'Operation failed',
            error: result.error
          };
        }
        
        lastError = new Error(result.error || 'Unknown error');
        logger.warn(`Retryable error on attempt ${attempt}: ${result.error}`);
        
      } catch (error) {
        lastError = error as Error;
        
        if (!this.isRetryableError(lastError.message, config.retryableErrors)) {
          logger.error(`Non-retryable exception: ${lastError.message}`);
          throw error;
        }
        
        logger.warn(`Retryable exception on attempt ${attempt}: ${lastError.message}`);
      }
      
      // Calculate delay with exponential backoff
      if (attempt < config.maxAttempts) {
        const delay = Math.min(
          config.initialDelayMs * Math.pow(config.backoffMultiplier, attempt - 1),
          config.maxDelayMs
        );
        
        logger.info(`Retrying in ${delay}ms (exponential backoff)...`);
        await this.sleep(delay);
      }
    }
    
    // All attempts failed
    logger.error(`Failed after ${config.maxAttempts} attempts. Last error: ${lastError?.message}`);
    return {
      success: false,
      message: `Failed after ${config.maxAttempts} attempts`,
      error: lastError?.message || 'Unknown error'
    };
  }

  /**
   * Check if an error is retryable
   */
  private isRetryableError(error: string | undefined, retryableErrors: string[]): boolean {
    if (!error) return false;
    
    const errorLower = error.toLowerCase();
    return retryableErrors.some(pattern => 
      errorLower.includes(pattern.toLowerCase())
    );
  }

  /**
   * Sleep for specified milliseconds
   */
  private sleep(ms: number): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, ms));
  }

  /**
   * Get appropriate API key based on mode
   */
  private getApiKey(isDev: boolean): string | undefined {
    if (isDev) {
      // In dev mode, prefer Claude Code Max API key
      const maxKey = process.env.CLAUDE_CODE_MAX_API_KEY;
      if (maxKey) {
        logger.debug('Using Claude Code Max API key from CLAUDE_CODE_MAX_API_KEY');
        return maxKey;
      }
      
      // Fall back to regular API key
      const regularKey = process.env.ANTHROPIC_API_KEY;
      if (regularKey) {
        logger.debug('Using regular API key in dev mode (CLAUDE_CODE_MAX_API_KEY not set)');
        return regularKey;
      }
      
      return undefined;
    }
    
    // Production mode: prioritize vended credentials over environment
    let apiKey: string | undefined;

    // Try vended credentials first if available
    if (this.credentialManager) {
      try {
        apiKey = this.credentialManager.getCredential('anthropic');
        if (apiKey) {
          logger.debug('Using vended credentials for production mode');
        }
      } catch (error) {
        logger.warn('Failed to get vended credentials:', error);
      }
    }

    // Fall back to environment variable if no vended credentials
    if (!apiKey) {
      apiKey = process.env.ANTHROPIC_API_KEY;
      if (apiKey) {
        logger.debug('Using environment ANTHROPIC_API_KEY');
      }
    }
    
    return apiKey;
  }

}

// Export for testing
export { CLISolutionResult };