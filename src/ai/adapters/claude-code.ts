/**
 * Claude Code adapter for the RSOLV AI integration
 * This class provides a wrapper around the Claude Code CLI for enhanced context-gathering
 * in repository analysis and solution generation.
 */
import { spawn } from 'child_process';
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
  contextGatheringTime?: number;
  solutionGenerationTime?: number;
  totalChunks?: number;
  cost?: number;
  errorType?: string;
  retryCount?: number;
}

/**
 * Claude Code adapter class
 */
export class ClaudeCodeAdapter {
  private executablePath: string;
  private repoPath: string;
  private config: AIConfig;
  private claudeConfig: ClaudeCodeConfig;
  private tempDir: string;
  private usageData: UsageData[] = [];
  private credentialManager?: any;
  
  /**
   * Create a new Claude Code adapter
   */
  constructor(config: AIConfig, repoPath: string = process.cwd(), credentialManager?: any) {
    this.config = config;
    this.repoPath = repoPath;
    this.credentialManager = credentialManager;
    
    // Initialize Claude Code config with defaults
    this.claudeConfig = config.claudeCodeConfig || {};
    this.executablePath = this.claudeConfig.executablePath || 'claude';
    this.tempDir = this.claudeConfig.tempDir || path.join(process.cwd(), 'temp');
    
    // Ensure temp directory exists
    if (!fs.existsSync(this.tempDir)) {
      try {
        fs.mkdirSync(this.tempDir, { recursive: true });
      } catch (error) {
        logger.warn(`Failed to create temp directory: ${error}`);
        // Will fall back to system temp dir if needed
      }
    }
    
    if (this.claudeConfig.verboseLogging) {
      logger.info('Claude Code adapter initialized with config:', JSON.stringify({
        executablePath: this.executablePath,
        tempDir: this.tempDir,
        contextOptions: this.claudeConfig.contextOptions,
        retryOptions: this.claudeConfig.retryOptions,
        timeout: this.claudeConfig.timeout
      }, null, 2));
    }
  }

  /**
   * Check if Claude Code CLI is available
   */
  async isAvailable(): Promise<boolean> {
    try {
      return new Promise<boolean>((resolve) => {
        const timeout = setTimeout(() => {
          logger.warn('Claude Code availability check timed out');
          resolve(false);
        }, 5000);
        
        const childProcess = spawn(this.executablePath, ['-v'], {
          shell: true
        });
        
        childProcess.on('close', (code) => {
          clearTimeout(timeout);
          resolve(code === 0);
        });
      });
    } catch (error) {
      logger.error('Error checking Claude Code availability', error as Error);
      return false;
    }
  }

  /**
   * Generate a solution for an issue using Claude Code's enhanced context-gathering
   */
  async generateSolution(
    issueContext: IssueContext, 
    analysis: IssueAnalysis,
    enhancedPrompt?: string
  ): Promise<{ success: boolean; message: string; changes?: Record<string, string>; error?: string }> {
    let promptPath: string | null = null;
    let errorRetryCount = 0;
    const maxRetries = this.claudeConfig.retryOptions?.maxRetries ?? 2;
    const baseDelay = this.claudeConfig.retryOptions?.baseDelay ?? 1000;
    const timeout = this.claudeConfig.timeout ?? 300000; // 5 minutes default
    
    // Initialize usage tracking
    const usageEntry: UsageData = {
      startTime: Date.now(),
      issueId: issueContext.id,
      successful: false
    };
    
    try {
      logger.info(`Generating solution using Claude Code for issue: ${issueContext.id}`);
      
      // Check if Claude Code is available
      const available = await this.isAvailable();
      if (!available) {
        logger.warn('Claude Code CLI not available, falling back to standard method');
        usageEntry.errorType = 'cli_not_available';
        this.trackUsage(usageEntry);
        
        // Provide helpful error message with installation instructions
        return {
          success: false,
          message: 'Claude Code CLI not available',
          error: 'Claude Code CLI not available. Please ensure Claude Code is installed and in your PATH.\n\n' +
            'Installation instructions:\n' +
            '1. Visit https://claude.ai/console/claude-code\n' +
            '2. Follow the installation steps for your platform\n' +
            '3. Verify installation with: claude -v'
        };
      }
      
      // Construct the prompt with our feedback-enhanced content if provided
      const prompt = this.constructPrompt(issueContext, analysis, enhancedPrompt);
      
      // Create a temporary prompt file with proper error handling
      try {
        if (!fs.existsSync(this.tempDir)) {
          fs.mkdirSync(this.tempDir, { recursive: true });
        }
        promptPath = path.join(this.tempDir, `prompt-${issueContext.id}-${Date.now()}.txt`);
        fs.writeFileSync(promptPath, prompt);
      } catch (fsError) {
        logger.error('Error creating temporary files', fsError as Error);
        usageEntry.errorType = 'temp_file_error';
        this.trackUsage(usageEntry);
        
        // Return error with file access details
        return {
          success: false,
          message: 'Error creating temporary files',
          error: 'Error creating temporary files for Claude Code. Please check file permissions.'
        };
      }
      
      // Execute Claude Code CLI with retry logic
      const outputPath = path.join(this.tempDir, `solution-${issueContext.id}-${Date.now()}.json`);
      let result: string;
      
      const executeWithRetry = async (): Promise<string> => {
        try {
          return await this.executeClaudeCode(promptPath!, outputPath, usageEntry, timeout);
        } catch (execError) {
          errorRetryCount++;
          usageEntry.retryCount = errorRetryCount;
          
          if (errorRetryCount < maxRetries) {
            logger.warn(`Claude Code execution failed, retrying (${errorRetryCount}/${maxRetries})...`);
            
            // Provide user feedback about retry
            if (this.claudeConfig.verboseLogging) {
              logger.info(`Retry reason: ${(execError as Error).message}`);
            }
            
            // Wait before retry with exponential backoff
            const delay = baseDelay * Math.pow(2, errorRetryCount);
            await new Promise(resolve => setTimeout(resolve, delay));
            return executeWithRetry();
          } else {
            throw execError;
          }
        }
      };
      
      try {
        // Setup execution timeout
        const executionPromise = executeWithRetry();
        
        // Create a timeout promise
        const timeoutPromise = new Promise<never>((_, reject) => {
          setTimeout(() => {
            reject(new Error(`Claude Code execution timed out after ${timeout/1000} seconds`));
          }, timeout);
        });
        
        // Race the execution against the timeout
        result = await Promise.race([executionPromise, timeoutPromise]);
      } catch (execError) {
        logger.error('Claude Code execution failed after retries', execError as Error);
        usageEntry.errorType = 'execution_error';
        usageEntry.endTime = Date.now();
        this.trackUsage(usageEntry);
        
        // Return execution error
        return {
          success: false,
          message: 'Claude Code execution failed',
          error: `Claude Code execution failed: ${(execError as Error).message}`
        };
      }
      
      // Clean up temporary files
      try {
        if (promptPath) {
          fs.unlinkSync(promptPath);
        }
      } catch (error) {
        logger.warn('Error cleaning up prompt file', error as Error);
      }
      
      // Parse and normalize the solution
      try {
        const solution = this.parseSolution(result, outputPath, issueContext);
        
        // Mark as successful in usage tracking
        usageEntry.successful = true;
        usageEntry.endTime = Date.now();
        this.trackUsage(usageEntry);
        
        // Convert PullRequestSolution to expected format
        const changes: Record<string, string> = {};
        solution.files.forEach(file => {
          changes[file.path] = file.changes;
        });
        
        return {
          success: true,
          message: 'Solution generated with Claude Code',
          changes
        };
      } catch (parseError) {
        logger.error('Error parsing Claude Code solution', parseError as Error);
        usageEntry.errorType = 'parsing_error';
        usageEntry.endTime = Date.now();
        this.trackUsage(usageEntry);
        
        // Return parsing error
        return {
          success: false,
          message: 'Error parsing Claude Code output',
          error: 'Error parsing Claude Code output. Raw output preview: ' + result.slice(0, 500)
        };
      }
    } catch (error) {
      logger.error('Unexpected error generating solution with Claude Code', error as Error);
      usageEntry.errorType = 'unexpected_error';
      usageEntry.endTime = Date.now();
      this.trackUsage(usageEntry);
      
      // Return generic error
      return {
        success: false,
        message: 'Unexpected error using Claude Code',
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
      
      // Also save analytics locally for persistence
      const analyticsPath = path.join(this.tempDir, 'claude-code-analytics.json');
      try {
        // Read existing analytics if available
        let existingData: UsageData[] = [];
        if (fs.existsSync(analyticsPath)) {
          existingData = JSON.parse(fs.readFileSync(analyticsPath, 'utf-8'));
        }
        
        // Append new data
        existingData.push(data);
        
        // Keep only last 100 entries to avoid unlimited growth
        if (existingData.length > 100) {
          existingData = existingData.slice(-100);
        }
        
        // Write back to file
        fs.writeFileSync(analyticsPath, JSON.stringify(existingData, null, 2));
      } catch (error) {
        logger.warn('Error saving analytics data', error as Error);
      }
      
      // Log usage summary if verbose logging is enabled
      if (this.claudeConfig.verboseLogging) {
        const durationSeconds = data.endTime ? (data.endTime - data.startTime) / 1000 : 0;
        logger.info(`Usage stats for issue ${data.issueId}: ` +
          `${data.successful ? 'Success' : 'Failed'} in ${durationSeconds.toFixed(1)}s ` +
          `(cost: ${data.cost ? '$' + data.cost : 'unknown'})`);
      }
    }
  }
  
  /**
   * Get usage analytics data
   */
  getUsageData(): UsageData[] {
    return this.usageData;
  }
  
  /**
   * Construct the prompt for Claude Code, incorporating feedback-enhanced content if available
   */
  private constructPrompt(
    issueContext: IssueContext, 
    analysis: IssueAnalysis,
    enhancedPrompt?: string
  ): string {
    // If an enhanced prompt was provided, use it
    if (enhancedPrompt) {
      return enhancedPrompt;
    }
    
    // Otherwise, construct a basic prompt with context directives
    
    // Add context directives based on configuration
    const contextDirectives = [];
    
    if (this.claudeConfig.contextOptions) {
      const opts = this.claudeConfig.contextOptions;
      
      // Add depth directive
      if (opts.maxDepth !== undefined) {
        contextDirectives.push(`Use a maximum exploration depth of ${opts.maxDepth} when gathering context.`);
      }
      
      // Add breadth directive
      if (opts.explorationBreadth !== undefined) {
        contextDirectives.push(`Use a context exploration breadth of ${opts.explorationBreadth} (on a scale of 1-5).`);
      }
      
      // Add include/exclude directories
      if (opts.includeDirs && opts.includeDirs.length > 0) {
        contextDirectives.push(`Focus on examining these directories: ${opts.includeDirs.join(', ')}`);
      }
      
      if (opts.excludeDirs && opts.excludeDirs.length > 0) {
        contextDirectives.push(`Skip examining these directories: ${opts.excludeDirs.join(', ')}`);
      }
      
      // Add include/exclude file patterns
      if (opts.includeFiles && opts.includeFiles.length > 0) {
        contextDirectives.push(`Focus on files matching these patterns: ${opts.includeFiles.join(', ')}`);
      }
      
      if (opts.excludeFiles && opts.excludeFiles.length > 0) {
        contextDirectives.push(`Skip files matching these patterns: ${opts.excludeFiles.join(', ')}`);
      }
    }
    
    // Join directives if any exist
    const contextSection = contextDirectives.length > 0 
      ? `\nContext Gathering Instructions:\n${contextDirectives.join('\n')}\n`
      : '';
    
    return `
      You are an expert developer tasked with fixing issues in a codebase.
      
      Issue Title: ${issueContext.title}
      Issue Description: ${issueContext.body}
      
      Complexity: ${analysis.complexity}
      Estimated Time: ${analysis.estimatedTime} minutes
      ${contextSection}
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
      }
    `;
  }

  /**
   * Execute the Claude Code CLI with the given prompt
   */
  private async executeClaudeCode(
    promptPath: string, 
    outputPath: string, 
    usageEntry: UsageData,
    timeout: number
  ): Promise<string> {
    return new Promise((resolve, reject) => {
      // Read the prompt from file
      let prompt;
      try {
        prompt = fs.readFileSync(promptPath, 'utf-8');
      } catch (error) {
        reject(new Error(`Could not read prompt file: ${error}`));
        return;
      }
      
      // Build Claude Code CLI arguments based on configuration
      const args = [
        '--print'  // Non-interactive mode - prompt will be passed via stdin
      ];
      
      // Add verbose flag first (required for stream-json)
      if (this.claudeConfig.verboseLogging) {
        args.push('--verbose');
      }
      
      // Add output format (stream-json requires --verbose)
      const outputFormat = this.claudeConfig.outputFormat || 'stream-json';
      if (outputFormat === 'stream-json' && !this.claudeConfig.verboseLogging) {
        // Auto-enable verbose for stream-json
        args.push('--verbose');
      }
      args.push('--output-format', outputFormat);
      
      // Add context options if configured
      if (this.claudeConfig.contextOptions) {
        const opts = this.claudeConfig.contextOptions;
        
        if (opts.maxDepth !== undefined) {
          args.push('--max-depth', opts.maxDepth.toString());
        }
        
        if (opts.includeDirs && opts.includeDirs.length > 0) {
          args.push('--include-dirs', opts.includeDirs.join(','));
        }
        
        if (opts.excludeDirs && opts.excludeDirs.length > 0) {
          args.push('--exclude-dirs', opts.excludeDirs.join(','));
        }
      }
      
      // API key is handled via environment
      // Support vended credentials
      let apiKey = this.config.apiKey;
      
      // If using vended credentials, get the key from credential manager
      if (this.config.useVendedCredentials && this.credentialManager) {
        try {
          apiKey = this.credentialManager.getCredential('anthropic');
          logger.info('Using vended Anthropic credential for Claude Code');
        } catch (error) {
          logger.warn('Failed to get vended credential, falling back to config API key', error);
        }
      }
      
      const envVars = {
        ...process.env,
        ANTHROPIC_API_KEY: apiKey
      };
      
      if (this.claudeConfig.verboseLogging) {
        logger.info('Executing Claude Code with args:', args.join(' '));
      }
      
      const childProcess = spawn(this.executablePath, args, {
        cwd: this.repoPath,
        shell: false, // Changed from true to false
        env: envVars,
        stdio: ['pipe', 'pipe', 'pipe'] // Explicit stdio setup
      });
      
      // Write the prompt to stdin and close it
      childProcess.stdin.write(prompt);
      childProcess.stdin.end();
      
      let output = '';
      let errorOutput = '';
      
      // Track progress through streaming updates
      let responseStarted = false;
      let contextGatheringStarted = false;
      let contextGatheringCompleted = false;
      let contextGatheringTime: number | undefined;
      let chunkCount = 0;
      const startTime = Date.now();
      
      // Set timeout for the child process
      const processTimeout = setTimeout(() => {
        logger.error(`Claude Code execution timed out after ${timeout/1000}s`);
        childProcess.kill();
        reject(new Error(`Execution timed out after ${timeout/1000} seconds`));
      }, timeout);
      
      childProcess.stdout.on('data', (data) => {
        const chunk = data.toString();
        output += chunk;
        chunkCount++;
        
        const elapsedSeconds = (Date.now() - startTime) / 1000;
        
        // Analyze chunk to provide progress updates
        if (!responseStarted) {
          responseStarted = true;
          logger.info(`Received first Claude response chunk after ${elapsedSeconds.toFixed(1)}s`);
        }
        
        // Process different stages based on chunk content
        if (chunk.includes('"type": "tool_use"') && !contextGatheringStarted) {
          contextGatheringStarted = true;
          logger.info(`Claude is gathering context... (${elapsedSeconds.toFixed(1)}s elapsed)`);
        } else if (chunk.includes('"type": "tool_result"') && !contextGatheringCompleted && contextGatheringStarted) {
          contextGatheringCompleted = true;
          contextGatheringTime = Date.now() - startTime;
          usageEntry.contextGatheringTime = contextGatheringTime;
          logger.info(`Context gathering completed in ${(contextGatheringTime/1000).toFixed(1)}s`);
          logger.info(`Claude is analyzing the issue... (${elapsedSeconds.toFixed(1)}s elapsed)`);
        } else if (chunk.includes('"type": "text"') && contextGatheringCompleted) {
          logger.info(`Claude is generating solution... (${elapsedSeconds.toFixed(1)}s elapsed)`);
        } else if (chunk.includes('"cost_usd"')) {
          const costMatch = chunk.match(/"cost_usd": ([0-9.]+)/);
          if (costMatch) {
            const cost = parseFloat(costMatch[1]);
            usageEntry.cost = cost;
            logger.info(`Claude completed response (cost: $${cost.toFixed(4)})`);
          }
        }
      });
      
      childProcess.stderr.on('data', (data) => {
        errorOutput += data.toString();
        logger.warn(`Claude CLI stderr: ${data.toString().trim()}`);
      });
      
      childProcess.on('close', (code) => {
        clearTimeout(processTimeout);
        
        const totalTime = (Date.now() - startTime) / 1000;
        logger.info(`Claude Code process completed in ${totalTime.toFixed(1)}s (${chunkCount} chunks)`);
        
        // Update usage tracking
        usageEntry.totalChunks = chunkCount;
        usageEntry.solutionGenerationTime = Date.now() - (startTime + (usageEntry.contextGatheringTime || 0));
        
        if (code !== 0) {
          reject(new Error(`Claude Code exited with code ${code}: ${errorOutput}`));
        } else {
          resolve(output);
        }
      });
    });
  }

  /**
   * Parse the Claude Code output into our standard solution format
   */
  private parseSolution(
    rawOutput: string, 
    outputPath: string, 
    issueContext: IssueContext
  ): PullRequestSolution {
    try {
      // The stream-json format outputs multiple JSON objects
      // We need to extract the solution from the response
      
      // Method 1: Look for a direct JSON solution in text content
      const directJsonMatch = rawOutput.match(/"text": "(\\{\\\\n[^"]*\\\\n\\})"/);
      if (directJsonMatch) {
        try {
          // Process the escaped JSON string
          const solutionText = directJsonMatch[1]
            .replace(/\\\\n/g, '\n')  // Double-escaped newlines
            .replace(/\\"/g, '"')     // Escaped quotes
            .replace(/\\\\\\\\/g, '\\');  // Double-escaped backslashes
          
          logger.debug('Found direct JSON solution in Claude response');
          const solution = JSON.parse(solutionText);
          
          // Return the solution if it matches our expected format
          if (solution.title && solution.description && Array.isArray(solution.files)) {
            return {
              title: solution.title,
              description: solution.description,
              files: solution.files,
              tests: solution.tests || []
            };
          }
        } catch (jsonError) {
          logger.warn('Failed to parse direct JSON solution', jsonError as Error);
          // Fall through to other methods
        }
      }
      
      // Method 2: Look for JSON in code blocks
      const solutionMatch = rawOutput.match(/"text": "([^"]+(?:\\.[^"]+)*)"/);
      if (solutionMatch) {
        try {
          const solutionText = solutionMatch[1]
            .replace(/\\n/g, '\n')
            .replace(/\\"/g, '"')
            .replace(/\\\\/g, '\\');
          
          // Look for JSON in a code block
          const jsonMatch = solutionText.match(/```(?:json)?\s*([\s\S]*?)\s*```/);
          if (jsonMatch) {
            logger.debug('Found JSON in code block in Claude response');
            const solution = JSON.parse(jsonMatch[1]);
            
            // Return the solution if it matches our expected format
            if (solution.title && solution.description && Array.isArray(solution.files)) {
              return {
                title: solution.title,
                description: solution.description,
                files: solution.files,
                tests: solution.tests || []
              };
            }
          }
        } catch (blockError) {
          logger.warn('Failed to parse JSON code block', blockError as Error);
          // Fall through to other methods
        }
      }
      
      // Method 3: Try to parse standard JSON response
      try {
        // Try to parse the entire output or individual JSON objects
        const jsonObjects = rawOutput.split(/}\s*{/).map((part, i) => {
          // Add back the braces except for first and last parts
          if (i === 0) return part + '}';
          if (i === rawOutput.split(/}\s*{/).length - 1) return '{' + part;
          return '{' + part + '}';
        });
        
        // Try each JSON object
        for (const jsonStr of jsonObjects) {
          try {
            const obj = JSON.parse(jsonStr);
            
            // Check if this object contains our solution
            if (obj.result) {
              const result = typeof obj.result === 'string' ? JSON.parse(obj.result) : obj.result;
              
              if (result.title && result.description && Array.isArray(result.files)) {
                logger.debug('Found solution in result field');
                return {
                  title: result.title,
                  description: result.description,
                  files: result.files,
                  tests: result.tests || []
                };
              }
            }
          } catch (e) {
            // Skip invalid JSON objects
            continue;
          }
        }
      } catch (err) {
        logger.error('Error parsing JSON from Claude Code output', err as Error);
      }
      
      // Fallback to a default solution if parsing fails
      logger.warn('Could not parse Claude Code output, using default solution');
      return {
        title: `Fix for: ${issueContext.title}`,
        description: 'Could not parse Claude Code output. Please check the logs for more information.',
        files: [],
        tests: []
      };
    } catch (error) {
      logger.error('Error parsing solution', error as Error);
      
      // Return a minimal solution in case of error
      return {
        title: `Fix for: ${issueContext.title}`,
        description: 'Error occurred while parsing Claude Code solution.',
        files: [],
        tests: []
      };
    }
  }
  
  /**
   * Get analytics and usage summary
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