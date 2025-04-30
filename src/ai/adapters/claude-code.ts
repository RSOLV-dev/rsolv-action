/**
 * Claude Code adapter for the RSOLV AI integration
 * This class provides a wrapper around the Claude Code CLI for enhanced context-gathering
 * in repository analysis and solution generation.
 */
import { spawn } from 'child_process';
import path from 'path';
import fs from 'fs';
import { logger } from '../../utils/logger';
import { IssueContext, IssueAnalysis } from '../../types';
import { PullRequestSolution, AIConfig } from '../types';

export class ClaudeCodeAdapter {
  private executablePath: string;
  private repoPath: string;
  private config: AIConfig;

  constructor(config: AIConfig, repoPath: string = process.cwd(), executablePath: string = 'claude') {
    this.executablePath = executablePath;
    this.repoPath = repoPath;
    this.config = config;
  }

  /**
   * Check if Claude Code CLI is available
   */
  async isAvailable(): Promise<boolean> {
    try {
      return new Promise<boolean>((resolve) => {
        const childProcess = spawn(this.executablePath, ['-v'], {
          shell: true
        });
        
        childProcess.on('close', (code) => {
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
  ): Promise<PullRequestSolution> {
    try {
      logger.info(`Generating solution using Claude Code for issue: ${issueContext.id}`);
      
      // Check if Claude Code is available
      const available = await this.isAvailable();
      if (!available) {
        logger.warn('Claude Code CLI not available, falling back to standard method');
        throw new Error('Claude Code CLI not available');
      }
      
      // Construct the prompt with our feedback-enhanced content if provided
      const prompt = this.constructPrompt(issueContext, analysis, enhancedPrompt);
      
      // Create a temporary prompt file
      const tempDir = path.join(process.cwd(), 'temp');
      if (!fs.existsSync(tempDir)) {
        fs.mkdirSync(tempDir, { recursive: true });
      }
      const promptPath = path.join(tempDir, `prompt-${Date.now()}.txt`);
      fs.writeFileSync(promptPath, prompt);
      
      // Execute Claude Code CLI
      const outputPath = path.join(tempDir, `solution-${Date.now()}.json`);
      const result = await this.executeClaudeCode(promptPath, outputPath);
      
      // Clean up temporary files
      try {
        fs.unlinkSync(promptPath);
      } catch (error) {
        logger.warn('Error cleaning up prompt file', error as Error);
      }
      
      // Parse and normalize the solution
      return this.parseSolution(result, outputPath, issueContext);
    } catch (error) {
      logger.error('Error generating solution with Claude Code', error as Error);
      throw error;
    }
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
    
    // Otherwise, construct a basic prompt
    return `
      You are an expert developer tasked with fixing issues in a codebase.
      
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
      }
    `;
  }

  /**
   * Execute the Claude Code CLI with the given prompt
   */
  private async executeClaudeCode(promptPath: string, outputPath: string): Promise<string> {
    return new Promise((resolve, reject) => {
      // Read the prompt from file
      let prompt;
      try {
        prompt = fs.readFileSync(promptPath, 'utf-8');
      } catch (error) {
        reject(new Error(`Could not read prompt file: ${error}`));
        return;
      }
      
      // Use stream-json format for better user experience
      // This provides faster initial response and progress updates
      const args = [
        '--print',  // Non-interactive mode
        '--output-format', 'stream-json',  // Stream JSON for responsive output
        '--verbose'  // Include additional progress information
      ];
      
      // The actual prompt is passed as the last argument
      args.push(prompt);
      
      // API key is handled via environment
      const envVars = {
        ...process.env,
        ANTHROPIC_API_KEY: this.config.apiKey
      };
      
      const childProcess = spawn(this.executablePath, args, {
        cwd: this.repoPath,
        shell: true,
        env: envVars
      });
      
      let output = '';
      let errorOutput = '';
      
      // Track progress through streaming updates
      let responseStarted = false;
      let chunkCount = 0;
      const startTime = Date.now();
      
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
        if (chunk.includes('"type": "tool_use"')) {
          logger.info(`Claude is gathering context... (${elapsedSeconds.toFixed(1)}s elapsed)`);
        } else if (chunk.includes('"type": "tool_result"')) {
          logger.info(`Claude is analyzing the issue... (${elapsedSeconds.toFixed(1)}s elapsed)`);
        } else if (chunk.includes('"type": "text"')) {
          logger.info(`Claude is generating solution... (${elapsedSeconds.toFixed(1)}s elapsed)`);
        } else if (chunk.includes('"cost_usd"')) {
          const costMatch = chunk.match(/"cost_usd": ([0-9.]+)/);
          if (costMatch) {
            logger.info(`Claude completed response (cost: $${costMatch[1]})`);
          }
        }
      });
      
      childProcess.stderr.on('data', (data) => {
        errorOutput += data.toString();
        logger.warn(`Claude CLI stderr: ${data.toString().trim()}`);
      });
      
      childProcess.on('close', (code) => {
        const totalTime = (Date.now() - startTime) / 1000;
        logger.info(`Claude Code process completed in ${totalTime.toFixed(1)}s (${chunkCount} chunks)`);
        
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
          let solutionText = directJsonMatch[1]
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
          let solutionText = solutionMatch[1]
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
        description: "Could not parse Claude Code output. Please check the logs for more information.",
        files: [],
        tests: []
      };
    } catch (error) {
      logger.error('Error parsing solution', error as Error);
      
      // Return a minimal solution in case of error
      return {
        title: `Fix for: ${issueContext.title}`,
        description: "Error occurred while parsing Claude Code solution.",
        files: [],
        tests: []
      };
    }
  }
}