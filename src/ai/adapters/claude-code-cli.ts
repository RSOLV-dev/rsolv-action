/**
 * Claude Code CLI adapter that calls the CLI directly
 * Bypasses SDK issues with MCP and file editing in Docker
 */
import { IssueContext } from '../../types/index.js';
import { AIConfig } from '../types.js';
import { IssueAnalysis } from '../types.js';
import { logger } from '../../utils/logger.js';
import { spawn } from 'child_process';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';

export interface CLISolutionResult {
  success: boolean;
  message: string;
  changes?: Record<string, string>;
  error?: string;
  messages?: any[];
}

/**
 * Claude Code adapter that uses CLI directly
 */
export class ClaudeCodeCLIAdapter {
  private claudeConfig?: AIConfig;
  private repoPath: string;
  private credentialManager?: any;

  constructor(config: AIConfig, repoPath: string = process.cwd(), credentialManager?: any) {
    this.claudeConfig = config;
    this.repoPath = repoPath;
    this.credentialManager = credentialManager;
  }

  /**
   * Generate solution using Claude Code CLI
   */
  async generateSolution(
    issueContext: IssueContext,
    analysis: IssueAnalysis,
    enhancedPrompt?: string
  ): Promise<CLISolutionResult> {
    try {
      logger.info('Using Claude Code CLI for file editing...');

      // Get API key from environment or vended credentials
      let apiKey = process.env.ANTHROPIC_API_KEY;
      
      // If no direct API key, try to get from vended credentials
      if (!apiKey && this.credentialManager) {
        try {
          apiKey = this.credentialManager.getCredential('anthropic');
          if (apiKey) {
            logger.info('Using vended credentials for Claude Code CLI');
          }
        } catch (error) {
          logger.warn('Failed to get vended credentials:', error);
        }
      }
      
      if (!apiKey) {
        return {
          success: false,
          message: 'CLI execution failed',
          error: 'ANTHROPIC_API_KEY environment variable or vended credentials required for CLI approach'
        };
      }

      // Create prompt
      const prompt = enhancedPrompt || this.constructPrompt(issueContext, analysis);
      
      logger.info(`Working directory: ${this.repoPath}`);
      logger.info(`Prompt length: ${prompt.length} characters`);

      // Execute Claude Code CLI with prompt via stdin
      const result = await this.executeCLI(prompt, {
        cwd: this.repoPath,
        env: {
          ...process.env,
          ANTHROPIC_API_KEY: apiKey
        }
      })

      if (!result.success) {
        return {
          success: false,
          message: result.error || 'Claude Code CLI execution failed',
          error: result.error
        };
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

      // Extract any JSON from the output
      let changes: Record<string, string> = {};
      const jsonMatch = result.output?.match(/```(?:json)?\s*(\{[\s\S]*?\})\s*```/);
      if (jsonMatch) {
        try {
          const jsonData = JSON.parse(jsonMatch[1]);
          if (jsonData.files && Array.isArray(jsonData.files)) {
            jsonData.files.forEach((file: any) => {
              if (file.path && file.changes) {
                changes[file.path] = file.changes;
              }
            });
          }
        } catch (e) {
          logger.debug('Could not parse JSON from CLI output');
        }
      }

      return {
        success: true,
        message: `Successfully fixed vulnerabilities in ${modifiedFiles.length} file(s)`,
        changes,
        messages: [{ type: 'cli_output', content: result.output }]
      };

    } catch (error) {
      logger.error('Claude Code CLI execution failed:', error);
      return {
        success: false,
        message: 'CLI execution failed',
        error: error instanceof Error ? error.message : String(error)
      };
    }
  }

  /**
   * Execute Claude Code CLI
   */
  private executeCLI(prompt: string, options: any): Promise<{ success: boolean; output?: string; error?: string }> {
    return new Promise((resolve) => {
      // Set a 20-minute timeout for Claude CLI
      const timeout = setTimeout(() => {
        logger.warn('Claude CLI execution timed out after 20 minutes');
        if (child && !child.killed) {
          child.kill('SIGTERM');
        }
        resolve({
          success: false,
          error: 'Claude CLI execution timed out after 20 minutes'
        });
      }, 20 * 60 * 1000); // 20 minutes
      
      let child: any;
      // Try different approaches to find Claude CLI
      // Use -p flag to pass prompt via stdin (as per working implementation)
      const cliCommands = [
        ['claude', ['-p', '-']],  // Global install with stdin
        ['bunx', ['@anthropic-ai/claude-code', '-p', '-']],  // Bunx with stdin
        ['bun', ['node_modules/@anthropic-ai/claude-code/cli.js', '-p', '-']]  // Direct run with stdin
      ];
      
      let attemptIndex = 0;
      
      const tryNextCommand = () => {
        if (attemptIndex >= cliCommands.length) {
          resolve({
            success: false,
            error: 'Could not find Claude Code CLI via bunx, bun, or global install'
          });
          return;
        }
        
        const [command, commandArgs] = cliCommands[attemptIndex];
        logger.info(`Attempting: ${command} ${commandArgs.join(' ')}`);
        attemptIndex++;
        
        child = spawn(command, commandArgs, {
          ...options,
          stdio: ['pipe', 'pipe', 'pipe']
        });

        // Write prompt to stdin and close it (as per working implementation)
        child.stdin.write(prompt);
        child.stdin.end();

        let stdout = '';
        let stderr = '';

        child.stdout?.on('data', (data) => {
          const chunk = data.toString();
          stdout += chunk;
          // Log output in real-time for debugging
          logger.debug(`Claude CLI stdout: ${chunk.slice(0, 200)}`);
          process.stdout.write(chunk);
        });

        child.stderr?.on('data', (data) => {
          const chunk = data.toString();
          stderr += chunk;
          // Log errors in real-time
          process.stderr.write(chunk);
        });

        child.on('close', (code) => {
          clearTimeout(timeout); // Clear timeout on completion
          if (code === 0) {
            resolve({ success: true, output: stdout });
          } else {
            resolve({ 
              success: false, 
              error: `Claude CLI exited with code ${code}. stderr: ${stderr}` 
            });
          }
        });

        child.on('error', (error) => {
          // If this command failed, try the next one
          if (attemptIndex < cliCommands.length) {
            logger.debug(`Command ${command} failed with: ${error.message}, trying next approach...`);
            tryNextCommand();
          } else {
            clearTimeout(timeout); // Clear timeout on error
            resolve({ 
              success: false, 
              error: `Failed to start Claude CLI: ${error.message}` 
            });
          }
        });
      };
      
      // Start with the first command
      tryNextCommand();
    });
  }

  /**
   * Get list of modified files using git
   */
  private getModifiedFiles(): string[] {
    try {
      const { execSync } = require('child_process');
      const output = execSync('git diff --name-only', {
        cwd: this.repoPath,
        encoding: 'utf-8'
      }).trim();
      
      return output ? output.split('\n') : [];
    } catch (error) {
      logger.error('Failed to get modified files:', error);
      return [];
    }
  }

  /**
   * Construct the prompt for CLI usage
   */
  private constructPrompt(issueContext: IssueContext, analysis: IssueAnalysis): string {
    // Use structured phased prompting if enabled
    if (this.claudeConfig?.useStructuredPhases) {
      return this.constructStructuredPhasedPrompt(issueContext, analysis);
    }
    
    return `You are an expert security engineer fixing vulnerabilities by directly editing files in a git repository.

## Issue Details:
- **Title**: ${issueContext.title}
- **Description**: ${issueContext.body}
- **Complexity**: ${analysis.complexity}
- **Files with vulnerabilities**: ${analysis.relatedFiles?.join(', ') || 'To be discovered'}

## Your Task:

### Phase 1: Locate Vulnerabilities
- Use Grep to find vulnerable code patterns
- Use Read to understand the full context
- Consider using sequential thinking for complex analysis

### Phase 2: Fix Vulnerabilities In-Place
**CRITICAL**: Use Edit or MultiEdit tools to modify files BEFORE providing JSON.
- Make minimal, surgical changes to fix security issues
- Preserve API compatibility and existing function signatures
- Fix all instances of the vulnerability

### Phase 3: Provide Fix Summary (ONLY AFTER EDITING FILES)
After you have used Edit/MultiEdit tools to modify files, provide this JSON:

\`\`\`json
{
  "title": "Fix [vulnerability type] in [component]",
  "description": "Clear explanation of what was vulnerable and how you fixed it",
  "files": [
    {
      "path": "path/to/file.js",
      "changes": "Description of changes made"
    }
  ],
  "tests": [
    "Description of test that validates the fix"
  ]
}
\`\`\`

Remember: Edit files FIRST using Edit/MultiEdit tools, then provide the JSON summary.`;
  }

  /**
   * Construct a structured phased prompt for CLI
   */
  private constructStructuredPhasedPrompt(issueContext: IssueContext, analysis: IssueAnalysis): string {
    return `You are an expert security engineer fixing vulnerabilities. You MUST complete this task in TWO distinct phases:

## 🚨 CRITICAL: FOLLOW THESE PHASES IN ORDER 🚨

## PHASE 1: FILE EDITING (MANDATORY - DO THIS FIRST)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

### Your Task:
1. Locate the vulnerability: ${issueContext.title}
   - Description: ${issueContext.body}
   - Related files: ${analysis.relatedFiles?.join(', ') || 'To be discovered'}

2. Use Edit or MultiEdit tools to fix the vulnerable code
   - Make minimal, surgical changes
   - Preserve API compatibility
   - Fix all instances of the vulnerability

3. After editing, use Read tool to verify your changes were applied

4. Say "PHASE 1 COMPLETE: Files have been edited" when done

⚠️ IMPORTANT: You MUST complete Phase 1 before proceeding to Phase 2.
Do NOT skip directly to providing JSON.

## PHASE 2: JSON SUMMARY (ONLY AFTER PHASE 1)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Only after you've confirmed "PHASE 1 COMPLETE", provide the JSON summary:

\`\`\`json
{
  "title": "Fix [vulnerability type] in [component]",
  "description": "Clear explanation of what was vulnerable and how you fixed it",
  "files": [
    {
      "path": "path/to/edited/file.js",
      "changes": "Complete file content after your edits (read it back with Read tool if needed)"
    }
  ],
  "tests": [
    "Description of test that validates the fix",
    "Description of test that ensures no regressions"
  ]
}
\`\`\`

## Execution Checklist:
□ Used Edit/MultiEdit tools
□ Verified changes with Read tool  
□ Stated "PHASE 1 COMPLETE"
□ Provided JSON summary

Remember: Edit files FIRST, then provide JSON. Do not provide JSON without editing.`;
  }
}