/**
 * Claude Agent SDK Adapter
 *
 * RFC-095: Unified adapter replacing 7 legacy Claude Code adapters
 *
 * Key features:
 * - Structured outputs via JSON schema (replaces regex parsing)
 * - Programmatic hooks for observability
 * - canUseTool security enforcement (test file protection)
 * - Session forking for A/B testing
 * - Git integration preserved (external shell commands)
 *
 * Git operations are external to the SDK - they observe filesystem changes
 * made by the SDK's Edit tool and wrap them with git commands.
 */

import { execSync } from 'child_process';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { query } from '@anthropic-ai/claude-agent-sdk';
import type {
  Options,
  Query,
  CanUseTool,
  HookCallback,
  HookCallbackMatcher,
} from '@anthropic-ai/claude-agent-sdk';
import type {
  PermissionResult,
  SDKMessage,
  SDKResultMessage,
  PostToolUseHookInput,
  HookJSONOutput,
} from '@anthropic-ai/claude-agent-sdk';
import { logger } from '../../utils/logger.js';
import type { IssueAnalysis } from '../types.js';
// RFC-095: Import legacy adapter for feature flag fallback
import { GitBasedClaudeCodeAdapter } from './deprecated/claude-code-git.js';
import type { AIConfig } from '../types.js';

/**
 * Result interface for git-based solution generation
 * Matches the interface from claude-code-git.ts for API compatibility
 */
export interface GitSolutionResult {
  success: boolean;
  message: string;
  filesModified?: string[];
  commitHash?: string;
  diffStats?: {
    insertions: number;
    deletions: number;
    filesChanged: number;
  };
  summary?: {
    title: string;
    description: string;
    securityImpact: string;
    tests: string[];
  };
  error?: string;
  isTestMode?: boolean;
  validationFailed?: boolean;
  testModeNote?: string;
}

/**
 * Issue context for solution generation
 */
export interface IssueContext {
  title: string;
  body: string;
  number: number;
  labels?: string[];
}

/**
 * Structured output schema for fix results
 */
export const FixResultSchema = {
  type: 'object' as const,
  properties: {
    title: { type: 'string', description: 'Title of the fix' },
    description: { type: 'string', description: 'Description of what was fixed' },
    securityImpact: { type: 'string', description: 'Security impact assessment' },
    files: {
      type: 'array',
      items: {
        type: 'object',
        properties: {
          path: { type: 'string' },
          changes: { type: 'string' }
        },
        required: ['path', 'changes']
      }
    },
    tests: {
      type: 'array',
      items: { type: 'string' },
      description: 'Tests that validate the fix'
    },
    finalStatus: {
      type: 'string',
      enum: ['PASS', 'FAIL'],
      description: 'Whether all tests pass'
    }
  },
  required: ['title', 'description']
};

/**
 * Type for structured output matching FixResultSchema
 */
export interface FixResultOutput {
  title: string;
  description: string;
  securityImpact?: string;
  files?: Array<{ path: string; changes: string }>;
  tests?: string[];
  finalStatus?: 'PASS' | 'FAIL';
}

/**
 * Test execution log entry
 */
interface TestLogEntry {
  command: string;
  output: string;
  timestamp: number;
}

/**
 * Credential manager interface for vended credentials
 */
export interface CredentialManager {
  getCredential(provider: string): Promise<string>;
  // RFC-095: Feature flag support for legacy adapter fallback
  shouldUseLegacyAdapter?(): boolean;
}

/**
 * Configuration for the adapter
 */
export interface ClaudeAgentSDKAdapterConfig {
  /** Working directory for file operations */
  repoPath: string;

  /** Optional credential manager for vended credentials */
  credentialManager?: CredentialManager;

  /** Use vended credentials instead of environment variables */
  useVendedCredentials?: boolean;

  /** Maximum conversation turns */
  maxTurns?: number;

  /** Model to use */
  model?: string;

  /** Custom test file patterns to protect */
  testFilePatterns?: string[];

  /** Enable verbose logging */
  verbose?: boolean;
}

/**
 * Claude Agent SDK Adapter
 *
 * Unified adapter for Claude Agent SDK that replaces 7 legacy adapters:
 * - claude-code.ts
 * - claude-code-enhanced.ts
 * - claude-code-git.ts
 * - claude-code-cli.ts
 * - claude-code-cli-retry.ts
 * - claude-code-cli-dev.ts
 * - claude-code-single-pass.ts
 */
export class ClaudeAgentSDKAdapter {
  private repoPath: string;
  private credentialManager?: CredentialManager;
  private useVendedCredentials: boolean;
  private maxTurns: number;
  private model?: string;
  private testFilePatterns: string[];
  private verbose: boolean;

  /** Test execution log for hybrid verification */
  private testLog: TestLogEntry[] = [];

  /** Session ID for resume/fork operations */
  private sessionId?: string;

  constructor(config: ClaudeAgentSDKAdapterConfig) {
    this.repoPath = config.repoPath;
    this.credentialManager = config.credentialManager;
    this.useVendedCredentials = config.useVendedCredentials ?? false;
    this.maxTurns = config.maxTurns ?? 3;
    this.model = config.model;
    this.testFilePatterns = config.testFilePatterns ?? [
      'test/',
      'tests/',
      '__tests__/',
      '*.test.ts',
      '*.test.js',
      '*.spec.ts',
      '*.spec.js',
      '_test.go',
      '_test.py'
    ];
    this.verbose = config.verbose ?? false;
  }

  /**
   * Get API key, either from vended credentials or environment
   */
  async getApiKey(): Promise<string> {
    if (this.useVendedCredentials && this.credentialManager) {
      return await this.credentialManager.getCredential('anthropic');
    }
    return process.env.ANTHROPIC_API_KEY || '';
  }

  /**
   * Build environment variables for SDK subprocess
   *
   * FIX: GitHub issue #4383, #865 - explicitly pass PATH to fix spawn issues in containers
   * FIX: GitHub issue #347 - exclude DEBUG to prevent [SandboxDebug] stdout pollution
   *
   * The SDK's spawn mechanism doesn't properly inherit environment variables in Docker
   * containers, so we must explicitly pass each required variable instead of spreading
   * process.env.
   */
  buildEnvForSDK(apiKey: string): Record<string, string> {
    return {
      // Explicitly set PATH - container spawn doesn't inherit properly (issue #4383)
      PATH: process.env.PATH || '/usr/local/bin:/usr/bin:/bin:/app/node_modules/.bin',
      // Core API credentials
      ANTHROPIC_API_KEY: apiKey,
      // Home directory for config files
      HOME: process.env.HOME || '/root',
      // Disable interactive prompts in headless mode
      CI: 'true',
      // Node environment
      NODE_ENV: process.env.NODE_ENV || 'production',
      // User identity for git operations
      USER: process.env.USER || 'root',
      // Shell for subprocess commands
      SHELL: process.env.SHELL || '/bin/bash',
      // Terminal type for proper output handling
      TERM: process.env.TERM || 'xterm-256color',
      // Note: DEBUG is intentionally excluded to prevent [SandboxDebug] stdout pollution (issue #347)
    };
  }

  /**
   * Get the path to the Claude Code CLI executable
   *
   * In Docker containers, the CLI is at a different path than the SDK expects.
   * This method finds the correct path by checking multiple locations.
   */
  getClaudeCodeExecutablePath(): string {
    // Possible locations for the Claude Code CLI
    const possiblePaths = [
      // Docker container path (production)
      '/app/node_modules/@anthropic-ai/claude-code/cli.js',
      // Local development paths
      path.join(process.cwd(), 'node_modules', '@anthropic-ai', 'claude-code', 'cli.js'),
      path.join(__dirname, '..', '..', '..', 'node_modules', '@anthropic-ai', 'claude-code', 'cli.js'),
    ];

    for (const cliPath of possiblePaths) {
      if (fs.existsSync(cliPath)) {
        logger.info(`[SDK] Found Claude Code CLI at: ${cliPath}`);
        return cliPath;
      }
    }

    // Fallback: try to find it using which/where command
    try {
      const claudePath = execSync('which claude 2>/dev/null || where claude 2>/dev/null', {
        encoding: 'utf-8'
      }).trim();
      if (claudePath) {
        logger.info(`[SDK] Found Claude Code CLI via PATH: ${claudePath}`);
        return claudePath;
      }
    } catch {
      // Ignore errors from which/where
    }

    // Last resort: return the first path and let the SDK fail with a clear error
    logger.warn('[SDK] Claude Code CLI not found at any expected location, using default path');
    return possiblePaths[0];
  }

  /**
   * Check if a file path is a test file that should be protected
   */
  isTestFile(filePath: string): boolean {
    const normalizedPath = filePath.replace(/\\/g, '/');

    return this.testFilePatterns.some(pattern => {
      if (pattern.endsWith('/')) {
        // Directory pattern
        return normalizedPath.includes(pattern) ||
               normalizedPath.startsWith(pattern);
      } else if (pattern.startsWith('*')) {
        // Glob pattern
        const suffix = pattern.slice(1);
        return normalizedPath.endsWith(suffix);
      } else if (pattern.startsWith('_')) {
        // Suffix pattern (e.g., _test.go)
        return normalizedPath.endsWith(pattern);
      }
      return false;
    });
  }

  /**
   * Check if a command is a test command
   */
  isTestCommand(command: string): boolean {
    if (!command) return false;

    const testPatterns = [
      /\bnpm\s+test\b/,
      /\bnpm\s+run\s+test\b/,
      /\bpnpm\s+test\b/,
      /\byarn\s+test\b/,
      /\bjest\b/,
      /\bvitest\b/,
      /\bmocha\b/,
      /\bpytest\b/,
      /\bgo\s+test\b/,
      /\bmix\s+test\b/,
      /\bcargo\s+test\b/,
      /\brspec\b/
    ];

    return testPatterns.some(pattern => pattern.test(command));
  }

  /**
   * Create the canUseTool callback for security enforcement
   */
  createCanUseTool(): CanUseTool {
    return async (
      toolName: string,
      input: Record<string, unknown>,
      _options: { signal: AbortSignal; toolUseID: string }
    ): Promise<PermissionResult> => {
      // Protect test files from modification
      if (toolName === 'Edit' || toolName === 'Write') {
        const filePath = (input.file_path || input.path) as string | undefined;

        if (filePath && this.isTestFile(filePath)) {
          logger.warn(`Denied edit to test file: ${filePath}`);
          return {
            behavior: 'deny',
            message: `Cannot modify test files. Test file protection is enabled for: ${filePath}`
          };
        }
      }

      // Allow all other operations
      return {
        behavior: 'allow',
        updatedInput: input
      };
    };
  }

  /**
   * Create hooks for observability
   */
  createHooks(): Partial<Record<string, HookCallbackMatcher[]>> {
    const postToolUseHook: HookCallback = async (
      input,
      _toolUseID,
      _options
    ): Promise<HookJSONOutput> => {
      const hookInput = input as PostToolUseHookInput;

      // Track test executions for verification
      if (hookInput.tool_name === 'Bash') {
        const command = (hookInput.tool_input as Record<string, unknown>)?.command as string;

        if (this.isTestCommand(command)) {
          this.testLog.push({
            command,
            output: String(hookInput.tool_response || ''),
            timestamp: Date.now()
          });

          if (this.verbose) {
            logger.info(`Test command executed: ${command.substring(0, 50)}...`);
          }
        }
      }

      return { continue: true };
    };

    return {
      PostToolUse: [{
        matcher: 'Bash',
        hooks: [postToolUseHook]
      }]
    };
  }

  /**
   * RFC-103 B3: Path patterns excluded from fix commits.
   * Workflow files must not be staged because GITHUB_TOKEN lacks `workflows` permission.
   */
  static readonly EXCLUDED_PATH_PATTERNS: RegExp[] = [
    /^\.github\/workflows\//,
    /^\.github\/actions\//,
  ];

  /**
   * Get list of modified files using git, excluding paths that should not be committed.
   * RFC-103 B3: Filters out .github/workflows/ and .github/actions/ files and reverts them.
   */
  getModifiedFiles(): string[] {
    try {
      const output = execSync('git diff --name-only', {
        cwd: this.repoPath,
        encoding: 'utf-8'
      }).trim();

      if (!output) return [];

      const allFiles = output.split('\n');
      const excluded = allFiles.filter(f =>
        ClaudeAgentSDKAdapter.EXCLUDED_PATH_PATTERNS.some(p => p.test(f))
      );
      const included = allFiles.filter(f =>
        !ClaudeAgentSDKAdapter.EXCLUDED_PATH_PATTERNS.some(p => p.test(f))
      );

      if (excluded.length > 0) {
        logger.warn(`[MITIGATE] Excluding ${excluded.length} files from commit: ${excluded.join(', ')}`);
        this.revertExcludedFiles(excluded);
      }

      return included;
    } catch (error) {
      logger.error('Failed to get modified files', error as Error);
      return [];
    }
  }

  /**
   * Revert excluded files so they don't appear in subsequent diffs.
   */
  private revertExcludedFiles(files: string[]): void {
    for (const file of files) {
      try {
        execSync(`git checkout -- "${file}"`, {
          cwd: this.repoPath,
          encoding: 'utf-8'
        });
      } catch (error) {
        logger.warn(`[MITIGATE] Failed to revert excluded file ${file}: ${(error as Error).message}`);
      }
    }
  }

  /**
   * Get diff statistics
   */
  getDiffStats(): GitSolutionResult['diffStats'] {
    try {
      const output = execSync('git diff --stat', {
        cwd: this.repoPath,
        encoding: 'utf-8'
      });

      // Parse the summary line (e.g., "3 files changed, 45 insertions(+), 23 deletions(-)")
      const match = output.match(/(\d+) files? changed(?:, (\d+) insertions?\(\+\))?(?:, (\d+) deletions?\(-\))?/);

      if (match) {
        return {
          filesChanged: parseInt(match[1], 10),
          insertions: parseInt(match[2] || '0', 10),
          deletions: parseInt(match[3] || '0', 10)
        };
      }

      return { filesChanged: 0, insertions: 0, deletions: 0 };
    } catch (error) {
      logger.error('Failed to get diff stats', error as Error);
      return { filesChanged: 0, insertions: 0, deletions: 0 };
    }
  }

  /**
   * Create a commit with the changes
   */
  createCommit(files: string[], message: string): string {
    try {
      // Configure git user if not set (for GitHub Actions)
      try {
        execSync('git config user.email', { cwd: this.repoPath });
      } catch {
        execSync('git config user.email "rsolv@users.noreply.github.com"', {
          cwd: this.repoPath
        });
        execSync('git config user.name "RSOLV Bot"', {
          cwd: this.repoPath
        });
      }

      // Stage the modified files
      execSync(`git add ${files.join(' ')}`, {
        cwd: this.repoPath
      });

      // Create the commit using a file to avoid shell escaping issues
      const messageFile = path.join(os.tmpdir(), `commit-msg-${Date.now()}.txt`);
      fs.writeFileSync(messageFile, message);

      try {
        execSync(`git commit -F "${messageFile}"`, {
          cwd: this.repoPath
        });
      } finally {
        // Clean up the temporary file
        try {
          fs.unlinkSync(messageFile);
        } catch {
          // Ignore cleanup errors
        }
      }

      // Get the commit hash
      const hash = execSync('git rev-parse HEAD', {
        cwd: this.repoPath,
        encoding: 'utf-8'
      }).trim();

      logger.info(`Created commit ${hash.substring(0, 8)}: ${message.split('\n')[0]}`);
      return hash;

    } catch (error) {
      logger.error('Failed to create commit', error as Error);
      throw error;
    }
  }

  /**
   * Create a meaningful commit message
   */
  createCommitMessage(title: string, description: string, issueNumber: number): string {
    return `${title}

${description}

Fixes #${issueNumber}

This commit was automatically generated by RSOLV to fix security vulnerabilities.`;
  }

  /**
   * Build the prompt for vulnerability fixing
   */
  buildPrompt(issueContext: IssueContext, analysis: IssueAnalysis): string {
    return `You are fixing a security vulnerability in this codebase.

## Issue
**Title:** ${issueContext.title}
**Description:** ${issueContext.body}

## Analysis
**Summary:** ${analysis.summary}
**Complexity:** ${analysis.complexity}
**Recommended Approach:** ${analysis.recommendedApproach}
${analysis.relatedFiles ? `**Related Files:** ${analysis.relatedFiles.join(', ')}` : ''}
${analysis.requiredChanges ? `**Required Changes:** ${analysis.requiredChanges.join(', ')}` : ''}

## Instructions
1. First, read the relevant files to understand the current implementation
2. Apply the security fix using the Edit tool
3. Run any existing tests to ensure the fix doesn't break functionality
4. Provide a summary of what was changed and why

Important:
- Do NOT modify test files - they are protected
- Make minimal changes to fix the vulnerability
- Follow existing code style and patterns
- Ensure backwards compatibility where possible`;
  }

  /**
   * Legacy compatibility method for constructing prompts
   * RFC-095: Alias for buildPrompt to maintain API compatibility with tests
   */
  protected constructPrompt(
    issueContext: IssueContext,
    analysis: IssueAnalysis,
    _enhancedPrompt?: string
  ): string {
    return this.buildPrompt(issueContext, analysis);
  }

  /**
   * Generate a solution with git integration
   *
   * This is the main entry point that replaces the legacy adapters.
   * It uses the Claude Agent SDK to make file edits, then wraps
   * those changes with git operations (same as claude-code-git.ts).
   *
   * @param issueContext - The issue to fix
   * @param analysis - Analysis of the issue
   * @param _enhancedPrompt - Optional enhanced prompt (legacy compatibility, unused)
   * @param _testResults - Optional test results (legacy compatibility, unused)
   * @param _validationResult - Optional validation result (legacy compatibility, unused)
   * @param _validationContext - Optional validation context (legacy compatibility, unused)
   */
  async generateSolutionWithGit(
    issueContext: IssueContext,
    analysis: IssueAnalysis,
    _enhancedPrompt?: string,
    _testResults?: unknown,
    _validationResult?: unknown,
    _validationContext?: { current: number; max: number }
  ): Promise<GitSolutionResult> {
    // Clear test log for new run
    this.testLog = [];

    try {
      // Get API key - either vended or from environment
      const apiKey = await this.getApiKey();
      process.env.ANTHROPIC_API_KEY = apiKey;
      logger.info(`[SDK] API key obtained (length: ${apiKey.length}, prefix: ${apiKey.substring(0, 10)}...)`);

      const prompt = this.buildPrompt(issueContext, analysis);

      const options: Options = {
        cwd: this.repoPath,
        allowedTools: ['Read', 'Edit', 'Bash', 'Glob', 'Grep'],
        permissionMode: 'acceptEdits',
        maxTurns: this.maxTurns,
        model: this.model,

        // Path to Claude Code CLI - needed for Docker containers where the CLI
        // is in a different location than the SDK expects
        pathToClaudeCodeExecutable: this.getClaudeCodeExecutablePath(),

        // Use Node.js to run the CLI (required in Docker where bun is the main runtime)
        executable: 'node',

        // Pass environment variables to the Claude Code process
        // Uses buildEnvForSDK() to fix Docker spawn issues (see method for details)
        env: this.buildEnvForSDK(apiKey),

        // Structured output for parsing fix results
        outputFormat: {
          type: 'json_schema',
          schema: FixResultSchema
        },

        // Security controls via canUseTool
        canUseTool: this.createCanUseTool(),

        // Observability hooks
        hooks: this.createHooks()
      };

      // Execute SDK query
      let structuredOutput: FixResultOutput | undefined;
      let toolCallCount = 0;
      let editToolCalls = 0;

      logger.info(`[SDK] Starting query with prompt length: ${prompt.length}, repoPath: ${this.repoPath}`);
      const queryGenerator: Query = query({ prompt, options });

      for await (const message of queryGenerator) {
        // Capture session ID from init message
        if (message.type === 'system' && 'subtype' in message && message.subtype === 'init') {
          this.sessionId = message.session_id;
          logger.info(`[SDK] Session initialized: ${this.sessionId}`);
        }

        // Track tool usage for debugging
        if (message.type === 'assistant' && 'message' in message) {
          const assistantMsg = message.message as { content?: Array<{ type: string; name?: string }> };
          if (assistantMsg.content) {
            for (const block of assistantMsg.content) {
              if (block.type === 'tool_use') {
                toolCallCount++;
                if (block.name === 'Edit') {
                  editToolCalls++;
                }
                logger.info(`[SDK] Tool call: ${block.name} (total: ${toolCallCount}, edits: ${editToolCalls})`);
              }
            }
          }
        }

        // Extract structured output from result
        if (message.type === 'result') {
          const resultMessage = message as SDKResultMessage;
          if ('structured_output' in resultMessage && resultMessage.structured_output) {
            structuredOutput = resultMessage.structured_output as FixResultOutput;
          }
          logger.info(`[SDK] Query completed. Total tool calls: ${toolCallCount}, Edit calls: ${editToolCalls}`);
        }

        if (this.verbose) {
          logger.debug(`SDK message: ${message.type}`);
        }
      }

      // Git integration - same as claude-code-git.ts
      const modifiedFiles = this.getModifiedFiles();
      logger.info(`[SDK] Modified files detected: ${modifiedFiles.length} - [${modifiedFiles.join(', ')}]`);

      if (modifiedFiles.length === 0) {
        logger.warn(`[SDK] No files modified. Tool calls made: ${toolCallCount}, Edit calls: ${editToolCalls}. This may indicate the SDK did not make any edits or the changes were not written to disk.`);
        return {
          success: false,
          message: 'No files were modified',
          error: `SDK did not make file changes. Tool calls: ${toolCallCount}, Edit calls: ${editToolCalls}`
        };
      }

      const diffStats = this.getDiffStats();

      const commitMessage = this.createCommitMessage(
        structuredOutput?.title || `Fix vulnerability: ${issueContext.title}`,
        structuredOutput?.description || 'Security fix applied',
        issueContext.number
      );

      const commitHash = this.createCommit(modifiedFiles, commitMessage);

      // Return GitSolutionResult (same interface!)
      return {
        success: true,
        message: `Fixed vulnerabilities in ${modifiedFiles.length} file(s)`,
        filesModified: modifiedFiles,
        commitHash,
        diffStats,
        summary: structuredOutput ? {
          title: structuredOutput.title,
          description: structuredOutput.description,
          securityImpact: structuredOutput.securityImpact || 'Security vulnerability addressed',
          tests: structuredOutput.tests || []
        } : undefined
      };

    } catch (error) {
      logger.error('Git-based solution generation failed', error as Error);
      return {
        success: false,
        message: 'Failed to generate solution',
        error: `Git-based solution generation failed: ${error instanceof Error ? error.message : String(error)}`
      };
    }
  }

  /**
   * Get the test execution log for hybrid verification
   */
  getTestLog(): TestLogEntry[] {
    return [...this.testLog];
  }

  /**
   * Get the current session ID for resume/fork operations
   */
  getSessionId(): string | undefined {
    return this.sessionId;
  }

  /**
   * Resume a previous session (Phase 3: Session forking)
   */
  async generateWithResume(
    sessionId: string,
    prompt: string,
    forkSession: boolean = false
  ): Promise<GitSolutionResult> {
    try {
      // Get API key - either vended or from environment
      const apiKey = await this.getApiKey();

      const options: Options = {
        cwd: this.repoPath,
        allowedTools: ['Read', 'Edit', 'Bash', 'Glob', 'Grep'],
        permissionMode: 'acceptEdits',
        maxTurns: this.maxTurns,
        model: this.model,
        pathToClaudeCodeExecutable: this.getClaudeCodeExecutablePath(),
        executable: 'node',
        env: this.buildEnvForSDK(apiKey),
        resume: sessionId,
        forkSession,
        canUseTool: this.createCanUseTool(),
        hooks: this.createHooks()
      };

      let structuredOutput: FixResultOutput | undefined;
      const queryGenerator: Query = query({ prompt, options });

      for await (const message of queryGenerator) {
        if (message.type === 'system' && 'subtype' in message && message.subtype === 'init') {
          this.sessionId = message.session_id;
        }

        if (message.type === 'result') {
          const resultMessage = message as SDKResultMessage;
          if ('structured_output' in resultMessage && resultMessage.structured_output) {
            structuredOutput = resultMessage.structured_output as FixResultOutput;
          }
        }
      }

      const modifiedFiles = this.getModifiedFiles();

      if (modifiedFiles.length === 0) {
        return {
          success: false,
          message: 'No files were modified in resumed session',
          error: 'SDK did not make file changes'
        };
      }

      const diffStats = this.getDiffStats();

      return {
        success: true,
        message: `Applied changes from ${forkSession ? 'forked' : 'resumed'} session`,
        filesModified: modifiedFiles,
        diffStats,
        summary: structuredOutput ? {
          title: structuredOutput.title,
          description: structuredOutput.description,
          securityImpact: structuredOutput.securityImpact || '',
          tests: structuredOutput.tests || []
        } : undefined
      };

    } catch (error) {
      logger.error('Resume session failed', error as Error);
      return {
        success: false,
        message: 'Failed to resume session',
        error: error instanceof Error ? error.message : String(error)
      };
    }
  }

  /**
   * A/B testing with session forking (Phase 3)
   *
   * Gathers context first, then forks into two parallel approaches
   */
  async generateWithABTest(
    issueContext: IssueContext,
    analysis: IssueAnalysis
  ): Promise<{ conservative: GitSolutionResult; aggressive: GitSolutionResult }> {
    // Get API key - either vended or from environment
    const apiKey = await this.getApiKey();

    // First pass: gather context
    const contextPrompt = `Analyze the codebase to understand the vulnerability:

Issue: ${issueContext.title}
${issueContext.body}

Read the relevant files and understand:
1. Where the vulnerability exists
2. What dependencies are involved
3. What tests exist

Do NOT make any changes yet.`;

    const contextOptions: Options = {
      cwd: this.repoPath,
      allowedTools: ['Read', 'Glob', 'Grep'],
      permissionMode: 'default',
      maxTurns: 2,
      model: this.model,
      pathToClaudeCodeExecutable: this.getClaudeCodeExecutablePath(),
      executable: 'node',
      env: this.buildEnvForSDK(apiKey),
    };

    const contextQuery = query({ prompt: contextPrompt, options: contextOptions });

    for await (const message of contextQuery) {
      if (message.type === 'system' && 'subtype' in message && message.subtype === 'init') {
        this.sessionId = message.session_id;
      }
    }

    if (!this.sessionId) {
      throw new Error('Failed to capture session ID for A/B testing');
    }

    // Fork A: Conservative approach
    const conservative = await this.generateWithResume(
      this.sessionId,
      'Fix the vulnerability with MINIMAL changes. Only modify what is absolutely necessary.',
      true
    );

    // Fork B: Aggressive approach (refactor for security)
    const aggressive = await this.generateWithResume(
      this.sessionId,
      'Fix the vulnerability with a thorough approach. Refactor if needed for better security.',
      true
    );

    return { conservative, aggressive };
  }

  // ============================================================
  // Legacy API Compatibility Methods (for unified-processor.ts)
  // ============================================================

  /**
   * Generate solution without git integration (legacy compatibility)
   *
   * This matches the interface of the original ClaudeCodeAdapter.generateSolution()
   * Used by solution.ts and some test files.
   */
  async generateSolution(
    issueContext: IssueContext,
    analysis: IssueAnalysis,
    _enhancedPrompt?: string
  ): Promise<GitSolutionResult> {
    // Delegate to generateSolutionWithGit but skip the git commit
    this.testLog = [];

    try {
      // Get API key - either vended or from environment
      const apiKey = await this.getApiKey();
      process.env.ANTHROPIC_API_KEY = apiKey;

      const prompt = this.buildPrompt(issueContext, analysis);

      const options: Options = {
        cwd: this.repoPath,
        allowedTools: ['Read', 'Edit', 'Bash', 'Glob', 'Grep'],
        permissionMode: 'acceptEdits',
        maxTurns: this.maxTurns,
        model: this.model,
        pathToClaudeCodeExecutable: this.getClaudeCodeExecutablePath(),
        executable: 'node',
        env: this.buildEnvForSDK(apiKey),
        outputFormat: {
          type: 'json_schema',
          schema: FixResultSchema
        },
        canUseTool: this.createCanUseTool(),
        hooks: this.createHooks()
      };

      let structuredOutput: FixResultOutput | undefined;
      const queryGenerator: Query = query({ prompt, options });

      for await (const message of queryGenerator) {
        if (message.type === 'system' && 'subtype' in message && message.subtype === 'init') {
          this.sessionId = message.session_id;
        }

        if (message.type === 'result') {
          const resultMessage = message as SDKResultMessage;
          if ('structured_output' in resultMessage && resultMessage.structured_output) {
            structuredOutput = resultMessage.structured_output as FixResultOutput;
          }
        }
      }

      const modifiedFiles = this.getModifiedFiles();

      return {
        success: modifiedFiles.length > 0,
        message: modifiedFiles.length > 0
          ? `Modified ${modifiedFiles.length} file(s)`
          : 'No files were modified',
        filesModified: modifiedFiles,
        diffStats: this.getDiffStats(),
        summary: structuredOutput ? {
          title: structuredOutput.title,
          description: structuredOutput.description,
          securityImpact: structuredOutput.securityImpact || '',
          tests: structuredOutput.tests || []
        } : undefined
      };

    } catch (error) {
      logger.error('Solution generation failed', error as Error);
      return {
        success: false,
        message: 'Failed to generate solution',
        error: error instanceof Error ? error.message : String(error)
      };
    }
  }

  /**
   * Generate solution with integrated context gathering (legacy compatibility)
   *
   * This matches the interface of SinglePassClaudeCodeAdapter.generateSolutionWithContext()
   * Used by unified-processor.ts for single-pass mode.
   */
  async generateSolutionWithContext(
    issueContext: IssueContext,
    analysis: IssueAnalysis,
    _enhancedPrompt?: string,
    _securityAnalysis?: unknown
  ): Promise<GitSolutionResult> {
    // Single-pass mode: context gathering is integrated into the prompt
    const enhancedPrompt = `${this.buildPrompt(issueContext, analysis)}

Additional context gathering instructions:
1. First explore the codebase to understand the architecture
2. Read related files and tests
3. Then apply the fix with full context

This is single-pass mode - gather context and fix in one session.`;

    try {
      // Get API key - either vended or from environment
      const apiKey = await this.getApiKey();
      process.env.ANTHROPIC_API_KEY = apiKey;

      const options: Options = {
        cwd: this.repoPath,
        allowedTools: ['Read', 'Edit', 'Bash', 'Glob', 'Grep'],
        permissionMode: 'acceptEdits',
        maxTurns: this.maxTurns + 2, // Extra turns for context gathering
        model: this.model,
        pathToClaudeCodeExecutable: this.getClaudeCodeExecutablePath(),
        executable: 'node',
        env: this.buildEnvForSDK(apiKey),
        outputFormat: {
          type: 'json_schema',
          schema: FixResultSchema
        },
        canUseTool: this.createCanUseTool(),
        hooks: this.createHooks()
      };

      let structuredOutput: FixResultOutput | undefined;
      const queryGenerator: Query = query({ prompt: enhancedPrompt, options });

      for await (const message of queryGenerator) {
        if (message.type === 'system' && 'subtype' in message && message.subtype === 'init') {
          this.sessionId = message.session_id;
        }

        if (message.type === 'result') {
          const resultMessage = message as SDKResultMessage;
          if ('structured_output' in resultMessage && resultMessage.structured_output) {
            structuredOutput = resultMessage.structured_output as FixResultOutput;
          }
        }
      }

      const modifiedFiles = this.getModifiedFiles();

      return {
        success: modifiedFiles.length > 0,
        message: modifiedFiles.length > 0
          ? `Modified ${modifiedFiles.length} file(s) with context`
          : 'No files were modified',
        filesModified: modifiedFiles,
        diffStats: this.getDiffStats(),
        summary: structuredOutput ? {
          title: structuredOutput.title,
          description: structuredOutput.description,
          securityImpact: structuredOutput.securityImpact || '',
          tests: structuredOutput.tests || []
        } : undefined
      };

    } catch (error) {
      logger.error('Solution generation with context failed', error as Error);
      return {
        success: false,
        message: 'Failed to generate solution with context',
        error: error instanceof Error ? error.message : String(error)
      };
    }
  }

  /**
   * Gather deep context about the codebase (legacy compatibility)
   *
   * This matches the interface of EnhancedClaudeCodeAdapter.gatherDeepContext()
   * Used by unified-processor.ts for enhanced context mode.
   */
  async gatherDeepContext(
    issueContext: IssueContext,
    options: {
      contextDepth?: 'shallow' | 'medium' | 'deep' | 'ultra';
      maxExplorationTime?: number;
      enableUltraThink?: boolean;
      includeArchitectureAnalysis?: boolean;
      includeTestPatterns?: boolean;
      includeStyleGuide?: boolean;
      includeDependencyAnalysis?: boolean;
    } = {}
  ): Promise<{
    files: string[];
    architecture?: string;
    testPatterns?: string;
    styleGuide?: string;
    dependencies?: string;
  }> {
    const depthInstructions = {
      shallow: 'Quick overview of directly related files only',
      medium: 'Related files and immediate dependencies',
      deep: 'Full exploration including tests and documentation',
      ultra: 'Comprehensive codebase analysis with architecture mapping'
    };

    const depth = options.contextDepth || 'medium';

    const contextPrompt = `Explore this codebase to gather context for fixing:

Issue: ${issueContext.title}
${issueContext.body}

Exploration depth: ${depth}
Instructions: ${depthInstructions[depth]}

${options.includeArchitectureAnalysis ? '- Analyze the overall architecture' : ''}
${options.includeTestPatterns ? '- Identify testing patterns and frameworks' : ''}
${options.includeStyleGuide ? '- Note code style conventions' : ''}
${options.includeDependencyAnalysis ? '- Analyze dependencies' : ''}

Use Read, Glob, and Grep to explore. Do NOT make any changes.`;

    try {
      // Get API key - either vended or from environment
      const apiKey = await this.getApiKey();
      process.env.ANTHROPIC_API_KEY = apiKey;

      const queryOptions: Options = {
        cwd: this.repoPath,
        allowedTools: ['Read', 'Glob', 'Grep'],
        permissionMode: 'default',
        maxTurns: depth === 'ultra' ? 5 : depth === 'deep' ? 4 : depth === 'medium' ? 3 : 2,
        model: this.model,
        pathToClaudeCodeExecutable: this.getClaudeCodeExecutablePath(),
        executable: 'node',
        env: this.buildEnvForSDK(apiKey),
      };

      const exploredFiles: string[] = [];
      const queryGenerator: Query = query({ prompt: contextPrompt, options: queryOptions });

      for await (const message of queryGenerator) {
        if (message.type === 'system' && 'subtype' in message && message.subtype === 'init') {
          this.sessionId = message.session_id;
        }

        // Track files that were read during exploration
        // Note: SDK message types don't include 'tool_use' directly,
        // but we can check for assistant messages with tool content
        const msgAny = message as unknown as { type: string; name?: string; input?: { file_path?: string } };
        if (msgAny.name === 'Read' && msgAny.input?.file_path) {
          exploredFiles.push(msgAny.input.file_path);
        }
      }

      return {
        files: exploredFiles,
        architecture: options.includeArchitectureAnalysis ? 'Architecture analysis gathered' : undefined,
        testPatterns: options.includeTestPatterns ? 'Test patterns identified' : undefined,
        styleGuide: options.includeStyleGuide ? 'Style conventions noted' : undefined,
        dependencies: options.includeDependencyAnalysis ? 'Dependencies analyzed' : undefined
      };

    } catch (error) {
      logger.error('Deep context gathering failed', error as Error);
      return { files: [] };
    }
  }
}

/**
 * Factory function to create the appropriate adapter based on feature flags.
 *
 * RFC-095: When `use_legacy_claude_adapter` feature flag is enabled via FunWithFlags,
 * this returns the legacy GitBasedClaudeCodeAdapter which uses the CLI directly
 * instead of the Agent SDK binary (which has Docker compatibility issues).
 *
 * The legacy adapter is proven to work in containerized environments while the
 * SDK binary has known compatibility issues (GitHub issues #20, #74, #865).
 */
export function createClaudeAgentSDKAdapter(
  config: ClaudeAgentSDKAdapterConfig
): ClaudeAgentSDKAdapter | GitBasedClaudeCodeAdapter {
  // RFC-095: Environment variable overrides for testing and emergency fallback
  // These override the feature flag from the platform
  const forceSDK = process.env.RSOLV_FORCE_SDK_ADAPTER === 'true';
  const forceLegacy = process.env.RSOLV_FORCE_LEGACY_ADAPTER === 'true';

  if (forceSDK) {
    logger.info('[SDK Factory] RSOLV_FORCE_SDK_ADAPTER=true: forcing ClaudeAgentSDKAdapter');
    return new ClaudeAgentSDKAdapter(config);
  }

  if (forceLegacy) {
    logger.info('[SDK Factory] RSOLV_FORCE_LEGACY_ADAPTER=true: forcing legacy adapter');
    const legacyConfig: AIConfig = {
      provider: 'anthropic',
      model: config.model || 'claude-sonnet-4-5-20250929',
      useVendedCredentials: config.useVendedCredentials,
      useStructuredPhases: true,
      claudeCodeConfig: { verboseLogging: config.verbose }
    };
    return new GitBasedClaudeCodeAdapter(legacyConfig, config.repoPath, config.credentialManager);
  }

  // RFC-095: Check feature flag for legacy adapter fallback
  const useLegacy = config.credentialManager?.shouldUseLegacyAdapter?.() ?? false;

  if (useLegacy) {
    logger.info('[SDK Factory] Feature flag enabled: using legacy GitBasedClaudeCodeAdapter');

    // Convert config to AIConfig format for legacy adapter
    const legacyConfig: AIConfig = {
      provider: 'anthropic',
      model: config.model || 'claude-sonnet-4-5-20250929',
      useVendedCredentials: config.useVendedCredentials,
      useStructuredPhases: true, // Legacy adapter uses structured phases
      claudeCodeConfig: {
        verboseLogging: config.verbose
      }
    };

    return new GitBasedClaudeCodeAdapter(
      legacyConfig,
      config.repoPath,
      config.credentialManager
    );
  }

  logger.info('[SDK Factory] Using ClaudeAgentSDKAdapter (new unified adapter)');
  return new ClaudeAgentSDKAdapter(config);
}

export default ClaudeAgentSDKAdapter;
