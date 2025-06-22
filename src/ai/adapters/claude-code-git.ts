/**
 * Git-based Claude Code adapter that makes direct file edits
 * and commits them to create clean, reviewable PRs
 */
import { ClaudeCodeAdapter } from './claude-code.js';
import { IssueContext } from '../../types/index.js';
import { AIConfig } from '../types.js';
import { IssueAnalysis } from '../types.js';
import { logger } from '../../utils/logger.js';
import { execSync } from 'child_process';
import path from 'path';

/**
 * Result from git-based solution generation
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
}

/**
 * Claude Code adapter that uses git for change tracking
 */
export class GitBasedClaudeCodeAdapter extends ClaudeCodeAdapter {
  constructor(config: AIConfig, repoPath: string = process.cwd(), credentialManager?: any) {
    super(config, repoPath, credentialManager);
  }

  /**
   * Construct the prompt for git-based editing
   */
  protected constructPrompt(
    issueContext: IssueContext,
    analysis: IssueAnalysis,
    enhancedPrompt?: string
  ): string {
    if (enhancedPrompt) {
      return enhancedPrompt;
    }
    
    return `You are an expert security engineer fixing vulnerabilities by directly editing files in a git repository. You have access to file editing tools and will make changes that will be committed to git.

## Issue Details:
- **Title**: ${issueContext.title}
- **Description**: ${issueContext.body}
- **Complexity**: ${analysis.complexity}
- **Files with vulnerabilities**: ${analysis.relatedFiles?.join(', ') || 'To be discovered'}

## Your Task:

### Phase 1: Locate Vulnerabilities
- Use Grep to find vulnerable code patterns
- Use Read to understand the full context
- Identify all instances that need fixing

### Phase 2: Fix Vulnerabilities In-Place
**IMPORTANT**: Use the Edit or MultiEdit tools to directly modify the vulnerable files.
- Make minimal, surgical changes to fix security issues
- Preserve all non-vulnerable functionality
- Maintain existing code style and formatting
- Fix all instances of the vulnerability

### Phase 3: Verify Your Changes
- Use Read to verify your edits were applied correctly
- Ensure the code still makes sense and will function properly
- Check that you haven't introduced syntax errors

### Phase 4: Provide Fix Summary
After completing your edits, provide a summary in this JSON format:

\`\`\`json
{
  "title": "Fix [vulnerability type] in [component]",
  "description": "Clear explanation of what was vulnerable and how you fixed it",
  "vulnerabilityDetails": {
    "type": "e.g., SQL Injection, XSS, etc.",
    "severity": "LOW|MEDIUM|HIGH|CRITICAL",
    "cwe": "CWE-XX identifier if applicable"
  },
  "filesModified": [
    {
      "path": "path/to/file.js",
      "changesDescription": "Replaced string concatenation with parameterized queries",
      "linesModified": [45, 67, 89]
    }
  ],
  "securityImpact": "Explanation of how this improves security",
  "testingGuidance": [
    "Test that normal functionality still works",
    "Verify malicious inputs are now handled safely"
  ],
  "breakingChanges": false,
  "additionalNotes": "Any other relevant information"
}
\`\`\`

## Critical Instructions:
1. **Use Edit/MultiEdit tools** - Do NOT provide file contents in JSON
2. **Edit existing files only** - Do NOT create new files
3. **Make minimal changes** - Only fix the security issue
4. **Preserve functionality** - The code must still work correctly
5. **Fix all instances** - Don't leave any vulnerabilities unfixed

Your changes will be committed to git, so make them production-ready!`;
  }

  /**
   * Generate solution using git-based approach
   */
  async generateSolutionWithGit(
    issueContext: IssueContext,
    analysis: IssueAnalysis,
    enhancedPrompt?: string
  ): Promise<GitSolutionResult> {
    const startTime = Date.now();
    
    try {
      // Record initial git state
      const initialFiles = this.getModifiedFiles();
      if (initialFiles.length > 0) {
        logger.warn(`Repository has uncommitted changes: ${initialFiles.join(', ')}`);
      }
      
      // Execute Claude Code to make edits
      logger.info('Executing Claude Code to fix vulnerabilities in-place...');
      const result = await super.generateSolution(issueContext, analysis, enhancedPrompt);
      
      if (!result.success) {
        return {
          success: false,
          message: result.message,
          error: result.error
        };
      }
      
      // Check what files were modified
      const modifiedFiles = this.getModifiedFiles();
      if (modifiedFiles.length === 0) {
        return {
          success: false,
          message: 'No files were modified',
          error: 'Claude Code did not make any file changes. The vulnerability may not exist or could not be located.'
        };
      }
      
      logger.info(`Files modified by Claude Code: ${modifiedFiles.join(', ')}`);
      
      // Get diff statistics
      const diffStats = this.getDiffStats();
      
      // Extract summary from Claude's response
      let summary;
      if (result.changes) {
        // Check if we have a 'summary' key in changes
        if (result.changes['summary']) {
          try {
            summary = JSON.parse(result.changes['summary']);
          } catch (e) {
            logger.warn('Failed to parse summary JSON', e);
          }
        }
        
        // Fallback: try to extract from any change value
        if (!summary && Object.keys(result.changes).length > 0) {
          const firstChange = Object.values(result.changes)[0];
          if (typeof firstChange === 'string' && firstChange.includes('{')) {
            try {
              summary = JSON.parse(firstChange);
            } catch (e) {
              // Not JSON, use as description
              summary = {
                title: `Fix security vulnerability in ${modifiedFiles[0]}`,
                description: firstChange
              };
            }
          }
        }
      }
      
      // Create a meaningful commit
      const commitMessage = this.createCommitMessage(
        summary?.title || `Fix security vulnerability in ${issueContext.title}`,
        summary?.description || result.message || 'Applied security fixes',
        issueContext.number
      );
      
      const commitHash = this.createCommit(modifiedFiles, commitMessage);
      
      return {
        success: true,
        message: `Successfully fixed vulnerabilities in ${modifiedFiles.length} file(s)`,
        filesModified: modifiedFiles,
        commitHash,
        diffStats,
        summary: summary ? {
          title: summary.title,
          description: summary.description,
          securityImpact: summary.securityImpact || 'Vulnerabilities have been patched',
          tests: summary.testingGuidance || summary.tests || []
        } : {
          title: `Fix security vulnerability: ${issueContext.title}`,
          description: result.message || 'Security vulnerabilities fixed',
          securityImpact: 'Vulnerabilities have been patched',
          tests: []
        }
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
   * Get list of modified files using git
   */
  private getModifiedFiles(): string[] {
    try {
      const output = execSync('git diff --name-only', {
        cwd: this.repoPath,
        encoding: 'utf-8'
      }).trim();
      
      return output ? output.split('\n') : [];
    } catch (error) {
      logger.error('Failed to get modified files', error as Error);
      return [];
    }
  }
  
  /**
   * Get diff statistics
   */
  private getDiffStats(): GitSolutionResult['diffStats'] {
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
  private createCommit(files: string[], message: string): string {
    try {
      // Stage the modified files
      execSync(`git add ${files.join(' ')}`, {
        cwd: this.repoPath
      });
      
      // Create the commit
      execSync(`git commit -m "${message.replace(/"/g, '\\"')}"`, {
        cwd: this.repoPath
      });
      
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
  private createCommitMessage(title: string, description: string, issueNumber: number): string {
    return `${title}

${description}

Fixes #${issueNumber}

This commit was automatically generated by RSOLV to fix security vulnerabilities.`;
  }
}