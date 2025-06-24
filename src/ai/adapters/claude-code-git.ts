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
import type { AnalysisWithTestsResult } from '../test-generating-security-analyzer.js';
import type { ValidationResult } from '../git-based-test-validator.js';

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

### Phase 1: Locate Vulnerabilities & Check Tests
- Use Grep to find vulnerable code patterns
- Use Read to understand the full context
- Search for existing tests that exercise the vulnerable code
- Identify how the vulnerable code is used (callbacks, promises, etc.)
- Consider using sequential thinking for complex vulnerability analysis

### Phase 2: Red-Green-Refactor Validation
**CRITICAL**: Before fixing, validate the vulnerability exists:
- If tests exist: Run them to establish baseline
- Create or identify a test that demonstrates the vulnerability
- Ensure this test would FAIL on vulnerable code (RED phase)
- Document what malicious input would exploit the vulnerability

### Phase 3: Fix Vulnerabilities In-Place with Compatibility
**IMPORTANT**: Use the Edit or MultiEdit tools to directly modify the vulnerable files.
- Make minimal, surgical changes to fix security issues
- **PRESERVE API COMPATIBILITY**: 
  - If code uses callbacks, maintain callback interface
  - If changing from callbacks to async/await, add compatibility wrapper
  - Never break existing function signatures
- Maintain existing code style and formatting
- Fix all instances of the vulnerability

Example compatibility wrapper for callback to async conversion:
\`\`\`javascript
// Original method for compatibility
methodName(param1, param2, callback) {
  if (typeof callback === 'function') {
    // Callback style
    this.methodNameAsync(param1, param2)
      .then(result => callback(null, result))
      .catch(error => callback(error));
  } else {
    // Promise style
    return this.methodNameAsync(param1, param2);
  }
}

// New async implementation
async methodNameAsync(param1, param2) {
  // Secure implementation here
}
\`\`\`

### Phase 4: Verify Your Changes (GREEN phase)
- Use Read to verify your edits were applied correctly
- Ensure the code still makes sense and will function properly
- Verify the test that demonstrated the vulnerability now PASSES
- Check that legitimate use cases still work
- Ensure no breaking changes to public APIs

### Phase 5: Provide Fix Summary
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
  "compatibilityNotes": {
    "apiChanged": false,
    "backwardCompatible": true,
    "compatibilityMeasures": "Added wrapper to maintain callback interface while using async internally"
  },
  "validationResults": {
    "vulnerabilityDemonstrated": "Showed that input '; DROP TABLE; -- would execute",
    "testCreated": true,
    "testPasses": true
  },
  "securityImpact": "Explanation of how this improves security",
  "testingGuidance": [
    "Test that normal functionality still works",
    "Verify malicious inputs are now handled safely",
    "Run existing test suite to ensure no regressions"
  ],
  "breakingChanges": false,
  "additionalNotes": "Any other relevant information"
}
\`\`\`

## Critical Instructions:
1. **Use Edit/MultiEdit tools** - Do NOT provide file contents in JSON
2. **Edit existing files only** - Do NOT create new files unless absolutely necessary (e.g., missing security config file)  
3. **Make minimal changes** - Only fix the security issue
4. **Preserve functionality** - The code must still work correctly
5. **Maintain compatibility** - NEVER break existing APIs or interfaces
6. **Validate the fix** - Demonstrate vulnerability exists and is fixed
7. **Fix all instances** - Don't leave any vulnerabilities unfixed
8. **Use relative paths** - Use paths like 'app/data/file.js' not '/app/data/file.js'

Your changes will be committed to git, so make them production-ready!`;
  }
  
  /**
   * Construct prompt with test validation context
   */
  protected constructPromptWithTestContext(
    issueContext: IssueContext,
    analysis: IssueAnalysis,
    testResults?: AnalysisWithTestsResult,
    validationResult?: ValidationResult,
    iteration?: { current: number; max: number }
  ): string {
    let prompt = this.constructPrompt(issueContext, analysis);
    
    // Add test validation context
    if (testResults?.generatedTests?.success) {
      prompt += '\n\n## Generated Tests\n';
      prompt += 'The following tests have been generated to validate your fix:\n\n';
      testResults.generatedTests.tests.forEach(test => {
        prompt += `### ${test.framework} Test\n`;
        prompt += '```' + (test.framework === 'rspec' ? 'ruby' : 'javascript') + '\n';
        prompt += test.testCode;
        prompt += '\n```\n\n';
      });
      prompt += '**IMPORTANT**: Your fix must make these tests pass!\n';
      prompt += '- RED test should fail before your fix\n';
      prompt += '- GREEN test should pass after your fix\n';
      prompt += '- REFACTOR test should ensure functionality is maintained\n';
    }
    
    // Add validation failure context
    if (validationResult && !validationResult.success) {
      prompt += '\n\n## Previous Fix Attempt Failed\n';
      prompt += `This is attempt ${iteration?.current || 2} of ${iteration?.max || 3}.\n\n`;
      prompt += '### Test Results:\n';
      prompt += '```\n';
      prompt += `Vulnerable commit - Red test: ${validationResult.vulnerableCommit.redTestPassed ? 'PASSED' : 'FAILED'}\n`;
      prompt += `Fixed commit - Red test: ${validationResult.fixedCommit.redTestPassed ? 'PASSED' : 'FAILED'}\n`;
      prompt += `Fixed commit - Green test: ${validationResult.fixedCommit.greenTestPassed ? 'PASSED' : 'FAILED'}\n`;
      prompt += `Fixed commit - Refactor test: ${validationResult.fixedCommit.refactorTestPassed ? 'PASSED' : 'FAILED'}\n`;
      prompt += '\n```\n\n';
      
      if (!validationResult.fixedCommit.redTestPassed) {
        prompt += '- The vulnerability still exists (RED test failed)\n';
      }
      if (!validationResult.fixedCommit.greenTestPassed) {
        prompt += '- The fix was not properly applied (GREEN test failed)\n';
      }
      if (!validationResult.fixedCommit.refactorTestPassed) {
        prompt += '- The fix broke existing functionality (REFACTOR test failed)\n';
      }
      
      prompt += '**Please analyze the test failures and try a different approach.**\n';
      prompt += 'Consider:\n';
      prompt += '- Are you handling all edge cases?\n';
      prompt += '- Is the fix too restrictive or breaking functionality?\n';
      prompt += '- Do you need to adjust the implementation strategy?\n';
    }
    
    // Add iteration context
    if (iteration) {
      prompt += `\n\n## Iteration Context\n`;
      prompt += `You have ${iteration.max - iteration.current} attempts remaining.\n`;
      if (iteration.current === iteration.max) {
        prompt += '**This is your final attempt.** Ensure the fix is comprehensive.\n';
      }
    }
    
    // Add test running instructions
    prompt += '\n\n## Test Validation Instructions\n';
    prompt += '1. After implementing your fix, explain how to run the tests\n';
    prompt += '2. Specify which test framework is being used\n';
    prompt += '3. Include the test command (e.g., `bundle exec rspec` or `npm test`)\n';
    prompt += '4. Ensure all security tests pass before considering the fix complete\n';
    
    return prompt;
  }

  /**
   * Generate solution using git-based approach
   */
  async generateSolutionWithGit(
    issueContext: IssueContext,
    analysis: IssueAnalysis,
    enhancedPrompt?: string,
    testResults?: AnalysisWithTestsResult,
    validationResult?: ValidationResult,
    iteration?: { current: number; max: number }
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
      
      // Use enhanced prompt with test context if available
      const promptToUse = (testResults || validationResult || iteration) 
        ? this.constructPromptWithTestContext(issueContext, analysis, testResults, validationResult, iteration)
        : enhancedPrompt;
      
      const result = await super.generateSolution(issueContext, analysis, promptToUse);
      
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