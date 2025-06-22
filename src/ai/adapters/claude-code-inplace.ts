/**
 * Enhanced Claude Code adapter with in-place editing capabilities
 * This adapter ensures vulnerabilities are fixed by editing existing files
 * rather than creating new ones, making fixes immediately usable.
 */
import { ClaudeCodeAdapter } from './claude-code.js';
import { IssueContext } from '../../types/index.js';
import { AIConfig } from '../types.js';
import { IssueAnalysis } from '../types.js';
import { logger } from '../../utils/logger.js';

/**
 * Claude Code adapter optimized for in-place vulnerability fixes
 */
export class InPlaceClaudeCodeAdapter extends ClaudeCodeAdapter {
  constructor(config: AIConfig, repoPath: string = process.cwd(), credentialManager?: any) {
    super(config, repoPath, credentialManager);
  }

  /**
   * Construct the prompt for in-place editing
   */
  protected constructPrompt(
    issueContext: IssueContext,
    analysis: IssueAnalysis,
    enhancedPrompt?: string
  ): string {
    if (enhancedPrompt) {
      return enhancedPrompt;
    }
    
    return `You are an expert security engineer tasked with fixing vulnerabilities in existing code. Your goal is to make minimal, surgical changes that resolve security issues while preserving the existing code structure and functionality.

## Issue Details:
- **Title**: ${issueContext.title}
- **Description**: ${issueContext.body}
- **Complexity**: ${analysis.complexity}
- **Estimated Time**: ${analysis.estimatedTime} minutes
- **Files to Fix**: ${analysis.relatedFiles?.join(', ') || 'To be discovered'}

## Your Task:

### Phase 1: Locate the Vulnerability
First, find and examine the vulnerable code:
- Use Grep to search for the vulnerable patterns mentioned in the issue
- Use Read to examine the full context of vulnerable files
- Understand the existing code structure and conventions

### Phase 2: Plan Minimal Changes
Identify the smallest possible changes needed:
- Focus only on the vulnerable code sections
- Preserve all non-vulnerable functionality
- Maintain the existing code style and patterns
- Keep the same file structure and organization

### Phase 3: Apply In-Place Fixes
Use the Edit or MultiEdit tools to fix vulnerabilities:
- **IMPORTANT**: Edit existing files, do NOT create new files
- Make surgical changes to vulnerable lines only
- Add necessary imports if required
- Preserve all other code exactly as it is

### Phase 4: Generate Solution Summary
After making your edits, provide a JSON summary of what you changed:

\`\`\`json
{
  "title": "Brief title for the PR (e.g., 'Fix SQL injection in user search')",
  "description": "Detailed explanation of the vulnerability and the fix applied",
  "files_edited": [
    {
      "path": "exact/path/to/edited/file.js",
      "changes_summary": "Brief description of what was changed in this file",
      "vulnerable_lines": [73, 78],
      "fix_type": "parameterized_query"
    }
  ],
  "security_impact": "Explanation of how this fix improves security",
  "tests": [
    "Test case to verify the vulnerability is fixed",
    "Test case to ensure functionality still works"
  ]
}
\`\`\`

## Critical Requirements:
1. **Edit in place** - Modify existing files using Edit/MultiEdit tools
2. **Minimal changes** - Only change what's necessary to fix the vulnerability
3. **Preserve functionality** - Ensure the code still works exactly as before
4. **Match code style** - Follow the existing file's conventions
5. **No new files** - All fixes must be applied to existing vulnerable files

Remember: The best security fix is one that can be immediately merged with no additional integration work required.`;
  }

  /**
   * Override generateSolution to ensure in-place editing
   */
  async generateSolution(
    issueContext: IssueContext,
    analysis: IssueAnalysis,
    enhancedPrompt?: string
  ): Promise<{ success: boolean; message: string; changes?: Record<string, string>; error?: string }> {
    logger.info(`Generating in-place fix for issue: ${issueContext.id}`);
    
    // Call parent generateSolution with our specialized prompt
    const result = await super.generateSolution(issueContext, analysis, enhancedPrompt);
    
    if (result.success && result.changes) {
      // Log which files were edited vs created
      const fileCount = Object.keys(result.changes).length;
      logger.info(`In-place fix completed: ${fileCount} file(s) edited`);
    }
    
    return result;
  }

  /**
   * Extract solution from Claude's response
   * For in-place editing, we expect a summary since actual edits are done via tools
   */
  protected extractSolutionFromText(text: string): any {
    try {
      // Look for our specific JSON format
      const jsonMatch = text.match(/```(?:json)?\s*([\s\S]*?)\s*```/);
      if (jsonMatch) {
        const data = JSON.parse(jsonMatch[1]);
        
        // Convert summary format to expected format
        if (data.files_edited && Array.isArray(data.files_edited)) {
          return {
            title: data.title,
            description: data.description,
            files: data.files_edited.map((f: any) => ({
              path: f.path,
              changes: f.changes_summary || `Fixed vulnerability on lines ${f.vulnerable_lines?.join(', ')}`
            })),
            tests: data.tests || []
          };
        }
      }
    } catch (error) {
      logger.debug('Could not extract in-place edit summary from text');
    }
    
    // Fall back to parent implementation
    return super.extractSolutionFromText(text);
  }
}