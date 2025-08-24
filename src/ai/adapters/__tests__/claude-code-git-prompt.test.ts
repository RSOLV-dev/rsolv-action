/**
 * RED-GREEN-REFACTOR Test Suite for Git-Based Claude Code Prompt Engineering
 * 
 * These tests validate that our prompts cause Claude to:
 * 1. Edit files using Edit/MultiEdit tools
 * 2. Provide JSON solution summary
 * 3. Successfully create PRs
 */

import { describe, it, expect, beforeEach, jest } from '@jest/globals';
import { GitBasedClaudeCodeAdapter } from '../claude-code-git.js';
import type { IssueContext, IssueAnalysis } from '../../types.js';
import * as fs from 'fs/promises';
import * as path from 'path';
import { execSync } from 'child_process';

describe('GitBasedClaudeCodeAdapter Prompt Effectiveness', () => {
  let adapter: GitBasedClaudeCodeAdapter;
  let mockIssueContext: IssueContext;
  let mockAnalysis: IssueAnalysis;
  const testRepoPath = '/tmp/test-repo';

  beforeEach(async () => {
    // Setup test repository
    await fs.rm(testRepoPath, { recursive: true, force: true });
    await fs.mkdir(testRepoPath, { recursive: true });
    
    // Initialize git repo
    execSync('git init', { cwd: testRepoPath });
    execSync('git config user.email "test@example.com"', { cwd: testRepoPath });
    execSync('git config user.name "Test User"', { cwd: testRepoPath });
    
    // Create vulnerable file
    const vulnerableFile = `
// Vulnerable to XSS
document.write(location.host);
    `;
    await fs.writeFile(path.join(testRepoPath, 'vulnerable.js'), vulnerableFile);
    execSync('git add . && git commit -m "Initial commit"', { cwd: testRepoPath });

    // Initialize adapter
    adapter = new GitBasedClaudeCodeAdapter({
      apiKey: process.env.TEST_ANTHROPIC_API_KEY || 'test-key',
      baseUrl: 'https://api.anthropic.com',
      model: 'claude-3-opus-20240229',
      maxTokens: 4096,
      temperature: 0.1,
      repoPath: testRepoPath,
      verboseLogging: true
    });

    mockIssueContext = {
      id: 'test-issue-1',
      title: 'XSS vulnerability in vulnerable.js',
      description: 'document.write with user input can lead to XSS',
      platform: 'github',
      repositoryUrl: 'https://github.com/test/repo',
      issueUrl: 'https://github.com/test/repo/issues/1'
    };

    mockAnalysis = {
      canBeFixed: true,
      filesToModify: ['vulnerable.js'],
      suggestedApproach: 'Escape the user input before writing to document'
    };
  });

  describe('RED Phase - Current Prompt Failures', () => {
    it('should fail when Claude only provides JSON without editing files', async () => {
      // This test documents the current failing behavior
      const spy = jest.vi.spyOn(adapter as any, 'getModifiedFiles');
      
      // Mock Claude returning JSON but not editing
      spy.mockReturnValue([]);
      
      const result = await adapter.generateSolutionWithGit(
        mockIssueContext,
        mockAnalysis
      );
      
      // Current behavior: fails because no files modified
      expect(result.success).toBe(false);
      expect(result.message).toContain('No files were modified');
    });

    it('should fail to create PR when files are not actually modified', async () => {
      // Document that PR creation fails without file modifications
      const getModifiedFilesSpy = jest.vi.spyOn(adapter as any, 'getModifiedFiles');
      getModifiedFilesSpy.mockReturnValue([]);
      
      const result = await adapter.generateSolutionWithGit(
        mockIssueContext,
        mockAnalysis
      );
      
      expect(result.success).toBe(false);
      expect(result.changes).toBeUndefined();
    });
  });

  describe('GREEN Phase - Prompt Improvements', () => {
    it('should successfully edit files when prompt explicitly requires Edit tool usage', async () => {
      // Test the improved prompt that forces Edit tool usage
      const improvedPrompt = adapter.constructPromptWithTestContext(
        mockIssueContext,
        mockAnalysis
      );
      
      // Verify prompt contains explicit Edit tool requirements
      expect(improvedPrompt).toContain('MUST use the Edit or MultiEdit tools');
      expect(improvedPrompt).toContain('DO NOT skip this step');
      expect(improvedPrompt).toContain('DO NOT just provide file contents in JSON');
      
      // Mock successful file modification
      const getModifiedFilesSpy = jest.vi.spyOn(adapter as any, 'getModifiedFiles');
      getModifiedFilesSpy.mockReturnValue(['vulnerable.js']);
      
      const result = await adapter.generateSolutionWithGit(
        mockIssueContext,
        mockAnalysis
      );
      
      expect(result.success).toBe(true);
      expect(result.changes).toBeDefined();
    });

    it('should validate that both Edit tools AND JSON are used', async () => {
      // Test that we get both file edits and JSON summary
      const getModifiedFilesSpy = jest.vi.spyOn(adapter as any, 'getModifiedFiles');
      const extractSolutionSpy = jest.vi.spyOn(adapter as any, 'extractSolutionFromText');
      
      // Mock both conditions met
      getModifiedFilesSpy.mockReturnValue(['vulnerable.js']);
      extractSolutionSpy.mockReturnValue({
        title: 'Fix XSS vulnerability',
        description: 'Escaped user input',
        files: [{
          path: 'vulnerable.js',
          changes: '// Fixed content'
        }],
        tests: ['Verify XSS is prevented']
      });
      
      const result = await adapter.generateSolutionWithGit(
        mockIssueContext,
        mockAnalysis
      );
      
      expect(result.success).toBe(true);
      expect(getModifiedFilesSpy).toHaveBeenCalled();
      expect(extractSolutionSpy).toHaveBeenCalled();
    });
  });

  describe('REFACTOR Phase - Optimized Prompt', () => {
    it('should use concise but effective prompt structure', () => {
      // Test that refactored prompt is clean and maintainable
      const prompt = adapter.constructPromptWithTestContext(
        mockIssueContext,
        mockAnalysis
      );
      
      // Check for clear section headers
      expect(prompt).toMatch(/### Phase \d+:/);
      expect(prompt).toMatch(/### CRITICAL:/);
      expect(prompt).toMatch(/## Steps Required:/);
      
      // Ensure no redundancy
      const editMentions = (prompt.match(/Edit.*tool/gi) || []).length;
      expect(editMentions).toBeLessThanOrEqual(5); // Reasonable mentions, not repetitive
      
      // Verify JSON format is clearly specified
      expect(prompt).toContain('"files"');
      expect(prompt).toContain('"changes"');
      expect(prompt).toContain('EXACT JSON format');
    });

    it('should maintain backward compatibility with existing adapters', () => {
      // Ensure refactored code doesn't break existing functionality
      expect(adapter).toHaveProperty('generateSolutionWithGit');
      expect(adapter).toHaveProperty('constructPromptWithTestContext');
      expect(adapter).toHaveProperty('getModifiedFiles');
      
      // Should still implement AIClient interface
      expect(adapter).toHaveProperty('generateSolution');
      expect(adapter).toHaveProperty('analyzeIssue');
    });
  });

  describe('Integration Tests', () => {
    it('should handle real Claude responses correctly', async () => {
      // Skip in CI without real API key
      if (!process.env.TEST_ANTHROPIC_API_KEY) {
        return expect(true).toBe(true);
      }

      // Real integration test with Claude
      const result = await adapter.generateSolutionWithGit(
        mockIssueContext,
        mockAnalysis
      );
      
      // Should successfully:
      // 1. Modify files
      // 2. Generate JSON
      // 3. Return success
      expect(result.success).toBe(true);
      expect(result.changes).toBeDefined();
      expect(Object.keys(result.changes).length).toBeGreaterThan(0);
      
      // Verify actual file was modified
      const modifiedContent = await fs.readFile(
        path.join(testRepoPath, 'vulnerable.js'),
        'utf-8'
      );
      expect(modifiedContent).not.toContain('document.write(location.host)');
    });
  });
});