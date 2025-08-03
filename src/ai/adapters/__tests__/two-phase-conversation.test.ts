/**
 * RED Phase: Test for two-phase conversation approach
 * Tests that Claude Code SDK can:
 * 1. Edit files in first phase
 * 2. Provide JSON summary in second phase
 */

import { describe, it, expect, beforeEach, jest } from '@jest/globals';
import { GitBasedClaudeCodeAdapter } from '../claude-code-git.js';
import type { IssueContext, IssueAnalysis } from '../../../types/index.js';
import * as fs from 'fs/promises';
import * as path from 'path';
import { execSync } from 'child_process';

describe('Two-Phase Claude Code Conversation', () => {
  let adapter: GitBasedClaudeCodeAdapter;
  let mockIssueContext: IssueContext;
  let mockAnalysis: IssueAnalysis;
  const testRepoPath = '/tmp/test-two-phase';

  beforeEach(async () => {
    // Setup test repository
    await fs.rm(testRepoPath, { recursive: true, force: true });
    await fs.mkdir(testRepoPath, { recursive: true });
    
    // Initialize git repo
    execSync('git init', { cwd: testRepoPath });
    execSync('git config user.email "test@example.com"', { cwd: testRepoPath });
    execSync('git config user.name "Test User"', { cwd: testRepoPath });
    
    // Create vulnerable file
    const vulnerableCode = `
function processInput(userInput) {
  // XSS vulnerability
  document.write(userInput);
}
    `;
    await fs.writeFile(path.join(testRepoPath, 'vulnerable.js'), vulnerableCode);
    execSync('git add . && git commit -m "Initial commit"', { cwd: testRepoPath });

    // Initialize adapter
    adapter = new GitBasedClaudeCodeAdapter(
      {
        apiKey: process.env.ANTHROPIC_API_KEY || 'test-key',
        baseUrl: 'https://api.anthropic.com',
        model: 'claude-3-opus-20240229',
        maxTokens: 4096,
        temperature: 0.1,
        claudeCodeConfig: {
          verboseLogging: true,
          useTwoPhaseApproach: true // New config option
        }
      },
      testRepoPath
    );

    mockIssueContext = {
      number: 1,
      title: 'XSS vulnerability in processInput',
      body: 'document.write with user input can lead to XSS',
      owner: 'test',
      repo: 'test-repo'
    };

    mockAnalysis = {
      complexity: 'simple',
      estimatedTime: 5,
      relatedFiles: ['vulnerable.js'],
      canBeAutomated: true,
      suggestedApproach: 'Escape the user input before writing to document'
    };
  });

  describe('RED Phase - Current Single-Phase Failures', () => {
    it('should fail with single-phase approach (files not edited)', async () => {
      // Mock single-phase behavior
      const singlePhaseAdapter = new GitBasedClaudeCodeAdapter(
        {
          apiKey: process.env.ANTHROPIC_API_KEY || 'test-key',
          baseUrl: 'https://api.anthropic.com',
          model: 'claude-3-opus-20240229',
          maxTokens: 4096,
          temperature: 0.1,
          claudeCodeConfig: {
            useTwoPhaseApproach: false // Use old approach
          }
        },
        testRepoPath
      );

      const result = await singlePhaseAdapter.generateSolutionWithGit(
        mockIssueContext,
        mockAnalysis
      );

      // This should fail with current implementation
      expect(result.success).toBe(false);
      expect(result.message).toContain('No files were modified');
    });
  });

  describe('GREEN Phase - Two-Phase Solution', () => {
    it('should successfully edit files then provide JSON with two-phase approach', async () => {
      const result = await adapter.generateSolutionWithTwoPhases(
        mockIssueContext,
        mockAnalysis
      );

      // Phase 1: Files should be modified
      expect(result.filesModified).toBeDefined();
      expect(result.filesModified.length).toBeGreaterThan(0);
      
      // Phase 2: JSON summary should be provided
      expect(result.success).toBe(true);
      expect(result.summary).toBeDefined();
      expect(result.summary.title).toBeDefined();
      expect(result.summary.description).toBeDefined();
      expect(result.summary.files).toBeDefined();
      
      // Verify actual file was modified
      const modifiedContent = await fs.readFile(
        path.join(testRepoPath, 'vulnerable.js'),
        'utf-8'
      );
      expect(modifiedContent).not.toContain('document.write(userInput)');
    });

    it('should handle conversation flow correctly', async () => {
      // Spy on the query function to verify two-phase flow
      const querySpy = jest.spyOn(adapter as any, 'executeClaudeQuery');
      
      const result = await adapter.generateSolutionWithTwoPhases(
        mockIssueContext,
        mockAnalysis
      );

      // Should have two distinct phases
      expect(querySpy).toHaveBeenCalledTimes(2);
      
      // First call should be for editing
      const firstCallPrompt = querySpy.mock.calls[0][0];
      expect(firstCallPrompt).toContain('Edit');
      expect(firstCallPrompt).toContain('MultiEdit');
      expect(firstCallPrompt).not.toContain('JSON');
      
      // Second call should be for JSON summary
      const secondCallPrompt = querySpy.mock.calls[1][0];
      expect(secondCallPrompt).toContain('JSON');
      expect(secondCallPrompt).toContain('summary');
    });
  });

  describe('REFACTOR Phase - Optimized Implementation', () => {
    it('should use clean separation of concerns', () => {
      // Test that the adapter has clean methods
      expect(adapter).toHaveProperty('generateSolutionWithTwoPhases');
      expect(adapter).toHaveProperty('executePhaseOne');
      expect(adapter).toHaveProperty('executePhaseTwo');
    });

    it('should handle phase failures gracefully', async () => {
      // Mock phase 1 failure (no files edited)
      jest.spyOn(adapter as any, 'getModifiedFiles').mockReturnValue([]);
      
      const result = await adapter.generateSolutionWithTwoPhases(
        mockIssueContext,
        mockAnalysis
      );

      // Should fail gracefully without attempting phase 2
      expect(result.success).toBe(false);
      expect(result.error).toContain('Phase 1 failed');
    });

    it('should maintain conversation context between phases', async () => {
      const result = await adapter.generateSolutionWithTwoPhases(
        mockIssueContext,
        mockAnalysis
      );

      // JSON summary should reference the actual files that were edited
      expect(result.summary.files).toEqual(
        expect.arrayContaining([
          expect.objectContaining({
            path: 'vulnerable.js'
          })
        ])
      );
    });

    it('should complete within reasonable time', async () => {
      const startTime = Date.now();
      
      await adapter.generateSolutionWithTwoPhases(
        mockIssueContext,
        mockAnalysis
      );
      
      const duration = Date.now() - startTime;
      // Should complete within 5 minutes (300000ms)
      expect(duration).toBeLessThan(300000);
    });
  });

  describe('Integration Tests', () => {
    it('should work with real Claude Code SDK', async () => {
      // Skip in CI without real API key
      if (!process.env.ANTHROPIC_API_KEY) {
        return expect(true).toBe(true);
      }

      const result = await adapter.generateSolutionWithTwoPhases(
        mockIssueContext,
        mockAnalysis
      );

      // Full integration test with real Claude
      expect(result.success).toBe(true);
      expect(result.filesModified).toContain('vulnerable.js');
      expect(result.commitHash).toBeDefined();
      expect(result.summary.tests).toBeDefined();
      expect(result.summary.tests.length).toBeGreaterThan(0);
    });
  });
});