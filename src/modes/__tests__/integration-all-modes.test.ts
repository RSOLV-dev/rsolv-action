/**
 * Integration tests for all three phases working together
 * Tests the full pipeline: SCAN → VALIDATE → MITIGATE
 */

import { describe, test, expect, beforeEach, afterEach, mock } from 'bun:test';
import { PhaseExecutor } from '../phase-executor/index.js';
import { IssueContext, ActionConfig } from '../../types/index.js';
import fs from 'fs/promises';
import path from 'path';

describe('Three-Phase Integration', () => {
  let executor: PhaseExecutor;
  let mockConfig: ActionConfig;
  let mockIssue: IssueContext;
  let phaseDataDir: string;

  beforeEach(async () => {
    mock.restore();
    
    // Create temp directory for phase data
    phaseDataDir = '.rsolv/test-phase-data';
    await fs.mkdir(phaseDataDir, { recursive: true });
    
    mockConfig = {
      aiProvider: {
        provider: 'anthropic',
        apiKey: 'test-key',
        model: 'claude-3',
        maxTokens: 4000
      },
      enableSecurityAnalysis: true,
      testGeneration: {
        enabled: true,
        validateFixes: true
      },
      github: {
        token: 'test-token',
        owner: 'test',
        repo: 'webapp'
      }
    } as ActionConfig;

    mockIssue = {
      id: 'issue-999',
      number: 999,
      title: 'Buffer overflow in image processor',
      body: 'Unchecked buffer size can cause overflow',
      labels: ['rsolv:automate', 'security'],
      assignees: [],
      repository: {
        owner: 'test',
        name: 'webapp',
        fullName: 'test/webapp',
        defaultBranch: 'main',
        language: 'JavaScript'
      },
      source: 'github',
      createdAt: '2025-08-06T15:00:00Z',
      updatedAt: '2025-08-06T15:00:00Z',
      metadata: {}
    };

    executor = new PhaseExecutor(mockConfig);
  });

  afterEach(async () => {
    mock.restore();
    // Clean up test data
    await fs.rm(phaseDataDir, { recursive: true, force: true });
  });

  describe('Full Pipeline', () => {
    test('should execute all three phases sequentially', async () => {
      // Mock git status
      mock.module('child_process', () => ({
        execSync: (cmd: string) => {
          if (cmd.includes('git status')) {
            return 'nothing to commit, working tree clean';
          }
          if (cmd.includes('git rev-parse')) {
            return 'abc123def456';
          }
          return '';
        }
      }));

      // Mock issue analysis
      mock.module('../../ai/issue-analyzer.js', () => ({
        analyzeIssue: async () => ({
          canBeFixed: true,
          issueType: 'security',
          filesToModify: ['src/image-processor.js'],
          estimatedComplexity: 'medium',
          suggestedApproach: 'Add buffer size validation'
        })
      }));

      // Mock test generation
      mock.module('../../ai/test-generating-security-analyzer.js', () => ({
        TestGeneratingSecurityAnalyzer: class {
          async generateTestsForIssue() {
            return {
              success: true,
              tests: [
                {
                  name: 'should detect buffer overflow',
                  code: 'test("overflow", () => { expect(overflow).toBe(true); })',
                  type: 'red'
                }
              ]
            };
          }
        }
      }));

      // Mock fix generation
      mock.module('../../ai/adapters/claude-code-git.js', () => ({
        GitBasedClaudeCodeAdapter: class {
          async generateSolutionWithGit() {
            return {
              success: true,
              filesModified: ['src/image-processor.js'],
              commitHash: 'fix123'
            };
          }
        }
      }));

      // Execute SCAN phase
      const scanResult = await executor.execute('scan', {
        issues: [mockIssue]
      });
      
      expect(scanResult.success).toBe(true);
      expect(scanResult.phase).toBe('scan');
      expect(scanResult.data.scan).toBeDefined();

      // Execute VALIDATE phase
      const validateResult = await executor.execute('validate', {
        issues: [mockIssue],
        usePriorScan: true
      });
      
      expect(validateResult.success).toBe(true);
      expect(validateResult.phase).toBe('validate');
      expect(validateResult.data.validation).toBeDefined();

      // Execute MITIGATE phase
      const mitigateResult = await executor.execute('mitigate', {
        issues: [mockIssue],
        usePriorValidation: true
      });
      
      expect(mitigateResult.success).toBe(true);
      expect(mitigateResult.phase).toBe('mitigate');
      expect(mitigateResult.data.mitigation).toBeDefined();
    });

    test('should handle data passing between phases', async () => {
      // Mock implementations
      mock.module('child_process', () => ({
        execSync: () => 'nothing to commit, working tree clean'
      }));

      let scanData: any;
      let validationData: any;

      // SCAN phase
      mock.module('../../ai/issue-analyzer.js', () => ({
        analyzeIssue: async () => {
          scanData = {
            canBeFixed: true,
            issueType: 'security',
            filesToModify: ['app.js']
          };
          return scanData;
        }
      }));

      const scanResult = await executor.execute('scan', {
        issues: [mockIssue]
      });
      
      expect(scanResult.success).toBe(true);

      // VALIDATE phase should receive scan data
      mock.module('../../ai/test-generating-security-analyzer.js', () => ({
        TestGeneratingSecurityAnalyzer: class {
          async generateTestsForIssue(issue: any, analysis: any) {
            // Should receive scan data
            expect(analysis).toBeTruthy();
            
            validationData = {
              success: true,
              tests: [{
                name: 'test',
                code: 'test code',
                type: 'red'
              }]
            };
            return validationData;
          }
        }
      }));

      const validateResult = await executor.execute('validate', {
        issues: [mockIssue],
        usePriorScan: true
      });
      
      expect(validateResult.success).toBe(true);

      // MITIGATE phase should receive validation data
      mock.module('../../ai/adapters/claude-code-git.js', () => ({
        GitBasedClaudeCodeAdapter: class {
          async generateSolutionWithGit(issue: any, options: any) {
            // Should receive validation data with tests
            expect(options.redTests).toBeDefined();
            
            return {
              success: true,
              filesModified: ['app.js']
            };
          }
        }
      }));

      const mitigateResult = await executor.execute('mitigate', {
        issues: [mockIssue],
        usePriorValidation: true
      });
      
      expect(mitigateResult.success).toBe(true);
    });

    test('should stop pipeline if scan determines issue cannot be fixed', async () => {
      mock.module('child_process', () => ({
        execSync: () => 'nothing to commit, working tree clean'
      }));

      mock.module('../../ai/issue-analyzer.js', () => ({
        analyzeIssue: async () => ({
          canBeFixed: false,
          reason: 'Issue is not a security vulnerability'
        })
      }));

      // SCAN phase
      const scanResult = await executor.execute('scan', {
        issues: [mockIssue]
      });
      
      expect(scanResult.success).toBe(true);
      expect(scanResult.data.scan.canBeFixed).toBe(false);

      // VALIDATE phase should skip
      const validateResult = await executor.execute('validate', {
        issues: [mockIssue],
        usePriorScan: true
      });
      
      // Should fail or skip since issue cannot be fixed
      expect(validateResult.success).toBe(false);
    });
  });

  describe('Backward Compatibility', () => {
    test('should maintain compatibility with fix mode', async () => {
      // Mock all required components
      mock.module('child_process', () => ({
        execSync: () => 'nothing to commit, working tree clean'
      }));

      mock.module('../../ai/issue-analyzer.js', () => ({
        analyzeIssue: async () => ({
          canBeFixed: true,
          issueType: 'security',
          filesToModify: ['file.js']
        })
      }));

      mock.module('../../ai/test-generating-security-analyzer.js', () => ({
        TestGeneratingSecurityAnalyzer: class {
          async generateTestsForIssue() {
            return {
              success: true,
              tests: [{
                name: 'test',
                code: 'test',
                type: 'red'
              }]
            };
          }
        }
      }));

      mock.module('../../ai/adapters/claude-code-git.js', () => ({
        GitBasedClaudeCodeAdapter: class {
          async generateSolutionWithGit() {
            return {
              success: true,
              filesModified: ['file.js']
            };
          }
        }
      }));

      // FIX mode should run all phases internally
      const fixResult = await executor.execute('fix', {
        issues: [mockIssue]
      });
      
      expect(fixResult.success).toBe(true);
      expect(fixResult.phase).toBe('fix');
      
      // Should have results from all phases
      expect(fixResult.data.scan).toBeDefined();
      expect(fixResult.data.validation).toBeDefined();
      expect(fixResult.data.mitigation).toBeDefined();
    });

    test('should work with processIssueWithGit', async () => {
      const { processIssueWithGit } = await import('../../ai/git-based-processor.js');
      
      // Mock necessary components
      mock.module('child_process', () => ({
        execSync: () => 'nothing to commit, working tree clean'
      }));

      // This should still work as before
      const result = await processIssueWithGit(mockIssue, mockConfig);
      
      // Should return expected result structure
      expect(result).toBeDefined();
    });
  });

  describe('Error Recovery', () => {
    test('should handle validation failure gracefully', async () => {
      mock.module('child_process', () => ({
        execSync: () => 'nothing to commit, working tree clean'
      }));

      mock.module('../../ai/issue-analyzer.js', () => ({
        analyzeIssue: async () => ({
          canBeFixed: true,
          issueType: 'security'
        })
      }));

      // Make validation fail
      mock.module('../../ai/test-generating-security-analyzer.js', () => ({
        TestGeneratingSecurityAnalyzer: class {
          async generateTestsForIssue() {
            throw new Error('AI service unavailable');
          }
        }
      }));

      const scanResult = await executor.execute('scan', {
        issues: [mockIssue]
      });
      expect(scanResult.success).toBe(true);

      const validateResult = await executor.execute('validate', {
        issues: [mockIssue],
        usePriorScan: true
      });
      
      // Validation should fail but gracefully
      expect(validateResult.success).toBe(false);
      expect(validateResult.error).toContain('AI');

      // Mitigation should not proceed without validation
      const mitigateResult = await executor.execute('mitigate', {
        issues: [mockIssue],
        usePriorValidation: true
      });
      
      expect(mitigateResult.success).toBe(false);
    });

    test('should handle mitigation failure and allow retry', async () => {
      // Setup successful scan and validation
      mock.module('child_process', () => ({
        execSync: () => 'nothing to commit, working tree clean'
      }));

      mock.module('../../ai/issue-analyzer.js', () => ({
        analyzeIssue: async () => ({
          canBeFixed: true,
          issueType: 'security'
        })
      }));

      mock.module('../../ai/test-generating-security-analyzer.js', () => ({
        TestGeneratingSecurityAnalyzer: class {
          async generateTestsForIssue() {
            return {
              success: true,
              tests: [{
                name: 'test',
                code: 'test',
                type: 'red'
              }]
            };
          }
        }
      }));

      let attempts = 0;
      mock.module('../../ai/adapters/claude-code-git.js', () => ({
        GitBasedClaudeCodeAdapter: class {
          async generateSolutionWithGit() {
            attempts++;
            if (attempts === 1) {
              throw new Error('First attempt failed');
            }
            return {
              success: true,
              filesModified: ['file.js']
            };
          }
        }
      }));

      // Run all phases
      await executor.execute('scan', { issues: [mockIssue] });
      await executor.execute('validate', { issues: [mockIssue], usePriorScan: true });
      
      // First mitigation attempt
      const firstAttempt = await executor.execute('mitigate', {
        issues: [mockIssue],
        usePriorValidation: true,
        maxRetries: 1
      });
      
      expect(firstAttempt.success).toBe(false);

      // Retry should succeed
      const retryAttempt = await executor.execute('mitigate', {
        issues: [mockIssue],
        usePriorValidation: true,
        maxRetries: 2
      });
      
      expect(retryAttempt.success).toBe(true);
    });
  });

  describe('Performance', () => {
    test('should complete full pipeline within reasonable time', async () => {
      // Mock all components with minimal delays
      mock.module('child_process', () => ({
        execSync: () => 'clean'
      }));

      mock.module('../../ai/issue-analyzer.js', () => ({
        analyzeIssue: async () => {
          await new Promise(r => setTimeout(r, 10));
          return { canBeFixed: true };
        }
      }));

      mock.module('../../ai/test-generating-security-analyzer.js', () => ({
        TestGeneratingSecurityAnalyzer: class {
          async generateTestsForIssue() {
            await new Promise(r => setTimeout(r, 10));
            return { success: true, tests: [] };
          }
        }
      }));

      mock.module('../../ai/adapters/claude-code-git.js', () => ({
        GitBasedClaudeCodeAdapter: class {
          async generateSolutionWithGit() {
            await new Promise(r => setTimeout(r, 10));
            return { success: true };
          }
        }
      }));

      const startTime = Date.now();
      
      // Execute all phases
      await executor.execute('scan', { issues: [mockIssue] });
      await executor.execute('validate', { issues: [mockIssue], usePriorScan: true });
      await executor.execute('mitigate', { issues: [mockIssue], usePriorValidation: true });
      
      const duration = Date.now() - startTime;
      
      // Should complete in under 1 second for mocked operations
      expect(duration).toBeLessThan(1000);
    });
  });
});