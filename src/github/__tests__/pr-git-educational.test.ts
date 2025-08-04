/**
 * TDD tests for PR creation with educational content
 * Follows RED-GREEN-REFACTOR methodology
 */

import { describe, test, expect, beforeEach, mock } from 'bun:test';
import { createEducationalPullRequest } from '../pr-git-educational.js';

describe('Educational PR Creation', () => {
  beforeEach(() => {
    // Reset mocks before each test
  });

  describe('RED Phase - Educational Content Generation', () => {
    test('should include educational vulnerability explanation', async () => {
      const issue = {
        id: '123',
        number: 48,
        title: 'XSS vulnerability in config',
        body: 'Security issue found',
        repository: {
          fullName: 'user/repo',
          defaultBranch: 'main'
        }
      };

      const summary = {
        title: 'Fix XSS vulnerability',
        description: 'Fixed XSS by sanitizing input',
        vulnerabilityType: 'XSS',
        severity: 'high'
      };

      // Mock execSync to prevent actual git operations
      const childProcess = await import('child_process');
      const originalExecSync = childProcess.execSync;
      childProcess.execSync = mock(() => Buffer.from(''));

      // Mock GitHub API
      const api = await import('../api.js');
      const originalGetClient = api.getGitHubClient;
      api.getGitHubClient = mock(() => ({
        pulls: {
          create: mock(() => Promise.resolve({
            data: {
              number: 100,
              html_url: 'https://github.com/user/repo/pull/100'
            }
          })),
          list: mock(() => Promise.resolve({ data: [] }))
        }
      }));

      const result = await createEducationalPullRequest(
        issue,
        'abc123',
        summary,
        { rsolvApiKey: 'test' }
      );

      // Restore mocks
      childProcess.execSync = originalExecSync;
      api.getGitHubClient = originalGetClient;

      // GREEN: Educational content should be included
      expect(result.educationalContent).toBeDefined();
      expect(result.educationalContent).toContain('What is Cross-Site Scripting');
      expect(result.educationalContent).toContain('How this fix prevents');
      expect(result.educationalContent).toContain('Best practices');
      expect(result.educationalContent).toContain('RSOLV');
    });

    test('should include AI-specific vulnerability context for slopsquatting', async () => {
      const issue = {
        id: '124',
        number: 49,
        title: 'Slopsquatting vulnerability detected',
        body: 'AI hallucinated package',
        repository: {
          fullName: 'user/repo',
          defaultBranch: 'main'
        }
      };

      const summary = {
        title: 'Fix slopsquatting vulnerability',
        description: 'Removed hallucinated package reference',
        vulnerabilityType: 'slopsquatting',
        severity: 'critical',
        isAiGenerated: true
      };

      // Mock execSync
      const childProcess = await import('child_process');
      const originalExecSync = childProcess.execSync;
      childProcess.execSync = mock(() => Buffer.from(''));

      // Mock GitHub API
      const api = await import('../api.js');
      const originalGetClient = api.getGitHubClient;
      api.getGitHubClient = mock(() => ({
        pulls: {
          create: mock(() => Promise.resolve({
            data: {
              number: 101,
              html_url: 'https://github.com/user/repo/pull/101'
            }
          })),
          list: mock(() => Promise.resolve({ data: [] }))
        }
      }));

      const result = await createEducationalPullRequest(
        issue,
        'def456',
        summary,
        { rsolvApiKey: 'test' }
      );

      // Restore mocks
      childProcess.execSync = originalExecSync;
      api.getGitHubClient = originalGetClient;

      // GREEN: Should include AI-specific education
      expect(result.educationalContent).toContain('AI-Specific Vulnerability');
      expect(result.educationalContent).toContain('19.6% of AI package suggestions');
      expect(result.educationalContent).toContain('hallucinated');
    });

    test('should include RSOLV value proposition', async () => {
      const issue = {
        id: '125',
        number: 50,
        title: 'SQL Injection in query',
        body: 'Unsanitized input',
        repository: {
          fullName: 'user/repo',
          defaultBranch: 'main'
        }
      };

      const summary = {
        title: 'Fix SQL injection',
        description: 'Used parameterized queries',
        vulnerabilityType: 'SQLi',
        severity: 'critical'
      };

      // Mock execSync
      const childProcess = await import('child_process');
      const originalExecSync = childProcess.execSync;
      childProcess.execSync = mock(() => Buffer.from(''));

      // Mock GitHub API
      const api = await import('../api.js');
      const originalGetClient = api.getGitHubClient;
      api.getGitHubClient = mock(() => ({
        pulls: {
          create: mock(() => Promise.resolve({
            data: {
              number: 102,
              html_url: 'https://github.com/user/repo/pull/102'
            }
          })),
          list: mock(() => Promise.resolve({ data: [] }))
        }
      }));

      const result = await createEducationalPullRequest(
        issue,
        'ghi789',
        summary,
        { rsolvApiKey: 'test' }
      );

      // Restore mocks
      childProcess.execSync = originalExecSync;
      api.getGitHubClient = originalGetClient;

      // GREEN: Should include RSOLV's unique value
      expect(result.educationalContent).toContain('RSOLV');
      expect(result.educationalContent).toContain('181 patterns');
      expect(result.educationalContent).toContain('Success-based pricing');
      expect(result.educationalContent).toContain('only pay for deployed fixes');
    });
  });

  describe('GREEN Phase - Complete Flow', () => {
    test('should create educational PR with all components', async () => {
      const issue = {
        id: '128',
        number: 53,
        title: 'XSS in user input',
        body: 'Unsanitized HTML',
        repository: {
          fullName: 'RSOLV-dev/demo',
          defaultBranch: 'main'
        }
      };

      const summary = {
        title: 'Fix XSS vulnerability in user input',
        description: 'Sanitized HTML output using DOMPurify',
        vulnerabilityType: 'XSS',
        severity: 'high',
        cwe: 'CWE-79',
        tests: [
          'Verify malicious scripts are blocked',
          'Ensure legitimate HTML still works'
        ]
      };

      // Mock execSync
      const childProcess = await import('child_process');
      const originalExecSync = childProcess.execSync;
      let gitCommands: string[] = [];
      childProcess.execSync = mock((cmd: string) => {
        gitCommands.push(cmd);
        if (cmd.includes('git config user.email')) {
          throw new Error('not configured');
        }
        return Buffer.from('');
      });

      // Mock GitHub API
      const api = await import('../api.js');
      const originalGetClient = api.getGitHubClient;
      let prBody = '';
      api.getGitHubClient = mock(() => ({
        pulls: {
          create: mock((params: any) => {
            prBody = params.body;
            return Promise.resolve({
              data: {
                number: 100,
                html_url: 'https://github.com/RSOLV-dev/demo/pull/100'
              }
            });
          }),
          list: mock(() => Promise.resolve({ data: [] }))
        }
      }));

      const result = await createEducationalPullRequest(
        issue,
        'pqr678',
        summary,
        { rsolvApiKey: 'test' },
        { insertions: 10, deletions: 5, filesChanged: 1 }
      );

      // Restore mocks
      childProcess.execSync = originalExecSync;
      api.getGitHubClient = originalGetClient;

      // REFACTOR: Complete flow should work
      expect(result.success).toBe(true);
      expect(result.pullRequestUrl).toBe('https://github.com/RSOLV-dev/demo/pull/100');
      expect(result.pullRequestNumber).toBe(100);
      expect(result.branchName).toBe('rsolv/fix-issue-53');
      
      // Verify git commands were called
      expect(gitCommands.some(cmd => cmd.includes('git config user.email'))).toBe(true);
      expect(gitCommands.some(cmd => cmd.includes('git checkout'))).toBe(true);
      expect(gitCommands.some(cmd => cmd.includes('git push'))).toBe(true);
      
      // Verify PR body includes educational content
      expect(prBody).toContain('📚 Understanding This Fix');
      expect(prBody).toContain('🛡️ What is Cross-Site Scripting');
      expect(prBody).toContain('🔧 How This Fix Works');
      expect(prBody).toContain('✅ Best Practices');
      expect(prBody).toContain('🤖 About RSOLV');
      expect(prBody).toContain('Success-based pricing');
      expect(prBody).toContain('181+ patterns');
    });
  });
});