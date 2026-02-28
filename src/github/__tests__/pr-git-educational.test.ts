/**
 * TDD tests for PR creation with educational content
 * Follows RED-GREEN-REFACTOR methodology
 */

import { describe, test, expect, beforeEach, mock, vi } from 'vitest';
import { createEducationalPullRequest } from '../pr-git-educational.js';

// Track git commands globally
let globalGitCommands: string[] = [];

// Mock child_process module
vi.mock('child_process', () => ({
  execSync: vi.fn((cmd: string) => {
    globalGitCommands.push(cmd);
    return Buffer.from('');
  })
}));

// Store PR body globally for assertion
let globalPRBody = '';

// Mock GitHub API module
vi.mock('../api.js', () => ({
  getGitHubClient: vi.fn(() => ({
    pulls: {
      create: vi.fn((params: any) => {
        // Capture PR body for assertion
        globalPRBody = params?.body || '';
        // Return different URLs based on the repository
        const repoName = params?.owner === 'RSOLV-dev' ? 'RSOLV-dev/demo' : 'user/repo';
        return Promise.resolve({
          data: {
            number: 100,
            html_url: `https://github.com/${repoName}/pull/100`
          }
        });
      }),
      list: vi.fn(() => Promise.resolve({ data: [] }))
    }
  }))
}));

describe('Educational PR Creation', () => {
  beforeEach(() => {
    // Reset mocks before each test
    globalGitCommands = [];
    globalPRBody = '';
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
        severity: 'high',
        cwe: 'CWE-79',
        educationalContent: {
          title: 'Cross-Site Scripting (XSS)',
          description: 'XSS allows attackers to inject malicious scripts into web pages viewed by other users.',
          prevention: 'Sanitize and escape all user input before rendering in HTML context.',
          example: "fetch('/api?q=<script>alert(1)</script>')",
        },
      };

      // GitHub API already mocked at module level

      const result = await createEducationalPullRequest(
        issue,
        'abc123',
        summary,
        { rsolvApiKey: 'test' }
      );

      // Mocks are reset in beforeEach

      // GREEN: Educational content should be included (platform-provided)
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

      // execSync already mocked at module level

      // GitHub API already mocked at module level

      const result = await createEducationalPullRequest(
        issue,
        'def456',
        summary,
        { rsolvApiKey: 'test' }
      );

      // Mocks are reset in beforeEach

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

      // execSync already mocked at module level

      // GitHub API already mocked at module level

      const result = await createEducationalPullRequest(
        issue,
        'ghi789',
        summary,
        { rsolvApiKey: 'test' }
      );

      // Mocks are reset in beforeEach

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
        ],
        educationalContent: {
          title: 'Cross-Site Scripting (XSS)',
          description: 'XSS allows attackers to inject malicious scripts into web pages viewed by other users.',
          prevention: 'Sanitize and escape all user input before rendering in HTML context.',
          example: "fetch('/api?q=<script>alert(1)</script>')",
        },
      };

      // Mock execSync
      // Git commands are tracked globally

      // GitHub API already mocked at module level

      const result = await createEducationalPullRequest(
        issue,
        'pqr678',
        summary,
        { rsolvApiKey: 'test' },
        { insertions: 10, deletions: 5, filesChanged: 1 }
      );

      // Mocks are reset in beforeEach

      // REFACTOR: Complete flow should work
      expect(result.success).toBe(true);
      expect(result.pullRequestUrl).toBe('https://github.com/RSOLV-dev/demo/pull/100');
      expect(result.pullRequestNumber).toBe(100);
      expect(result.branchName).toBe('rsolv/fix-issue-53');
      
      // Verify git commands were called
      expect(globalGitCommands.length).toBeGreaterThan(0);
      expect(globalGitCommands.some(cmd => cmd === 'git config user.email' || cmd.includes('git config user.email'))).toBe(true);
      expect(globalGitCommands.some(cmd => cmd.includes('git checkout'))).toBe(true);
      expect(globalGitCommands.some(cmd => cmd.includes('git push'))).toBe(true);
      
      // Verify PR body includes educational content
      expect(globalPRBody).toContain('📚 Understanding This Fix');
      expect(globalPRBody).toContain('🛡️ What is Cross-Site Scripting');
      expect(globalPRBody).toContain('🔧 How This Fix Works');
      expect(globalPRBody).toContain('✅ Best Practices');
      expect(globalPRBody).toContain('🤖 About RSOLV');
      expect(globalPRBody).toContain('Success-based pricing');
      expect(globalPRBody).toContain('181+ patterns');
    });
  });

  describe('RFC-041: Validation Data Integration', () => {
    test('should include validation branch link when validationData provided', async () => {
      const issue = {
        id: '456',
        number: 123,
        title: 'SQL Injection vulnerability',
        body: 'Security issue found',
        repository: {
          fullName: 'user/repo',
          defaultBranch: 'main'
        }
      };

      const summary = {
        title: 'Fix SQL Injection',
        description: 'Fixed SQL injection using parameterized queries',
        vulnerabilityType: 'SQLi',
        severity: 'critical',
        cwe: '89'
      };

      const validationData = {
        branchName: 'rsolv/validate/issue-123',
        testResults: { passed: 0, failed: 3, total: 3 },
        vulnerabilities: [{
          type: 'SQLi',
          file: 'app.js',
          line: 42,
          severity: 'critical'
        }]
      };

      const result = await createEducationalPullRequest(
        issue,
        'xyz789',
        summary,
        { rsolvApiKey: 'test' },
        { insertions: 5, deletions: 2, filesChanged: 1 },
        validationData
      );

      expect(result.success).toBe(true);

      // Verify validation branch link is included
      expect(globalPRBody).toContain('🧪 Validation Tests');
      expect(globalPRBody).toContain('rsolv/validate/issue-123');
      expect(globalPRBody).toContain('validation branch');
      expect(globalPRBody).toContain('RED tests');
    });

    test('should include test results section when testResults provided', async () => {
      const issue = {
        id: '789',
        number: 456,
        title: 'XSS vulnerability',
        body: 'Security issue found',
        repository: {
          fullName: 'user/repo',
          defaultBranch: 'main'
        }
      };

      const summary = {
        title: 'Fix XSS',
        description: 'Fixed XSS by sanitizing input',
        vulnerabilityType: 'XSS',
        severity: 'high'
      };

      const validationData = {
        testResults: {
          passed: 0,
          failed: 3,
          total: 3,
          output: 'Tests failed as expected'
        }
      };

      const result = await createEducationalPullRequest(
        issue,
        'abc999',
        summary,
        { rsolvApiKey: 'test' },
        undefined,
        validationData
      );

      expect(result.success).toBe(true);

      // Verify test results section
      expect(globalPRBody).toContain('✅ Test Results');
      expect(globalPRBody).toContain('Before Fix (RED Tests)');
      expect(globalPRBody).toContain('3 failed, 0 passed, 3 total');
      expect(globalPRBody).toContain('After Fix (GREEN Tests)');
      expect(globalPRBody).toContain('0 failed, 3 passed, 3 total');
    });

    test('should include attack example section when vulnerability has examples', async () => {
      const issue = {
        id: '101',
        number: 789,
        title: 'SQL Injection',
        body: 'Security issue',
        repository: {
          fullName: 'user/repo',
          defaultBranch: 'main'
        }
      };

      const summary = {
        title: 'Fix SQL Injection',
        description: 'Fixed SQLi',
        vulnerabilityType: 'SQLi',
        severity: 'critical',
        cwe: '89',
        educationalContent: {
          title: 'SQL Injection',
          description: 'SQL injection allows attackers to execute arbitrary SQL commands.',
          prevention: 'Use parameterized queries or prepared statements.',
          example: "SELECT * FROM users WHERE id = '1' OR '1'='1'",
        },
      };

      const result = await createEducationalPullRequest(
        issue,
        'def111',
        summary,
        { rsolvApiKey: 'test' }
      );

      expect(result.success).toBe(true);

      // Verify attack example section is present (platform content has example)
      expect(globalPRBody).toContain('🎯 Attack Example');
      expect(globalPRBody).toContain('How this vulnerability could be exploited');
    });

    test('should include learning resources section with CWE link', async () => {
      const issue = {
        id: '202',
        number: 999,
        title: 'CSRF vulnerability',
        body: 'Security issue',
        repository: {
          fullName: 'user/repo',
          defaultBranch: 'main'
        }
      };

      const summary = {
        title: 'Fix CSRF',
        description: 'Fixed CSRF',
        vulnerabilityType: 'CSRF',
        severity: 'medium',
        cwe: '352'
      };

      const result = await createEducationalPullRequest(
        issue,
        'ghi222',
        summary,
        { rsolvApiKey: 'test' }
      );

      expect(result.success).toBe(true);

      // Verify learning resources
      expect(globalPRBody).toContain('📖 Learning Resources');
      expect(globalPRBody).toContain('CWE-352');
      expect(globalPRBody).toContain('cwe.mitre.org');
      expect(globalPRBody).toContain('OWASP');
      expect(globalPRBody).toContain('RSOLV Security Patterns');
    });

    test('should not double-prefix CWE link when cwe already has CWE- prefix', async () => {
      const issue = {
        id: '303',
        number: 888,
        title: 'CSRF vulnerability',
        body: 'Security issue',
        repository: {
          fullName: 'user/repo',
          defaultBranch: 'main'
        }
      };

      const summary = {
        title: 'Fix CSRF',
        description: 'Fixed CSRF',
        vulnerabilityType: 'CSRF',
        severity: 'medium',
        cwe: 'CWE-352'  // Already has prefix — this is what extractCweFromIssue() returns
      };

      const result = await createEducationalPullRequest(
        issue,
        'cweprefix123',
        summary,
        { rsolvApiKey: 'test' }
      );

      expect(result.success).toBe(true);

      // Should show CWE-352, NOT CWE-CWE-352
      expect(globalPRBody).toContain('CWE-352');
      expect(globalPRBody).not.toContain('CWE-CWE-352');
      expect(globalPRBody).toContain('cwe.mitre.org/data/definitions/352.html');
    });

    test('should use correct education content for prototype_pollution vulnerability type', async () => {
      const issue = {
        id: '404',
        number: 222,
        title: 'Prototype Pollution in loader.js',
        body: 'Unsafe property assignment',
        repository: {
          fullName: 'user/repo',
          defaultBranch: 'main'
        }
      };

      const summary = {
        title: 'Fix Prototype Pollution',
        description: 'Added __proto__ guard',
        vulnerabilityType: 'prototype_pollution',
        severity: 'high',
        cwe: '1321',
        educationalContent: {
          title: 'Prototype Pollution',
          description: 'Prototype pollution allows attackers to modify object prototypes, affecting all instances.',
          prevention: 'Guard against __proto__, constructor, and prototype property assignments.',
          example: 'obj[userInput] = value; // if userInput is "__proto__", pollutes all objects',
        },
      };

      const result = await createEducationalPullRequest(
        issue,
        'proto123',
        summary,
        { rsolvApiKey: 'test' }
      );

      expect(result.success).toBe(true);

      // Should use Prototype Pollution education (platform-provided), NOT XSS fallback
      expect(globalPRBody).toContain('Prototype Pollution');
      expect(globalPRBody).not.toContain('What is Cross-Site Scripting');
      expect(globalPRBody).toContain('__proto__');
    });

    test('should use correct education content for code_injection vulnerability type', async () => {
      const issue = {
        id: '505',
        number: 333,
        title: 'Code Injection via eval()',
        body: 'eval with user input',
        repository: {
          fullName: 'user/repo',
          defaultBranch: 'main'
        }
      };

      const summary = {
        title: 'Fix Code Injection',
        description: 'Replaced eval with safe parsing',
        vulnerabilityType: 'code_injection',
        severity: 'critical',
        cwe: '94',
        educationalContent: {
          title: 'Code Injection',
          description: 'Code injection allows attackers to execute arbitrary code through eval() or similar constructs.',
          prevention: 'Never pass user input to eval(). Use safe parsing alternatives.',
          example: 'eval(userInput); // Attacker controls what code runs',
        },
      };

      const result = await createEducationalPullRequest(
        issue,
        'eval456',
        summary,
        { rsolvApiKey: 'test' }
      );

      expect(result.success).toBe(true);

      // Should use Code Injection education (platform-provided), NOT XSS fallback
      expect(globalPRBody).toContain('Code Injection');
      expect(globalPRBody).toContain('eval()');
      expect(globalPRBody).not.toContain('What is Cross-Site Scripting');
    });

    test('should use correct education content for hardcoded_secrets vulnerability type', async () => {
      const issue = {
        id: '606',
        number: 444,
        title: 'Hardcoded API key',
        body: 'API key in source',
        repository: {
          fullName: 'user/repo',
          defaultBranch: 'main'
        }
      };

      const summary = {
        title: 'Fix Hardcoded Credentials',
        description: 'Moved secrets to env vars',
        vulnerabilityType: 'hardcoded_secrets',
        severity: 'high',
        cwe: '798',
        educationalContent: {
          title: 'Hardcoded Credentials',
          description: 'Hardcoded credentials in source code can be extracted by attackers.',
          prevention: 'Store secrets in environment variables or a secrets manager.',
        },
      };

      const result = await createEducationalPullRequest(
        issue,
        'secret789',
        summary,
        { rsolvApiKey: 'test' }
      );

      expect(result.success).toBe(true);

      // Should use Hardcoded Credentials education (platform-provided)
      expect(globalPRBody).toContain('Hardcoded Credentials');
      expect(globalPRBody).toContain('environment variables');
    });

    test('should use platform-provided educational content when present', async () => {
      const issue = {
        id: '700',
        number: 700,
        title: 'Weak crypto vulnerability',
        body: 'MD5 in use',
        repository: {
          fullName: 'user/repo',
          defaultBranch: 'main'
        }
      };

      const summary = {
        title: 'Fix weak cryptography',
        description: 'Replaced MD5 with bcrypt',
        vulnerabilityType: 'weak_crypto',
        severity: 'high',
        cwe: 'CWE-327',
        educationalContent: {
          title: 'Use of a Broken or Risky Cryptographic Algorithm',
          description: 'MD5 and SHA-1 are cryptographically broken.',
          prevention: 'Use vetted cryptographic libraries with Argon2id or bcrypt.',
        },
      };

      const result = await createEducationalPullRequest(
        issue,
        'platform123',
        summary,
        { rsolvApiKey: 'test' }
      );

      expect(result.success).toBe(true);

      // Platform content should be used in PR body
      expect(globalPRBody).toContain('Use of a Broken or Risky Cryptographic Algorithm');
      expect(globalPRBody).toContain('vetted cryptographic');
      // And in the educational content return value
      expect(result.educationalContent).toContain('Use of a Broken or Risky Cryptographic Algorithm');
    });

    test('should fall back to generic education when no platform content', async () => {
      const issue = {
        id: '701',
        number: 701,
        title: 'Security issue',
        body: 'Vulnerability found',
        repository: {
          fullName: 'user/repo',
          defaultBranch: 'main'
        }
      };

      const summary = {
        title: 'Fix security issue',
        description: 'Applied fix',
        vulnerabilityType: 'buffer_overflow',
        severity: 'critical',
        cwe: 'CWE-120',
        // No educationalContent — tests generic fallback
      };

      const result = await createEducationalPullRequest(
        issue,
        'generic456',
        summary,
        { rsolvApiKey: 'test' }
      );

      expect(result.success).toBe(true);

      // Generic fallback uses CWE MITRE link, not XSS content
      expect(globalPRBody).toContain('Buffer Overflow');
      expect(globalPRBody).toContain('CWE-120');
      expect(globalPRBody).toContain('cwe.mitre.org/data/definitions/120.html');
      expect(globalPRBody).not.toContain('Cross-Site Scripting');
    });

    test('should not crash with null CWE in generic fallback', async () => {
      const issue = {
        id: '702',
        number: 702,
        title: 'Unknown vuln',
        body: 'Some issue',
        repository: {
          fullName: 'user/repo',
          defaultBranch: 'main'
        }
      };

      const summary = {
        title: 'Fix unknown issue',
        description: 'Applied fix',
        // No vulnerabilityType, no cwe, no educationalContent
      };

      const result = await createEducationalPullRequest(
        issue,
        'nullcwe789',
        summary,
        { rsolvApiKey: 'test' }
      );

      expect(result.success).toBe(true);

      // Should render with generic "Security Vulnerability" title, no crash
      expect(globalPRBody).toContain('Security Vulnerability');
      expect(globalPRBody).not.toContain('Cross-Site Scripting');
    });

    test('should work without validationData (backward compatibility)', async () => {
      const issue = {
        id: '303',
        number: 111,
        title: 'Security issue',
        body: 'Issue found',
        repository: {
          fullName: 'user/repo',
          defaultBranch: 'main'
        }
      };

      const summary = {
        title: 'Fix security issue',
        description: 'Fixed the issue',
        vulnerabilityType: 'XSS',
        severity: 'medium'
      };

      const result = await createEducationalPullRequest(
        issue,
        'jkl333',
        summary,
        { rsolvApiKey: 'test' }
      );

      expect(result.success).toBe(true);

      // Should NOT contain validation-specific sections
      expect(globalPRBody).not.toContain('🧪 Validation Tests');
      expect(globalPRBody).not.toContain('rsolv/validate');
      expect(globalPRBody).not.toContain('✅ Test Results');

      // But should still contain educational content
      expect(globalPRBody).toContain('📚 Understanding This Fix');
      expect(globalPRBody).toContain('🤖 About RSOLV');
    });
  });
});