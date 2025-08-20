/**
 * Regression tests for RFC-047 vendor detection bug
 * Tests that the fix correctly handles both 'file' and 'files' properties
 */

import { describe, test, expect, beforeEach, mock } from 'bun:test';
import type { ActionConfig } from '../../types/index.js';

describe('Vendor Detection Regression Tests (RFC-047)', () => {
  let mockConfig: ActionConfig;
  let capturedFiles: string[] = [];

  beforeEach(() => {
    // Clear mock state
    mock.restore();
    capturedFiles = [];
    
    mockConfig = {
      githubToken: 'test-token',
      apiKey: 'test-api-key',
      aiProvider: {
        provider: 'anthropic',
        apiKey: 'test-anthropic-key',
        model: 'claude-3-sonnet'
      }
    } as ActionConfig;

    // Mock all dependencies before import
    mock.module('../../github/api.js', () => ({
      getIssue: mock(async (owner: string, repo: string, issueNumber: number) => {
        // Return different data based on issue number for different tests
        if (issueNumber === 1) {
          return {
            title: 'Security Vulnerability: weak_cryptography',
            body: JSON.stringify({ 
              vulnerabilities: [
                { type: 'weak_cryptography', file: 'app/assets/vendor/jquery.min.js', line: 42 },
                { type: 'sql_injection', file: 'app/models/user.rb', line: 100 }
              ]
            }),
            labels: ['rsolv:automate']
          };
        } else if (issueNumber === 2) {
          return {
            title: 'Security Vulnerability: information_disclosure',
            body: JSON.stringify({ 
              vulnerabilities: [
                { 
                  type: 'information_disclosure', 
                  files: ['config/secrets.yml', 'app/config/database.yml'],
                  line: 1 
                }
              ]
            }),
            labels: ['rsolv:automate']
          };
        } else {
          return {
            title: 'Multiple vulnerabilities found',
            body: JSON.stringify({ 
              vulnerabilities: [
                { type: 'weak_cryptography', file: 'vendor/jquery.min.js', line: 42 },
                { type: 'sql_injection', files: ['app/models/user.rb', 'app/models/admin.rb'], line: 100 },
                { type: 'xss', line: 50 } // No file property at all
              ]
            }),
            labels: ['rsolv:automate']
          };
        }
      }),
      getGitHubClient: mock(() => ({}))
    }));

    // Mock vendor detection to capture files
    mock.module('../../vendor/index.js', () => ({
      VendorDetectionIntegration: class {
        async isVendorFile(file: string) {
          capturedFiles.push(file);
          return file.includes('vendor') || file.includes('.min.');
        }
        async processVulnerability(vuln: any) {
          return { action: 'issue_created', type: 'vendor_update' };
        }
      }
    }));

    // Mock phase data client
    mock.module('../../external/phase-data-client.js', () => ({
      PhaseDataClient: class {
        async retrievePhaseResults() { return null; }
        async storePhaseResults() { return { success: true }; }
      }
    }));

    // Mock AI components
    mock.module('../../ai/adapters/claude-code-git.js', () => ({
      GitBasedClaudeCodeAdapter: class {
        async generateSolutionWithGit() {
          return {
            success: true,
            pullRequestUrl: 'https://github.com/test/repo/pull/1',
            pullRequestNumber: 1,
            commitHash: 'abc123',
            filesModified: ['test.js']
          };
        }
      }
    }));
    
    mock.module('../../ai/git-based-test-validator.js', () => ({
      GitBasedTestValidator: class {
        async validateFixWithTests() {
          return { isValidFix: true };
        }
      }
    }));
  });

  test('should handle vulnerabilities with singular "file" property', async () => {
    // Import after mocks are set up
    const { PhaseExecutor } = await import('../phase-executor');
    const executor = new PhaseExecutor(mockConfig);

    // Execute mitigate with issue #1 (has singular 'file')
    await executor.executeMitigate({
      issueNumber: 1,
      repository: {
        owner: 'test-owner',
        name: 'test-repo',
        fullName: 'test-owner/test-repo',
        defaultBranch: 'main'
      }
    });

    // Verify that files were extracted correctly from singular 'file' property
    expect(capturedFiles).toContain('app/assets/vendor/jquery.min.js');
    expect(capturedFiles).toContain('app/models/user.rb');
  });

  test('should handle vulnerabilities with plural "files" property', async () => {
    // Clear captured files from previous test
    capturedFiles = [];
    
    // Import after mocks are set up
    const { PhaseExecutor } = await import('../phase-executor');
    const executor = new PhaseExecutor(mockConfig);

    // Execute mitigate with issue #2 (has plural 'files')
    await executor.executeMitigate({
      issueNumber: 2,
      repository: {
        owner: 'test-owner',
        name: 'test-repo',
        fullName: 'test-owner/test-repo',
        defaultBranch: 'main'
      }
    });

    // Verify that files were extracted correctly from plural 'files' property
    expect(capturedFiles).toContain('config/secrets.yml');
    expect(capturedFiles).toContain('app/config/database.yml');
  });

  test('should handle mixed vulnerabilities with both file and files properties', async () => {
    // Clear captured files from previous test
    capturedFiles = [];
    
    // Import after mocks are set up
    const { PhaseExecutor } = await import('../phase-executor');
    const executor = new PhaseExecutor(mockConfig);

    // Execute mitigate with issue #3 (has mixed)
    await executor.executeMitigate({
      issueNumber: 3,
      repository: {
        owner: 'test-owner',
        name: 'test-repo',
        fullName: 'test-owner/test-repo',
        defaultBranch: 'main'
      }
    });

    // Verify that all files were extracted correctly
    expect(capturedFiles).toContain('vendor/jquery.min.js'); // from 'file'
    expect(capturedFiles).toContain('app/models/user.rb');   // from 'files'
    expect(capturedFiles).toContain('app/models/admin.rb');  // from 'files'
    expect(capturedFiles.length).toBe(3); // No spurious entries from the XSS vuln
  });
});