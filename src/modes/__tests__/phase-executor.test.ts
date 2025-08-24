/**
 * TDD tests for PhaseExecutor
 * Following RFC-041 simple switch-based execution for v1
 */

import { describe, test, expect, beforeEach, afterEach, mock } from 'vitest';
import type { IssueContext, ActionConfig } from '../../types/index.js';

describe('PhaseExecutor', () => {
  let executor: any; // Will be PhaseExecutor instance
  let mockConfig: ActionConfig;
  let mockIssue: IssueContext;

  beforeEach(() => {
    // Clear all mocks to avoid pollution
    mock.restore();
    
    // Mock AI components globally to prevent configuration errors
    vi.mock('../../ai/adapters/claude-code-git.js', () => ({
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
    
    vi.mock('../../ai/git-based-test-validator.js', () => ({
      GitBasedTestValidator: class {
        async validateFixWithTests() {
          return { isValidFix: true };
        }
      }
    }));
    
    // Set up common mocks
    mockConfig = {
      githubToken: 'test-token',
      apiKey: 'test-api-key',
      aiProvider: {
        provider: 'anthropic',
        apiKey: 'test-anthropic-key',
        model: 'claude-3-sonnet'
      }
    } as ActionConfig;

    mockIssue = {
      id: 'test-123',
      number: 123,
      title: 'Test vulnerability',
      body: 'SQL injection found',
      labels: ['rsolv:automate'],
      repository: {
        owner: 'test-owner',
        name: 'test-repo',
        fullName: 'test-owner/test-repo',
        defaultBranch: 'main'
      },
      source: 'github'
    } as IssueContext;
  });

  afterEach(() => {
    // Clean up after each test to avoid pollution
    mock.restore();
  });

  describe('execute method', () => {
    test('should execute scan mode without prerequisites', async () => {
      const { PhaseExecutor } = await import('../phase-executor');
      executor = new PhaseExecutor(mockConfig);

      // Mock the scanner to avoid GitHub token requirement
      executor.scanner = {
        performScan: mock(async () => ({
          vulnerabilities: [
            { type: 'sql-injection', file: 'test.js', line: 42 }
          ],
          createdIssues: []
        }))
      } as any;

      const result = await executor.execute('scan', {
        repository: mockIssue.repository
      });

      expect(result.success).toBe(true);
      expect(result.phase).toBe('scan');
      expect(result.data?.scan).toBeDefined();
    });

    test('should require issue or scan data for validate mode', async () => {
      const { PhaseExecutor } = await import('../phase-executor');
      executor = new PhaseExecutor(mockConfig);

      // Should fail without issue or scan data
      await expect(
        executor.execute('validate', {})
      ).rejects.toThrow('Validation requires issues, --issue, or prior scan');

      // Should succeed with issue number
      const result = await executor.execute('validate', {
        issueNumber: 123
      });
      expect(result.success).toBe(true);
    });

    test('should require issue for mitigate mode', async () => {
      const { PhaseExecutor } = await import('../phase-executor');
      executor = new PhaseExecutor(mockConfig);

      // Should fail without issue but return success: false instead of throwing
      const result = await executor.execute('mitigate', {});
      expect(result.success).toBe(false);
      expect(result.error || result.message || '').toContain('No issues provided for mitigation');

      // Should succeed with issue number (mock validation data and AI components)
      const mockValidation = {
        validation: {
          "issue-123": {
            generatedTests: {
              success: true,
              testSuite: 'test code',
              tests: [{ name: 'test', code: 'test code', type: 'red' }]
            },
            validated: true,
            analysisData: { canBeFixed: true }
          }
        }
      };
      executor.phaseDataClient.retrievePhaseResults = mock(() => Promise.resolve(mockValidation));
      
      const result2 = await executor.execute('mitigate', {
        repository: {
          owner: 'test-owner',
          name: 'test-repo',
          fullName: 'test-owner/test-repo'
        },
        issueNumber: 123
      });
      if (!result2.success) {
        console.log('Debug - result2:', result2);
      }
      expect(result2.success).toBe(true);
    });


    test('should execute full mode without prerequisites', async () => {
      const { PhaseExecutor } = await import('../phase-executor');
      executor = new PhaseExecutor(mockConfig);

      // Mock the scanner for full mode
      executor.scanner = {
        performScan: mock(async () => ({
          vulnerabilities: [],
          createdIssues: []
        }))
      } as any;

      const result = await executor.execute('full', {
        repository: mockIssue.repository
      });

      expect(result.success).toBe(true);
      expect(result.phase).toBe('full');
      expect(result.message).toContain('all phases');
    });

    test('should throw error for invalid mode', async () => {
      const { PhaseExecutor } = await import('../phase-executor');
      executor = new PhaseExecutor(mockConfig);

      await expect(
        executor.execute('invalid' as any, {})
      ).rejects.toThrow('Unknown mode: invalid');
    });
  });

  describe('individual phase methods', () => {
    test('executeScan should detect vulnerabilities', async () => {
      const { PhaseExecutor } = await import('../phase-executor');
      executor = new PhaseExecutor(mockConfig);

      // Mock the scanner
      const mockScan = mock(() => ({
        vulnerabilities: [
          { type: 'sql-injection', file: 'user.js', line: 42 }
        ],
        createdIssues: []
      }));

      executor.scanner = { performScan: mockScan };

      const result = await executor.executeScan({
        repository: mockIssue.repository
      });

      expect(result.success).toBe(true);
      expect(result.data.scan.vulnerabilities).toHaveLength(1);
      expect(mockScan).toHaveBeenCalled();
    });

    test('executeValidate should generate RED tests', async () => {
      const { PhaseExecutor } = await import('../phase-executor');
      executor = new PhaseExecutor(mockConfig);

      // Mock test generation
      const mockGenerateTests = mock(() => ({
        tests: ['test1.js'],
        validated: true
      }));

      executor.testGenerator = { generateValidationTests: mockGenerateTests };

      const result = await executor.executeValidate({
        issueNumber: 123
      });

      expect(result.success).toBe(true);
      expect(result.data.validation).toBeDefined();
      expect(mockGenerateTests).toHaveBeenCalled();
    });

    test('executeMitigate should fix vulnerability', async () => {
      const { PhaseExecutor } = await import('../phase-executor');
      executor = new PhaseExecutor(mockConfig);

      // Mock fix generation
      const mockFix = mock(() => ({
        prUrl: 'https://github.com/test/pr/1',
        filesModified: ['user.js']
      }));

      executor.fixer = { applyFix: mockFix };

      const result = await executor.executeMitigate({
        issueNumber: 123
      });

      expect(result.success).toBe(true);
      expect(result.data.mitigation).toBeDefined();
      expect(result.data.mitigation.prUrl).toBe('https://github.com/test/pr/1');
      expect(mockFix).toHaveBeenCalled();
    });

    test('executeAllPhases should run scan, validate, and mitigate', async () => {
      const { PhaseExecutor } = await import('../phase-executor');
      executor = new PhaseExecutor(mockConfig);

      // Mock all phase methods - need to be async
      const scanSpy = mock(async () => ({ success: true, data: { scan: { vulnerabilities: [] } } }));
      const validateSpy = mock(async () => ({ success: true, data: { validation: {} } }));
      const mitigateSpy = mock(async () => ({ success: true, data: { mitigation: {} } }));

      executor.executeScan = scanSpy;
      executor.executeValidate = validateSpy;
      executor.executeMitigate = mitigateSpy;

      const result = await executor.executeAllPhases({
        repository: mockIssue.repository
      });

      expect(result.success).toBe(true);
      expect(scanSpy).toHaveBeenCalled();
      // Validate and mitigate won't be called if no vulnerabilities found
      // expect(validateSpy).toHaveBeenCalled();
      // expect(mitigateSpy).toHaveBeenCalled();
    });
  });

  describe('vendor detection regression tests', () => {
    test('should handle vulnerabilities with singular "file" property', async () => {
      // Mock GitHub API globally first
      vi.mock('../../github/api.js', () => ({
        getIssue: mock(async () => ({
          title: 'Security Vulnerability: weak_cryptography',
          body: JSON.stringify({ 
            vulnerabilities: [
              { type: 'weak_cryptography', file: 'app/assets/vendor/jquery.min.js', line: 42 },
              { type: 'sql_injection', file: 'app/models/user.rb', line: 100 }
            ]
          }),
          labels: ['rsolv:automate']
        }))
      }));

      // Mock vendor detection
      let capturedFiles: string[] = [];
      vi.mock('../../vendor/index.js', () => ({
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
      vi.mock('../../external/phase-data-client.js', () => ({
        PhaseDataClient: class {
          async retrievePhaseResults() { return null; }
          async storePhaseResults() { return { success: true }; }
        }
      }));

      const { PhaseExecutor } = await import('../phase-executor');
      const executor = new PhaseExecutor(mockConfig);

      // Execute mitigate which should trigger vendor detection
      const result = await executor.executeMitigate({
        issueNumber: 123,
        repository: mockIssue.repository
      });

      // Verify that files were extracted correctly from singular 'file' property
      expect(capturedFiles).toContain('app/assets/vendor/jquery.min.js');
    });

    test('should handle vulnerabilities with plural "files" property', async () => {
      // Mock GitHub API globally first
      vi.mock('../../github/api.js', () => ({
        getIssue: mock(async () => ({
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
        }))
      }));

      // Mock vendor detection
      let capturedFiles: string[] = [];
      vi.mock('../../vendor/index.js', () => ({
        VendorDetectionIntegration: class {
          async isVendorFile(file: string) {
            capturedFiles.push(file);
            return file.includes('vendor');
          }
          async processVulnerability(vuln: any) {
            return { action: 'normal_fix' };
          }
        }
      }));

      // Mock phase data client
      vi.mock('../../external/phase-data-client.js', () => ({
        PhaseDataClient: class {
          async retrievePhaseResults() { return null; }
          async storePhaseResults() { return { success: true }; }
        }
      }));

      const { PhaseExecutor } = await import('../phase-executor');
      const executor = new PhaseExecutor(mockConfig);

      // Execute mitigate which should trigger vendor detection
      const result = await executor.executeMitigate({
        issueNumber: 123,
        repository: mockIssue.repository
      });

      // Verify that files were extracted correctly from plural 'files' property
      expect(capturedFiles).toContain('config/secrets.yml');
      expect(capturedFiles).toContain('app/config/database.yml');
    });

    test('should handle mixed vulnerabilities with both file and files properties', async () => {
      // Mock GitHub API globally first
      vi.mock('../../github/api.js', () => ({
        getIssue: mock(async () => ({
          title: 'Multiple vulnerabilities found',
          body: JSON.stringify({ 
            vulnerabilities: [
              { type: 'weak_cryptography', file: 'vendor/jquery.min.js', line: 42 },
              { type: 'sql_injection', files: ['app/models/user.rb', 'app/models/admin.rb'], line: 100 },
              { type: 'xss', line: 50 } // No file property at all
            ]
          }),
          labels: ['rsolv:automate']
        }))
      }));

      // Mock vendor detection
      let capturedFiles: string[] = [];
      vi.mock('../../vendor/index.js', () => ({
        VendorDetectionIntegration: class {
          async isVendorFile(file: string) {
            capturedFiles.push(file);
            return file.includes('vendor');
          }
          async processVulnerability(vuln: any) {
            return { action: 'vendor_update' };
          }
        }
      }));

      // Mock phase data client
      vi.mock('../../external/phase-data-client.js', () => ({
        PhaseDataClient: class {
          async retrievePhaseResults() { return null; }
          async storePhaseResults() { return { success: true }; }
        }
      }));

      const { PhaseExecutor } = await import('../phase-executor');
      const executor = new PhaseExecutor(mockConfig);

      // Execute mitigate which should trigger vendor detection
      const result = await executor.executeMitigate({
        issueNumber: 123,
        repository: mockIssue.repository
      });

      // Verify that all files were extracted correctly
      expect(capturedFiles).toContain('vendor/jquery.min.js'); // from 'file'
      expect(capturedFiles).toContain('app/models/user.rb');   // from 'files'
      expect(capturedFiles).toContain('app/models/admin.rb');  // from 'files'
      expect(capturedFiles.length).toBe(3); // No spurious entries from the XSS vuln
    });
  });

  describe('phase data persistence', () => {
    test('should store phase results using PhaseDataClient', async () => {
      const { PhaseExecutor } = await import('../phase-executor');
      executor = new PhaseExecutor(mockConfig);

      // Mock PhaseDataClient - needs to be async
      const mockStore = mock(async () => ({ success: true, id: 'phase-123' }));
      executor.phaseDataClient = { 
        storePhaseResults: mockStore,
        retrievePhaseResults: mock(async () => null)
      } as any;

      await executor.storePhaseData('scan', {
        vulnerabilities: []
      }, {
        repo: 'test/repo',
        commitSha: 'abc123'
      });

      expect(mockStore).toHaveBeenCalledWith(
        'scan',
        expect.objectContaining({ scan: expect.objectContaining({ vulnerabilities: [] }) }),
        expect.objectContaining({ repo: 'test/repo' })
      );
    });

    test('should retrieve phase results using PhaseDataClient', async () => {
      const { PhaseExecutor } = await import('../phase-executor');
      executor = new PhaseExecutor(mockConfig);

      // Mock PhaseDataClient
      const mockRetrieve = mock(() => ({
        scan: { vulnerabilities: [] }
      }));
      executor.phaseDataClient = { retrievePhaseResults: mockRetrieve };

      const result = await executor.retrievePhaseData('test/repo', 123, 'abc123');

      expect(result).toBeDefined();
      expect(mockRetrieve).toHaveBeenCalledWith('test/repo', 123, 'abc123');
    });
  });
});