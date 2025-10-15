/**
 * Test suite for ValidationMode backend integration
 * RFC-060-AMENDMENT-001: Test Integration with Backend APIs
 *
 * Tests the integration with TestIntegrationClient for:
 * - Analyzing test files to find best target
 * - Generating AST-integrated test content
 * - Retry logic with exponential backoff
 * - Fallback to .rsolv/tests/ on backend failure
 */

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { ValidationMode } from '../validation-mode.js';
import { IssueContext, ActionConfig } from '../../types/index.js';
import { TestIntegrationClient } from '../test-integration-client.js';
import * as fs from 'fs';
import { execSync } from 'child_process';

// Mock dependencies
vi.mock('../test-integration-client');
vi.mock('../../ai/analyzer');
vi.mock('../../ai/test-generating-security-analyzer');
vi.mock('../../ai/git-based-test-validator');
vi.mock('child_process');
vi.mock('fs');
vi.mock('../../github/api', () => ({
  getGitHubClient: vi.fn(() => ({
    issues: {
      addLabels: vi.fn(),
      createComment: vi.fn()
    }
  }))
}));

describe('ValidationMode - Backend Integration', () => {
  let validationMode: ValidationMode;
  let mockConfig: ActionConfig;
  let mockIssue: IssueContext;
  let mockTestIntegrationClient: any;
  let originalEnv: NodeJS.ProcessEnv;

  beforeEach(() => {
    // Save original env
    originalEnv = { ...process.env };

    // Setup config with API keys
    mockConfig = {
      apiKey: 'test-key',
      rsolvApiKey: 'test-rsolv-key',
      githubToken: 'test-token',
      configPath: '.rsolv/config.json',
      issueLabel: 'rsolv:automate',
      mode: 'validate',
      executableTests: true,
      aiProvider: {
        apiKey: 'test-ai-key',
        model: 'claude-sonnet-4-5-20250929',
        provider: 'anthropic'
      },
      containerConfig: {
        enabled: false
      },
      securitySettings: {
        disableNetworkAccess: false
      }
    } as ActionConfig;

    // Set API URL to enable backend integration
    process.env.RSOLV_API_URL = 'https://api.rsolv.dev';

    mockIssue = {
      id: 'issue-123',
      number: 123,
      title: 'SQL injection in users controller',
      body: 'Vulnerability in app/controllers/users_controller.rb:42',
      labels: ['rsolv:automate'],
      assignees: [],
      file: 'app/controllers/users_controller.rb',
      repository: {
        owner: 'test-org',
        name: 'test-repo',
        fullName: 'test-org/test-repo',
        defaultBranch: 'main'
      },
      source: 'github',
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
      metadata: {}
    };

    // Mock TestIntegrationClient
    mockTestIntegrationClient = {
      analyze: vi.fn(),
      generate: vi.fn()
    };

    (TestIntegrationClient as any).mockImplementation(() => mockTestIntegrationClient);

    validationMode = new ValidationMode(mockConfig);

    // Mock file system operations
    (fs.existsSync as any).mockReturnValue(true);
    (fs.readFileSync as any).mockImplementation((path: string) => {
      if (path.includes('users_controller_spec.rb')) {
        return `describe UsersController do
  before do
    @user = User.create(name: 'test')
  end

  it 'creates user' do
    expect(User.count).to eq(1)
  end
end`;
      }
      return 'mock file content';
    });
    (fs.writeFileSync as any).mockImplementation(() => {});
    (fs.mkdirSync as any).mockImplementation(() => {});

    // Mock git operations
    (execSync as any).mockImplementation((cmd: string) => {
      if (cmd.includes('git status')) return '';
      if (cmd.includes('git rev-parse HEAD')) return 'abc123';
      if (cmd.includes('find')) return 'spec/controllers/users_controller_spec.rb\nspec/models/user_spec.rb';
      return '';
    });
  });

  afterEach(() => {
    // Restore original env
    process.env = originalEnv;
    vi.clearAllMocks();
  });

  describe('integrateTestsWithBackendRetry() - Success path', () => {
    it('should successfully integrate test using backend on first attempt', async () => {
      // Arrange
      mockTestIntegrationClient.analyze.mockResolvedValue({
        recommendations: [
          {
            path: 'spec/controllers/users_controller_spec.rb',
            score: 1.5,
            reason: 'Exact match: controller test for controller file'
          }
        ],
        fallback: {
          path: 'spec/security/users_controller_security_spec.rb',
          reason: 'No existing test found'
        }
      });

      mockTestIntegrationClient.generate.mockResolvedValue({
        integratedContent: `describe UsersController do
  before do
    @user = User.create(name: 'test')
  end

  it 'creates user' do
    expect(User.count).to eq(1)
  end

  describe 'security' do
    it 'rejects SQL injection in search' do
      post :search, params: { q: "admin'; DROP TABLE users;--" }
      expect(response.status).to eq(400)
    end
  end
end`,
        method: 'ast',
        insertionPoint: {
          line: 9,
          strategy: 'after_last_it_block'
        }
      });

      const testContent = {
        redTests: [{
          testName: 'rejects SQL injection',
          testCode: "post :search, params: { q: \"admin'; DROP TABLE users;--\" }\nexpect(response.status).to eq(400)",
          attackVector: "admin'; DROP TABLE users;--"
        }]
      };

      // Act
      const result = await (validationMode as any).integrateTestsWithBackendRetry(testContent, mockIssue);

      // Assert
      expect(result).toBeDefined();
      expect(result.targetFile).toBe('spec/controllers/users_controller_spec.rb');
      expect(result.content).toContain('rejects SQL injection');
      expect(result.content).toContain("admin'; DROP TABLE users;--");

      // Verify backend API was called with correct parameters
      expect(mockTestIntegrationClient.analyze).toHaveBeenCalledWith({
        vulnerableFile: 'app/controllers/users_controller.rb',
        vulnerabilityType: 'SQL injection in users controller',
        candidateTestFiles: expect.arrayContaining([
          'spec/controllers/users_controller_spec.rb',
          'spec/models/user_spec.rb'
        ]),
        framework: expect.any(String)
      });

      expect(mockTestIntegrationClient.generate).toHaveBeenCalledWith({
        targetFileContent: expect.stringContaining('describe UsersController'),
        testSuite: testContent,
        framework: expect.any(String),
        language: 'ruby'
      });
    });
  });

  describe('integrateTestsWithBackendRetry() - Retry on 5xx errors', () => {
    it('should retry on 500 server error and succeed on second attempt', async () => {
      // Arrange - First call fails with 500, second succeeds
      let callCount = 0;
      mockTestIntegrationClient.analyze.mockImplementation(() => {
        callCount++;
        if (callCount === 1) {
          throw new Error('HTTP 500: Internal Server Error');
        }
        return Promise.resolve({
          recommendations: [{
            path: 'spec/controllers/users_controller_spec.rb',
            score: 1.5,
            reason: 'Direct match'
          }],
          fallback: { path: 'spec/security/fallback_spec.rb', reason: 'Generated' }
        });
      });

      mockTestIntegrationClient.generate.mockResolvedValue({
        integratedContent: 'integrated content',
        method: 'ast',
        insertionPoint: { line: 5, strategy: 'after_last_test' }
      });

      const testContent = { redTests: [{ testName: 'test', testCode: 'code', attackVector: 'attack' }] };

      // Act
      const result = await (validationMode as any).integrateTestsWithBackendRetry(testContent, mockIssue);

      // Assert
      expect(result).toBeDefined();
      expect(callCount).toBe(2); // First attempt failed, second succeeded
      expect(mockTestIntegrationClient.analyze).toHaveBeenCalledTimes(2);
    });

    it('should fail after 3 attempts on persistent 500 errors', async () => {
      // Arrange - All attempts fail with 500
      mockTestIntegrationClient.analyze.mockRejectedValue(
        new Error('HTTP 500: Internal Server Error')
      );

      const testContent = { redTests: [{ testName: 'test', testCode: 'code', attackVector: 'attack' }] };

      // Act & Assert
      await expect(
        (validationMode as any).integrateTestsWithBackendRetry(testContent, mockIssue)
      ).rejects.toThrow();

      // Should have tried 3 times
      expect(mockTestIntegrationClient.analyze).toHaveBeenCalledTimes(3);
    });
  });

  describe('integrateTestsWithBackendRetry() - Non-retryable errors', () => {
    it('should NOT retry on 400 Bad Request error', async () => {
      // Arrange
      mockTestIntegrationClient.analyze.mockRejectedValue(
        new Error('HTTP 400: Bad Request - Invalid framework')
      );

      const testContent = { redTests: [{ testName: 'test', testCode: 'code', attackVector: 'attack' }] };

      // Act & Assert
      await expect(
        (validationMode as any).integrateTestsWithBackendRetry(testContent, mockIssue)
      ).rejects.toThrow();

      // Should have tried only once (no retry)
      expect(mockTestIntegrationClient.analyze).toHaveBeenCalledTimes(1);
    });

    it('should NOT retry on 401 Unauthorized error', async () => {
      // Arrange
      mockTestIntegrationClient.analyze.mockRejectedValue(
        new Error('HTTP 401: Unauthorized - Invalid API key')
      );

      const testContent = { redTests: [{ testName: 'test', testCode: 'code', attackVector: 'attack' }] };

      // Act & Assert
      await expect(
        (validationMode as any).integrateTestsWithBackendRetry(testContent, mockIssue)
      ).rejects.toThrow('Unauthorized');

      // Should NOT retry on auth errors
      expect(mockTestIntegrationClient.analyze).toHaveBeenCalledTimes(1);
    });
  });

  describe('Backend not configured - fallback behavior', () => {
    it('should fall back to .rsolv/tests/ when API URL not set', async () => {
      // Arrange - Remove API URL
      delete process.env.RSOLV_API_URL;

      const validationModeWithoutBackend = new ValidationMode(mockConfig);

      const testContent = { redTests: [{ testName: 'test', testCode: 'code', attackVector: 'attack' }] };

      // Act
      await (validationModeWithoutBackend as any).commitTestsToBranch(
        testContent,
        'rsolv/validate/issue-123',
        mockIssue
      );

      // Assert - Should write to .rsolv/tests/ instead of calling backend
      expect(fs.writeFileSync).toHaveBeenCalledWith(
        expect.stringContaining('.rsolv/tests/validation.test.js'),
        expect.any(String),
        'utf8'
      );

      // Backend should NOT have been called
      expect(mockTestIntegrationClient.analyze).not.toHaveBeenCalled();
      expect(mockTestIntegrationClient.generate).not.toHaveBeenCalled();
    });
  });

  describe('Framework detection', () => {
    it('should detect rspec for Ruby test files', async () => {
      // Arrange
      mockIssue.file = 'app/controllers/users_controller.rb';

      mockTestIntegrationClient.analyze.mockResolvedValue({
        recommendations: [{ path: 'spec/users_spec.rb', score: 1.0, reason: 'match' }],
        fallback: { path: 'spec/fallback_spec.rb', reason: 'generated' }
      });

      mockTestIntegrationClient.generate.mockResolvedValue({
        integratedContent: 'content',
        method: 'ast',
        insertionPoint: { line: 5, strategy: 'after_last_test' }
      });

      const testContent = { redTests: [{ testName: 'test', testCode: 'code', attackVector: 'attack' }] };

      // Act
      await (validationMode as any).integrateTestsWithBackendRetry(testContent, mockIssue);

      // Assert - Should detect 'rspec' framework
      expect(mockTestIntegrationClient.generate).toHaveBeenCalledWith(
        expect.objectContaining({
          framework: 'rspec',
          language: 'ruby'
        })
      );
    });

    it('should detect vitest for TypeScript test files', async () => {
      // Arrange
      mockIssue.file = 'src/controllers/users.ts';

      (execSync as any).mockImplementation((cmd: string) => {
        if (cmd.includes('find')) return 'test/users.test.ts\ntest/api.test.ts';
        return '';
      });

      mockTestIntegrationClient.analyze.mockResolvedValue({
        recommendations: [{ path: 'test/users.test.ts', score: 1.0, reason: 'match' }],
        fallback: { path: 'test/fallback.test.ts', reason: 'generated' }
      });

      mockTestIntegrationClient.generate.mockResolvedValue({
        integratedContent: 'content',
        method: 'ast',
        insertionPoint: { line: 5, strategy: 'after_last_test' }
      });

      const testContent = { redTests: [{ testName: 'test', testCode: 'code', attackVector: 'attack' }] };

      // Act
      await (validationMode as any).integrateTestsWithBackendRetry(testContent, mockIssue);

      // Assert - Should detect 'vitest' or 'jest' framework
      expect(mockTestIntegrationClient.generate).toHaveBeenCalledWith(
        expect.objectContaining({
          framework: expect.stringMatching(/vitest|jest/),
          language: expect.stringMatching(/typescript|javascript/)
        })
      );
    });
  });
});
