/**
 * Test suite for TestIntegrationClient API client
 * RFC-060-AMENDMENT-001: Test Integration
 *
 * Tests the backend API client for test file analysis and AST-based integration.
 * These tests are RED (failing) because the TestIntegrationClient class
 * does not exist yet - it will be implemented in Phase 1.
 *
 * ⚠️ IMPLEMENTATION GUIDE:
 * See ./REALISTIC-VULNERABILITY-EXAMPLES.md for:
 * - Real-world vulnerability patterns (NodeGoat, RailsGoat)
 * - Actual attack vectors used in these tests
 * - Expected RED test behavior
 * - CWE classifications
 *
 * When implementing Phase 1, use those examples to ensure the LLM generates
 * tests that match real vulnerabilities we'll encounter in production.
 */

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';

// Types based on RFC-060-AMENDMENT-001 API specification
interface AnalyzeRequest {
  vulnerableFile: string;
  vulnerabilityType: string;
  candidateTestFiles: string[];
  framework: string;
}

interface AnalyzeResponse {
  recommendations: Array<{
    path: string;
    score: number;
    reason: string;
  }>;
  fallback: {
    path: string;
    reason: string;
  };
}

interface GenerateRequest {
  targetFileContent: string;
  testSuite: {
    redTests: Array<{
      testName: string;
      testCode: string;
      attackVector: string;
      expectedBehavior: string;
      vulnerableCodePath?: string;
      vulnerablePattern?: string;
    }>;
  };
  framework: string;
  language: string;
}

interface GenerateResponse {
  integratedContent: string;
  method: 'ast' | 'append';
  insertionPoint: {
    line?: number;
    strategy: string;
  };
}

/**
 * TestIntegrationClient - Backend API client for test integration
 *
 * Responsibilities:
 * 1. Analyze test files and score integration suitability
 * 2. Generate AST-based test integration
 * 3. Handle retry logic with exponential backoff
 * 4. Authenticate with x-api-key header (per project convention)
 *
 * Environment-aware URL configuration:
 * - Production: https://api.rsolv.dev
 * - Staging: https://api.rsolv-staging.com (via RSOLV_API_URL env)
 * - Local/CI: Custom URL via constructor or env variable
 */
class TestIntegrationClient {
  private readonly baseUrl: string;

  constructor(
    private apiKey: string,
    baseUrl?: string
  ) {
    // Support environment variable override with production default
    this.baseUrl = baseUrl || process.env.RSOLV_API_URL || 'https://api.rsolv.dev';
  }

  async analyze(request: AnalyzeRequest): Promise<AnalyzeResponse> {
    // STUB: Will be implemented in Phase 1
    throw new Error('Not implemented');
  }

  async generate(request: GenerateRequest): Promise<GenerateResponse> {
    // STUB: Will be implemented in Phase 1
    throw new Error('Not implemented');
  }
}

describe('TestIntegrationClient', () => {
  let client: TestIntegrationClient;
  let mockFetch: ReturnType<typeof vi.fn>;

  beforeEach(() => {
    // Setup client with test credentials
    client = new TestIntegrationClient(
      'test-api-key',
      'https://api.rsolv.test'
    );

    // Mock global fetch
    mockFetch = vi.fn();
    global.fetch = mockFetch;
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  describe('API Client - analyze() method', () => {
    it('should successfully analyze test files with valid request', async () => {
      // Arrange
      const mockResponse: AnalyzeResponse = {
        recommendations: [
          {
            path: 'spec/controllers/users_controller_spec.rb',
            score: 1.5,
            reason: 'Direct unit test for vulnerable controller'
          }
        ],
        fallback: {
          path: 'spec/security/users_controller_security_spec.rb',
          reason: 'No existing test found'
        }
      };

      mockFetch.mockResolvedValue({
        ok: true,
        json: async () => mockResponse
      });

      const request: AnalyzeRequest = {
        vulnerableFile: 'app/controllers/users_controller.rb',
        vulnerabilityType: 'sql_injection',
        candidateTestFiles: ['spec/controllers/users_controller_spec.rb'],
        framework: 'rspec'
      };

      // Act
      const result = await client.analyze(request);

      // Assert - This will FAIL because analyze() throws "Not implemented"
      expect(result).toBeDefined();
      expect(result.recommendations).toHaveLength(1);
      expect(result.recommendations[0].path).toBe('spec/controllers/users_controller_spec.rb');
      expect(result.recommendations[0].score).toBe(1.5);
      expect(result.fallback).toBeDefined();
    });

    it('should successfully generate integrated test with valid request', async () => {
      // Arrange
      const mockResponse: GenerateResponse = {
        integratedContent: 'describe UsersController do\n  it "rejects SQL injection" do\n  end\nend',
        method: 'ast',
        insertionPoint: {
          line: 42,
          strategy: 'after_last_it_block'
        }
      };

      mockFetch.mockResolvedValue({
        ok: true,
        json: async () => mockResponse
      });

      const request: GenerateRequest = {
        targetFileContent: `describe UsersController do
  before do
    @user = User.create(name: 'testuser', admin: false)
  end

  it 'updates user' do
    patch :update, params: { user: { id: @user.id, name: 'newname' } }
    expect(response).to be_successful
  end
end`,
        testSuite: {
          redTests: [{
            testName: 'rejects SQL injection in user update (CWE-89)',
            testCode: `# Based on RailsGoat vulnerability: String interpolation in WHERE clause
# Vulnerable pattern: User.where("id = '#{params[:user][:id]}'")
patch :update, params: {
  user: {
    id: "5') OR admin = 't' --'",  # SQL injection payload
    name: 'attacker'
  }
}

# Test expectations (FAILS on vulnerable code):
expect(response.status).to eq(400)  # Should reject malicious input
expect(User.find(5).admin).to be_falsey  # Should not escalate to admin`,
            attackVector: "5') OR admin = 't' --'",
            expectedBehavior: 'should_fail_on_vulnerable_code',
            vulnerableCodePath: 'app/controllers/users_controller.rb:42',
            vulnerablePattern: 'User.where("id = \'#{params[:user][:id]}\'")'
          }]
        },
        framework: 'rspec',
        language: 'ruby'
      };

      // Act
      const result = await client.generate(request);

      // Assert - This will FAIL because generate() throws "Not implemented"
      expect(result).toBeDefined();
      expect(result.integratedContent).toContain('rejects SQL injection');
      expect(result.method).toBe('ast');
      expect(result.insertionPoint).toBeDefined();
    });
  });

  describe('Retry logic with exponential backoff', () => {
    it('should retry on network timeout errors', async () => {
      // Arrange
      const timeoutError = new Error('Network timeout');
      mockFetch
        .mockRejectedValueOnce(timeoutError)
        .mockRejectedValueOnce(timeoutError)
        .mockResolvedValueOnce({
          ok: true,
          json: async () => ({
            recommendations: [],
            fallback: { path: 'test.rb', reason: 'fallback' }
          })
        });

      const request: AnalyzeRequest = {
        vulnerableFile: 'app/controllers/users_controller.rb',
        vulnerabilityType: 'sql_injection',
        candidateTestFiles: [],
        framework: 'rspec'
      };

      // Act
      const result = await client.analyze(request);

      // Assert - Should have retried 2 times and succeeded on 3rd attempt
      expect(mockFetch).toHaveBeenCalledTimes(3);
      expect(result).toBeDefined();
      expect(result.fallback.path).toBe('test.rb');
    });

    it('should retry on 5xx server errors', async () => {
      // Arrange
      mockFetch
        .mockResolvedValueOnce({
          ok: false,
          status: 503,
          statusText: 'Service Unavailable'
        })
        .mockResolvedValueOnce({
          ok: false,
          status: 503,
          statusText: 'Service Unavailable'
        })
        .mockResolvedValueOnce({
          ok: true,
          json: async () => ({
            recommendations: [],
            fallback: { path: 'test.rb', reason: 'fallback' }
          })
        });

      const request: AnalyzeRequest = {
        vulnerableFile: 'app/users.rb',
        vulnerabilityType: 'xss',
        candidateTestFiles: [],
        framework: 'rspec'
      };

      // Act
      const result = await client.analyze(request);

      // Assert - Should have retried twice and succeeded on 3rd attempt
      expect(mockFetch).toHaveBeenCalledTimes(3);
      expect(result).toBeDefined();
    });

    it('should use exponential backoff between retries', async () => {
      // Arrange
      const delays: number[] = [];
      let lastCallTime = Date.now();

      mockFetch.mockImplementation(() => {
        const now = Date.now();
        if (lastCallTime) {
          delays.push(now - lastCallTime);
        }
        lastCallTime = now;

        // Fail first 2 attempts
        if (delays.length < 2) {
          return Promise.reject(new Error('Network error'));
        }

        return Promise.resolve({
          ok: true,
          json: async () => ({
            recommendations: [],
            fallback: { path: 'test.rb', reason: 'fallback' }
          })
        });
      });

      const request: AnalyzeRequest = {
        vulnerableFile: 'app/users.rb',
        vulnerabilityType: 'sql_injection',
        candidateTestFiles: [],
        framework: 'rspec'
      };

      // Act
      const result = await client.analyze(request);

      // Assert - Verify exponential backoff
      // First retry: ~100ms, Second retry: ~200ms, Third retry: ~400ms
      expect(delays[1]).toBeGreaterThanOrEqual(80); // 100ms ± 20%
      expect(delays[2]).toBeGreaterThanOrEqual(delays[1]); // Exponentially increasing
      expect(result).toBeDefined();
    });
  });

  describe('Error handling', () => {
    it('should handle 4xx client errors without retry', async () => {
      // Arrange
      mockFetch.mockResolvedValue({
        ok: false,
        status: 400,
        statusText: 'Bad Request',
        json: async () => ({ error: 'Invalid request format' })
      });

      const request: AnalyzeRequest = {
        vulnerableFile: '',  // Invalid empty file
        vulnerabilityType: 'sql_injection',
        candidateTestFiles: [],
        framework: 'rspec'
      };

      // Act & Assert - Should NOT retry on 4xx errors
      await expect(client.analyze(request)).rejects.toThrow();
      expect(mockFetch).toHaveBeenCalledTimes(1); // No retries!
    });

    it('should handle 401 authentication errors', async () => {
      // Arrange
      mockFetch.mockResolvedValue({
        ok: false,
        status: 401,
        statusText: 'Unauthorized'
      });

      const request: AnalyzeRequest = {
        vulnerableFile: 'app/users.rb',
        vulnerabilityType: 'sql_injection',
        candidateTestFiles: [],
        framework: 'rspec'
      };

      // Act & Assert
      await expect(client.analyze(request)).rejects.toThrow(/unauthorized|auth/i);
    });

    it('should handle network connection errors', async () => {
      // Arrange
      mockFetch.mockRejectedValue(new Error('ECONNREFUSED'));

      const request: AnalyzeRequest = {
        vulnerableFile: 'app/users.rb',
        vulnerabilityType: 'sql_injection',
        candidateTestFiles: [],
        framework: 'rspec'
      };

      // Act & Assert - Should retry and eventually fail
      await expect(client.analyze(request)).rejects.toThrow();
      expect(mockFetch).toHaveBeenCalledTimes(3); // Should retry 3 times
    });
  });

  describe('URL configuration', () => {
    // Helper to access private baseUrl for testing
    type TestIntegrationClientWithBaseUrl = TestIntegrationClient & { baseUrl: string };

    it('should use custom baseUrl when provided', () => {
      // Arrange & Act
      const customClient = new TestIntegrationClient(
        'test-key',
        'https://api.custom-domain.com'
      ) as TestIntegrationClientWithBaseUrl;

      // Assert - baseUrl should be the custom URL
      expect(customClient.baseUrl).toBe('https://api.custom-domain.com');
    });

    it('should use RSOLV_API_URL environment variable when no baseUrl provided', () => {
      // Arrange
      const originalEnv = process.env.RSOLV_API_URL;
      process.env.RSOLV_API_URL = 'https://api.rsolv-staging.com';

      // Act
      const stagingClient = new TestIntegrationClient('test-key') as TestIntegrationClientWithBaseUrl;

      // Assert
      expect(stagingClient.baseUrl).toBe('https://api.rsolv-staging.com');

      // Cleanup
      if (originalEnv) {
        process.env.RSOLV_API_URL = originalEnv;
      } else {
        delete process.env.RSOLV_API_URL;
      }
    });

    it('should default to production URL when no config provided', () => {
      // Arrange
      const originalEnv = process.env.RSOLV_API_URL;
      delete process.env.RSOLV_API_URL;

      // Act
      const prodClient = new TestIntegrationClient('test-key') as TestIntegrationClientWithBaseUrl;

      // Assert
      expect(prodClient.baseUrl).toBe('https://api.rsolv.dev');

      // Cleanup
      if (originalEnv) {
        process.env.RSOLV_API_URL = originalEnv;
      }
    });

    it('should prefer explicit baseUrl over environment variable', () => {
      // Arrange
      const originalEnv = process.env.RSOLV_API_URL;
      process.env.RSOLV_API_URL = 'https://api.rsolv-staging.com';

      // Act
      const explicitClient = new TestIntegrationClient(
        'test-key',
        'https://api.local-dev.test'
      ) as TestIntegrationClientWithBaseUrl;

      // Assert - Explicit URL should override env variable
      expect(explicitClient.baseUrl).toBe('https://api.local-dev.test');

      // Cleanup
      if (originalEnv) {
        process.env.RSOLV_API_URL = originalEnv;
      } else {
        delete process.env.RSOLV_API_URL;
      }
    });
  });

  describe('TypeScript type safety', () => {
    it('should enforce correct request types for analyze()', async () => {
      // This test validates compile-time type checking
      const validRequest: AnalyzeRequest = {
        vulnerableFile: 'app/users.rb',
        vulnerabilityType: 'sql_injection',
        candidateTestFiles: ['spec/users_spec.rb'],
        framework: 'rspec'
      };

      // TypeScript should catch missing required fields at compile time
      // @ts-expect-error - Missing required field 'framework'
      const invalidRequest: AnalyzeRequest = {
        vulnerableFile: 'app/users.rb',
        vulnerabilityType: 'sql_injection',
        candidateTestFiles: []
        // framework is missing - TypeScript error
      };

      expect(validRequest.framework).toBe('rspec');
    });

    it('should enforce correct request types for generate()', async () => {
      // This test validates compile-time type checking
      const validRequest: GenerateRequest = {
        targetFileContent: 'describe "Test" do\nend',
        testSuite: {
          redTests: [{
            testName: 'test',
            testCode: 'expect(true).to eq(true)',
            attackVector: 'payload',
            expectedBehavior: 'should_fail_on_vulnerable_code'
          }]
        },
        framework: 'rspec',
        language: 'ruby'
      };

      // TypeScript should catch type mismatches at compile time
      expect(validRequest.language).toBe('ruby');
    });

    it('should enforce correct response types', async () => {
      // Arrange
      const mockAnalyzeResponse: AnalyzeResponse = {
        recommendations: [
          {
            path: 'spec/users_spec.rb',
            score: 1.2,
            reason: 'Direct test for user model'
          }
        ],
        fallback: {
          path: 'spec/security/users_security_spec.rb',
          reason: 'Generated security test file'
        }
      };

      // TypeScript enforces response structure
      expect(mockAnalyzeResponse.recommendations).toHaveLength(1);
      expect(mockAnalyzeResponse.recommendations[0].score).toBeGreaterThan(0);
    });
  });

  describe('x-api-key authentication', () => {
    it('should include x-api-key header for analyze requests', async () => {
      // Arrange
      mockFetch.mockResolvedValue({
        ok: true,
        json: async () => ({
          recommendations: [],
          fallback: { path: 'test.rb', reason: 'fallback' }
        })
      });

      const request: AnalyzeRequest = {
        vulnerableFile: 'app/users.rb',
        vulnerabilityType: 'sql_injection',
        candidateTestFiles: [],
        framework: 'rspec'
      };

      // Act
      await client.analyze(request);

      // Assert - Verify x-api-key header was included (per project convention)
      expect(mockFetch).toHaveBeenCalledWith(
        'https://api.rsolv.test/api/v1/test-integration/analyze',
        expect.objectContaining({
          method: 'POST',
          headers: expect.objectContaining({
            'x-api-key': 'test-api-key',
            'Content-Type': 'application/json'
          }),
          body: JSON.stringify(request)
        })
      );
    });

    it('should include x-api-key header for generate requests', async () => {
      // Arrange
      mockFetch.mockResolvedValue({
        ok: true,
        json: async () => ({
          integratedContent: 'test',
          method: 'ast',
          insertionPoint: { strategy: 'append' }
        })
      });

      const request: GenerateRequest = {
        targetFileContent: 'test',
        testSuite: {
          redTests: [{
            testName: 'test',
            testCode: 'expect(true).to eq(true)',
            attackVector: 'payload',
            expectedBehavior: 'should_fail_on_vulnerable_code'
          }]
        },
        framework: 'rspec',
        language: 'ruby'
      };

      // Act
      await client.generate(request);

      // Assert - Verify x-api-key and Content-Type headers
      expect(mockFetch).toHaveBeenCalledWith(
        'https://api.rsolv.test/api/v1/test-integration/generate',
        expect.objectContaining({
          headers: expect.objectContaining({
            'x-api-key': 'test-api-key',
            'Content-Type': 'application/json'
          })
        })
      );
    });
  });
});
