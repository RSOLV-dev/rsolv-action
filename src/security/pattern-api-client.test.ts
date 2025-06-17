import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { PatternAPIClient } from './pattern-api-client';
import { VulnerabilityType } from './types';

// Mock fetch globally
global.fetch = vi.fn();

describe('PatternAPIClient', () => {
  let client: PatternAPIClient;
  let originalApiUrl: string | undefined;
  
  beforeEach(() => {
    vi.clearAllMocks();
    // Reset fetch mock
    (global.fetch as any).mockReset();
    // Save and clear environment variable
    originalApiUrl = process.env.RSOLV_API_URL;
    delete process.env.RSOLV_API_URL;
  });

  afterEach(() => {
    vi.restoreAllMocks();
    // Restore environment variable
    if (originalApiUrl !== undefined) {
      process.env.RSOLV_API_URL = originalApiUrl;
    }
  });

  describe('constructor', () => {
    it('should use default API URL if not provided', () => {
      client = new PatternAPIClient();
      expect(client).toBeDefined();
    });

    it('should use provided API URL', () => {
      client = new PatternAPIClient({ apiUrl: 'https://custom.api/patterns' });
      expect(client).toBeDefined();
    });

    it('should use API key from config', () => {
      client = new PatternAPIClient({ apiKey: 'test-key' });
      expect(client).toBeDefined();
    });

    it('should use API key from environment if not in config', () => {
      process.env.RSOLV_API_KEY = 'env-key';
      client = new PatternAPIClient();
      expect(client).toBeDefined();
      delete process.env.RSOLV_API_KEY;
    });
  });

  describe('fetchPatterns', () => {
    beforeEach(() => {
      client = new PatternAPIClient({ apiKey: 'test-key' });
    });

    it('should fetch patterns for a language', async () => {
      const mockResponse = {
        count: 2,
        language: 'javascript',
        accessible_tiers: ['public', 'protected'],
        patterns: [
          {
            id: 'js-sql-injection',
            name: 'SQL Injection',
            type: 'sql_injection',
            description: 'SQL injection vulnerability',
            severity: 'critical',
            patterns: ['SELECT.*\\+', 'INSERT.*\\+'],
            languages: ['javascript'],
            frameworks: [],
            recommendation: 'Use parameterized queries',
            cwe_id: 'CWE-89',
            owasp_category: 'A03:2021',
            test_cases: {
              vulnerable: ['query = "SELECT * FROM users WHERE id = " + userId'],
              safe: ['query = "SELECT * FROM users WHERE id = ?"']
            }
          }
        ]
      };

      (global.fetch as any).mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: async () => mockResponse
      });

      const patterns = await client.fetchPatterns('javascript');

      // Check that fetch was called
      expect(fetch).toHaveBeenCalledTimes(1);
      
      // Get the actual call arguments
      const [url, options] = (fetch as any).mock.calls[0];
      expect(url).toBe('https://api.rsolv.dev/api/v1/patterns/javascript?format=enhanced');
      expect(options.headers['Content-Type']).toBe('application/json');
      expect(options.headers['Authorization']).toBe('Bearer test-key');

      expect(patterns).toHaveLength(1);
      expect(patterns[0].id).toBe('js-sql-injection');
      expect(patterns[0].type).toBe(VulnerabilityType.SQL_INJECTION);
      expect(patterns[0].patterns.regex).toHaveLength(2);
      expect(patterns[0].patterns.regex[0]).toBeInstanceOf(RegExp);
    });

    it('should handle API errors gracefully', async () => {
      // Disable fallback for this test
      client = new PatternAPIClient({ apiKey: 'test-key', fallbackToLocal: false });
      
      (global.fetch as any).mockResolvedValueOnce({
        ok: false,
        status: 500,
        statusText: 'Internal Server Error'
      });

      await expect(client.fetchPatterns('javascript')).rejects.toThrow(
        'Failed to fetch patterns: 500 Internal Server Error'
      );
    });

    it('should use cached patterns within TTL', async () => {
      const mockResponse = {
        count: 1,
        language: 'python',
        patterns: [
          {
            id: 'python-eval',
            name: 'Eval Usage',
            type: 'rce',
            description: 'Eval can execute arbitrary code',
            severity: 'critical',
            patterns: ['eval\\('],
            languages: ['python'],
            recommendation: 'Avoid eval',
            cwe_id: 'CWE-94',
            owasp_category: 'A03:2021',
            test_cases: { vulnerable: [], safe: [] }
          }
        ]
      };

      (global.fetch as any).mockResolvedValueOnce({
        ok: true,
        json: async () => mockResponse
      });

      // First call - should fetch
      await client.fetchPatterns('python');
      expect(fetch).toHaveBeenCalledTimes(1);

      // Second call - should use cache
      await client.fetchPatterns('python');
      expect(fetch).toHaveBeenCalledTimes(1);
    });

    it('should handle patterns without API key (public only)', async () => {
      client = new PatternAPIClient(); // No API key

      const mockResponse = {
        count: 1,
        language: 'javascript',
        accessible_tiers: ['public'],
        patterns: []
      };

      (global.fetch as any).mockResolvedValueOnce({
        ok: true,
        json: async () => mockResponse
      });

      await client.fetchPatterns('javascript');

      // Check that fetch was called without Authorization header
      expect(fetch).toHaveBeenCalledTimes(1);
      
      const [url, options] = (fetch as any).mock.calls[0];
      expect(url).toBe('https://api.rsolv.dev/api/v1/patterns/javascript?format=enhanced');
      expect(options.headers['Content-Type']).toBe('application/json');
      expect(options.headers['Authorization']).toBeUndefined();
    });
  });

  describe('fetchPatternsByTier', () => {
    beforeEach(() => {
      client = new PatternAPIClient({ apiKey: 'test-key' });
    });

    it('should fetch public patterns without auth', async () => {
      client = new PatternAPIClient(); // No API key

      const mockResponse = {
        count: 1,
        tier: 'public',
        language: 'all',
        patterns: []
      };

      (global.fetch as any).mockResolvedValueOnce({
        ok: true,
        json: async () => mockResponse
      });

      await client.fetchPatternsByTier('public');

      expect(fetch).toHaveBeenCalledWith(
        expect.stringContaining('/public'),
        expect.any(Object)
      );
    });

    it('should require API key for protected tier', async () => {
      client = new PatternAPIClient(); // No API key

      await expect(client.fetchPatternsByTier('protected')).rejects.toThrow(
        'API key required for protected tier patterns'
      );
    });

    it('should handle 403 access denied errors', async () => {
      (global.fetch as any).mockResolvedValueOnce({
        ok: false,
        status: 403,
        statusText: 'Forbidden'
      });

      await expect(client.fetchPatternsByTier('ai')).rejects.toThrow(
        'Access denied to ai tier patterns - upgrade your plan'
      );
    });

    it('should fetch tier patterns for specific language', async () => {
      const mockResponse = {
        count: 5,
        tier: 'ai',
        language: 'javascript',
        patterns: []
      };

      (global.fetch as any).mockResolvedValueOnce({
        ok: true,
        json: async () => mockResponse
      });

      await client.fetchPatternsByTier('ai', 'javascript');

      expect(fetch).toHaveBeenCalledWith(
        expect.stringContaining('/ai'),
        expect.objectContaining({
          headers: expect.objectContaining({
            'Authorization': 'Bearer test-key'
          })
        })
      );
    });
  });

  describe('convertToSecurityPattern', () => {
    it('should handle regex compilation errors gracefully', async () => {
      client = new PatternAPIClient({ apiKey: 'test-key' });

      const mockResponse = {
        count: 1,
        language: 'javascript',
        patterns: [
          {
            id: 'bad-regex',
            name: 'Bad Regex Pattern',
            type: 'xss',
            description: 'Pattern with invalid regex',
            severity: 'high',
            patterns: ['[invalid(regex', 'valid.*pattern'],
            languages: ['javascript'],
            recommendation: 'Fix the regex',
            cwe_id: 'CWE-79',
            owasp_category: 'A03:2021',
            test_cases: { vulnerable: [], safe: [] }
          }
        ]
      };

      (global.fetch as any).mockResolvedValueOnce({
        ok: true,
        json: async () => mockResponse
      });

      const patterns = await client.fetchPatterns('javascript');

      expect(patterns[0].patterns.regex).toHaveLength(1); // Only valid regex
      expect(patterns[0].patterns.regex[0].source).toBe('valid.*pattern');
    });

    it('should map vulnerability types correctly', async () => {
      const testCases = [
        { apiType: 'sql_injection', expected: VulnerabilityType.SQL_INJECTION },
        { apiType: 'xss', expected: VulnerabilityType.XSS },
        { apiType: 'command_injection', expected: VulnerabilityType.COMMAND_INJECTION },
        { apiType: 'weak_crypto', expected: VulnerabilityType.WEAK_CRYPTO },
        { apiType: 'unknown_type', expected: VulnerabilityType.UNKNOWN }
      ];

      for (const { apiType, expected } of testCases) {
        // Create a new client instance to avoid cache
        const testClient = new PatternAPIClient({ apiKey: 'test-key' });
        
        const mockResponse = {
          count: 1,
          language: 'javascript',
          patterns: [
            {
              id: 'test-pattern',
              name: 'Test Pattern',
              type: apiType,
              description: 'Test',
              severity: 'high',
              patterns: ['test'],
              languages: ['javascript'],
              recommendation: 'Test',
              cwe_id: 'CWE-1',
              owasp_category: 'A01:2021',
              test_cases: { vulnerable: [], safe: [] }
            }
          ]
        };

        (global.fetch as any).mockResolvedValueOnce({
          ok: true,
          json: async () => mockResponse
        });

        const patterns = await testClient.fetchPatterns('javascript');
        expect(patterns[0].type).toBe(expected);
      }
    });
  });

  describe('cache management', () => {
    beforeEach(() => {
      client = new PatternAPIClient({ 
        apiKey: 'test-key',
        cacheTTL: 1 // 1 second for testing
      });
    });

    it('should expire cache after TTL', async () => {
      const mockResponse = {
        count: 1,
        language: 'ruby',
        patterns: []
      };

      (global.fetch as any).mockResolvedValue({
        ok: true,
        json: async () => mockResponse
      });

      // First call
      await client.fetchPatterns('ruby');
      expect(fetch).toHaveBeenCalledTimes(1);

      // Wait for cache to expire
      await new Promise(resolve => setTimeout(resolve, 1100));

      // Second call should fetch again
      await client.fetchPatterns('ruby');
      expect(fetch).toHaveBeenCalledTimes(2);
    });

    it('should clear cache on demand', async () => {
      const mockResponse = {
        count: 1,
        language: 'java',
        patterns: []
      };

      (global.fetch as any).mockResolvedValue({
        ok: true,
        json: async () => mockResponse
      });

      // First call
      await client.fetchPatterns('java');
      expect(fetch).toHaveBeenCalledTimes(1);

      // Clear cache
      client.clearCache();

      // Second call should fetch again
      await client.fetchPatterns('java');
      expect(fetch).toHaveBeenCalledTimes(2);
    });
  });

  describe('fallback behavior', () => {
    it('should fallback to local patterns on API error when enabled', async () => {
      client = new PatternAPIClient({ 
        apiKey: 'test-key',
        fallbackToLocal: true
      });

      (global.fetch as any).mockRejectedValueOnce(new Error('Network error'));

      const patterns = await client.fetchPatterns('javascript');
      
      expect(patterns).toEqual([]); // TODO: Return actual local patterns
    });

    it('should throw error when fallback is disabled', async () => {
      client = new PatternAPIClient({ 
        apiKey: 'test-key',
        fallbackToLocal: false
      });

      (global.fetch as any).mockRejectedValueOnce(new Error('Network error'));

      await expect(client.fetchPatterns('javascript')).rejects.toThrow('Network error');
    });
  });
});