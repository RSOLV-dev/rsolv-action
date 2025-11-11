import { describe, test, expect, beforeEach, afterEach, mock, vi } from 'vitest';
import { PatternAPIClient } from './pattern-api-client.js';
import { VulnerabilityType } from './types.js';
import { getTestApiConfig } from '../../test/test-env-config.js';
import {
  mockPatternFetch,
  LANGUAGE_PATTERNS,
  createRailsGoatPattern
} from './__tests__/test-helpers/pattern-mocks.js';

describe('PatternAPIClient', () => {
  let client: PatternAPIClient;
  let originalApiUrl: string | undefined;
  let originalApiKey: string | undefined;
  let fetchMock: any;
  
  beforeEach(() => {
    // Create a fresh mock for fetch
    fetchMock = vi.fn(() => Promise.resolve({
      ok: true,
      status: 200,
      json: async () => ({})
    }));
    global.fetch = fetchMock;
    
    // Save and clear environment variables
    originalApiUrl = process.env.RSOLV_API_URL;
    originalApiKey = process.env.RSOLV_API_KEY;
    delete process.env.RSOLV_API_URL;
    delete process.env.RSOLV_API_KEY;
  });

  afterEach(() => {
    // Restore environment variables
    if (originalApiUrl !== undefined) {
      process.env.RSOLV_API_URL = originalApiUrl;
    }
    if (originalApiKey !== undefined) {
      process.env.RSOLV_API_KEY = originalApiKey;
    }
  });

  describe('constructor', () => {
    test('should use default API URL if not provided', () => {
      client = new PatternAPIClient();
      expect(client).toBeDefined();
    });

    test('should use provided API URL', () => {
      client = new PatternAPIClient({ apiUrl: 'https://custom.api/patterns' });
      expect(client).toBeDefined();
    });

    test('should use API key from config', () => {
      client = new PatternAPIClient({ apiKey: 'test-key' });
      expect(client).toBeDefined();
    });

    test('should use API key from environment if not in config', () => {
      process.env.RSOLV_API_KEY = 'env-key';
      client = new PatternAPIClient();
      expect(client).toBeDefined();
    });
  });

  describe('fetchPatterns', () => {
    const testConfig = getTestApiConfig();

    beforeEach(() => {
      client = new PatternAPIClient({
        apiUrl: testConfig.apiUrl,
        apiKey: testConfig.apiKey || 'test-key'
      });
    });

    test('should fetch patterns for a language', async () => {
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

      fetchMock.mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: async () => mockResponse
      });

      const result = await client.fetchPatterns('javascript');

      // Check that fetch was called
      expect(fetchMock).toHaveBeenCalledTimes(1);

      // Get the actual call arguments
      const [url, options] = fetchMock.mock.calls[0];
      const expectedBaseUrl = testConfig.apiUrl.includes('/api/v1/patterns')
        ? testConfig.apiUrl
        : `${testConfig.apiUrl}/api/v1/patterns`;
      expect(url).toBe(`${expectedBaseUrl}?language=javascript&format=enhanced`);
      expect(options.headers['Content-Type']).toBe('application/json');
      const expectedAuth = testConfig.apiKey || 'test-key';
      // ADR-027: Using x-api-key header for unified API authentication
      expect(options.headers['x-api-key']).toBe(expectedAuth);

      expect(result.patterns).toHaveLength(1);
      expect(result.patterns[0].id).toBe('js-sql-injection');
      expect(result.patterns[0].type).toBe(VulnerabilityType.SQL_INJECTION);
      expect(result.patterns[0].patterns.regex).toHaveLength(2);
      expect(result.patterns[0].patterns.regex[0]).toBeInstanceOf(RegExp);
      expect(result.fromCache).toBe(false);
    });

    test('should handle API errors gracefully', async () => {
      // Disable fallback for this test
      client = new PatternAPIClient({ apiKey: 'test-key', fallbackToLocal: false });
      
      fetchMock.mockResolvedValueOnce({
        ok: false,
        status: 500,
        statusText: 'Internal Server Error'
      });

      await expect(client.fetchPatterns('javascript')).rejects.toThrow(
        'Failed to fetch patterns: 500 Internal Server Error'
      );
    });

    test('should use cached patterns within TTL', async () => {
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

      fetchMock.mockResolvedValueOnce({
        ok: true,
        json: async () => mockResponse
      });

      // First call - should fetch
      await client.fetchPatterns('python');
      expect(fetchMock).toHaveBeenCalledTimes(1);

      // Second call - should use cache
      await client.fetchPatterns('python');
      expect(fetchMock).toHaveBeenCalledTimes(1); // Still only 1 call
    });

    test('should return fromCache: false on initial API fetch', async () => {
      const mockResponse = {
        count: 1,
        language: 'ruby',
        patterns: [
          {
            id: 'ruby-eval',
            name: 'Eval Usage',
            type: 'rce',
            description: 'Eval can execute arbitrary code',
            severity: 'critical',
            patterns: ['eval\\('],
            languages: ['ruby'],
            recommendation: 'Avoid eval',
            cwe_id: 'CWE-94',
            owasp_category: 'A03:2021',
            test_cases: { vulnerable: [], safe: [] }
          }
        ]
      };

      fetchMock.mockResolvedValueOnce({
        ok: true,
        json: async () => mockResponse
      });

      // First call - should fetch from API
      const result = await client.fetchPatterns('ruby');
      expect(result.fromCache).toBe(false);
      expect(result.patterns).toHaveLength(1);
      expect(fetchMock).toHaveBeenCalledTimes(1);
    });

    test('should return fromCache: true when using cached patterns', async () => {
      const mockResponse = {
        count: 1,
        language: 'php',
        patterns: [
          {
            id: 'php-eval',
            name: 'Eval Usage',
            type: 'rce',
            description: 'Eval can execute arbitrary code',
            severity: 'critical',
            patterns: ['eval\\('],
            languages: ['php'],
            recommendation: 'Avoid eval',
            cwe_id: 'CWE-94',
            owasp_category: 'A03:2021',
            test_cases: { vulnerable: [], safe: [] }
          }
        ]
      };

      fetchMock.mockResolvedValueOnce({
        ok: true,
        json: async () => mockResponse
      });

      // First call - should fetch from API
      const firstResult = await client.fetchPatterns('php');
      expect(firstResult.fromCache).toBe(false);
      expect(fetchMock).toHaveBeenCalledTimes(1);

      // Second call - should use cache
      const secondResult = await client.fetchPatterns('php');
      expect(secondResult.fromCache).toBe(true);
      expect(secondResult.patterns).toHaveLength(1);
      expect(fetchMock).toHaveBeenCalledTimes(1); // Still only 1 API call
    });

    describe('when checking cache behavior', () => {
      let mockPattern: any;

      beforeEach(() => {
        mockPattern = {
          id: 'cache-test',
          name: 'Cache Test',
          type: 'xss',
          description: 'Test pattern',
          severity: 'high',
          patterns: ['test'],
          languages: ['javascript'],
          recommendation: 'Fix it',
          cwe_id: 'CWE-79',
          owasp_category: 'A03:2021',
          test_cases: { vulnerable: [], safe: [] }
        };
      });

      test('refetches after TTL expires', async () => {
        const testClient = new PatternAPIClient({
          apiKey: 'test-key',
          cacheTTL: 0.001 // 1ms
        });

        fetchMock.mockResolvedValue({
          ok: true,
          json: async () => ({ count: 1, patterns: [mockPattern] })
        });

        await testClient.fetchPatterns('javascript');
        expect(fetchMock).toHaveBeenCalledTimes(1);

        await new Promise(resolve => setTimeout(resolve, 10));

        await testClient.fetchPatterns('javascript');
        expect(fetchMock).toHaveBeenCalledTimes(2);
      });

      test('maintains separate cache per language', async () => {
        fetchMock.mockImplementation((url: string) => {
          const lang = url.includes('python') ? 'python' : 'javascript';
          return Promise.resolve({
            ok: true,
            json: async () => ({
              count: 1,
              patterns: [{ ...mockPattern, id: `${lang}-pattern`, languages: [lang] }]
            })
          });
        });

        await client.fetchPatterns('javascript');
        await client.fetchPatterns('python');
        expect(fetchMock).toHaveBeenCalledTimes(2);

        await client.fetchPatterns('javascript');
        await client.fetchPatterns('python');
        expect(fetchMock).toHaveBeenCalledTimes(2); // No new calls
      });

      test('maintains separate cache per API key', async () => {
        let callCount = 0;
        fetchMock.mockImplementation(() => {
          callCount++;
          return Promise.resolve({
            ok: true,
            json: async () => ({ count: 1, patterns: [mockPattern] })
          });
        });

        const demoClient = new PatternAPIClient();
        await demoClient.fetchPatterns('javascript');

        const fullClient = new PatternAPIClient({ apiKey: 'test-key' });
        await fullClient.fetchPatterns('javascript');

        expect(callCount).toBe(2);
      });
    });

    test('should handle patterns without API key (public only)', async () => {
      client = new PatternAPIClient({ fallbackToLocal: false });

      const mockResponse = {
        count: 1,
        language: 'javascript',
        patterns: [
          {
            id: 'js-eval',
            name: 'Eval Usage',
            type: 'rce',
            description: 'Eval can execute arbitrary code',
            severity: 'critical',
            patterns: ['eval\\('],
            languages: ['javascript'],
            recommendation: 'Avoid eval',
            cwe_id: 'CWE-94',
            owasp_category: 'A03:2021',
            test_cases: { vulnerable: [], safe: [] }
          }
        ]
      };

      fetchMock.mockResolvedValueOnce({
        ok: true,
        json: async () => mockResponse
      });

      const result = await client.fetchPatterns('javascript');

      // Should not send Authorization header
      const [, options] = fetchMock.mock.calls[0];
      expect(options.headers['Authorization']).toBeUndefined();

      expect(result.patterns).toHaveLength(1);
      expect(result.fromCache).toBe(false);
    });
  });

  describe('clearCache', () => {
    test('forces refetch on next call', async () => {
      const testClient = new PatternAPIClient({ apiKey: 'test-key' });
      let callCount = 0;
      fetchMock.mockImplementation(() => {
        callCount++;
        return Promise.resolve({
          ok: true,
          json: async () => ({
            count: 1,
            patterns: [{
              id: 'test',
              name: 'Test',
              type: 'xss',
              description: 'Test',
              severity: 'high',
              patterns: ['test'],
              languages: ['javascript'],
              recommendation: 'Fix it',
              cwe_id: 'CWE-79',
              owasp_category: 'A03:2021',
              test_cases: { vulnerable: [], safe: [] }
            }]
          })
        });
      });

      await testClient.fetchPatterns('javascript');
      await testClient.fetchPatterns('javascript');
      expect(callCount).toBe(1);

      testClient.clearCache();

      await testClient.fetchPatterns('javascript');
      expect(callCount).toBe(2);
    });

    test('clears all languages', async () => {
      const testClient = new PatternAPIClient({ apiKey: 'test-key' });
      let callCount = 0;
      fetchMock.mockImplementation((url: string) => {
        callCount++;
        const lang = url.includes('python') ? 'python' : 'javascript';
        return Promise.resolve({
          ok: true,
          json: async () => ({
            count: 1,
            patterns: [{
              id: `${lang}-pattern`,
              name: 'Test',
              type: 'xss',
              description: 'Test',
              severity: 'high',
              patterns: ['test'],
              languages: [lang],
              recommendation: 'Fix it',
              cwe_id: 'CWE-79',
              owasp_category: 'A03:2021',
              test_cases: { vulnerable: [], safe: [] }
            }]
          })
        });
      });

      await testClient.fetchPatterns('javascript');
      await testClient.fetchPatterns('python');
      expect(callCount).toBe(2);

      await testClient.fetchPatterns('javascript');
      await testClient.fetchPatterns('python');
      expect(callCount).toBe(2); // Still 2 - using cache

      testClient.clearCache();

      await testClient.fetchPatterns('javascript');
      await testClient.fetchPatterns('python');
      expect(callCount).toBe(4); // Now 4 - refetched
    });
  });

  describe('Type mapping from API to VulnerabilityType', () => {
    beforeEach(() => {
      client = new PatternAPIClient({ apiKey: 'test-key' });
    });

    test.each([
      { language: 'javascript', patternFn: LANGUAGE_PATTERNS.javascript },
      { language: 'python', patternFn: LANGUAGE_PATTERNS.python },
      { language: 'ruby', patternFn: LANGUAGE_PATTERNS.ruby },
      { language: 'php', patternFn: LANGUAGE_PATTERNS.php }
    ])('should map code_injection type correctly for $language', async ({ language, patternFn }) => {
      mockPatternFetch(fetchMock, [patternFn()], language);

      const result = await client.fetchPatterns(language);

      expect(result.patterns[0].type).toBe(VulnerabilityType.CODE_INJECTION);
      expect(result.patterns[0].cweId).toBe('CWE-94');
      expect(result.patterns[0].severity).toBe('critical');
      expect(result.fromCache).toBe(false);
    });

    test.each([
      { wrongType: VulnerabilityType.COMMAND_INJECTION, name: 'COMMAND_INJECTION' },
      { wrongType: VulnerabilityType.IMPROPER_INPUT_VALIDATION, name: 'IMPROPER_INPUT_VALIDATION (regression)' }
    ])('should NOT map code_injection to $name', async ({ wrongType }) => {
      mockPatternFetch(fetchMock, [LANGUAGE_PATTERNS.javascript()]);

      const result = await client.fetchPatterns('javascript');

      // This test would have caught the bug - without the mapping,
      // code_injection falls back to IMPROPER_INPUT_VALIDATION
      expect(result.patterns[0].type).toBe(VulnerabilityType.CODE_INJECTION);
      expect(result.patterns[0].type).not.toBe(wrongType);
    });

    test('should preserve all metadata through type mapping', async () => {
      const pattern = LANGUAGE_PATTERNS.ruby();
      mockPatternFetch(fetchMock, [pattern], 'ruby');

      const result = await client.fetchPatterns('ruby');

      expect(result.patterns[0]).toMatchObject({
        type: VulnerabilityType.CODE_INJECTION,
        severity: 'critical',
        cweId: 'CWE-94'
      });
      expect(result.patterns[0].remediation).toContain('safer alternatives');
    });

    test('should compile regex patterns and validate against RailsGoat code', async () => {
      const pattern = createRailsGoatPattern();
      mockPatternFetch(fetchMock, [pattern]);

      const result = await client.fetchPatterns('javascript');
      const compiledPattern = result.patterns[0];

      expect(compiledPattern.type).toBe(VulnerabilityType.CODE_INJECTION);
      expect(compiledPattern.patterns.regex).toHaveLength(1);
      expect(compiledPattern.patterns.regex[0]).toBeInstanceOf(RegExp);

      // Validate against actual RailsGoat code
      expect(compiledPattern.patterns.regex[0].test('eval(request.responseText);')).toBe(true);
    });
  });

  describe('PatternAPIClient enhanced patterns', () => {
    test('should handle enhanced patterns with AST rules', async () => {
      client = new PatternAPIClient({ apiKey: 'test-key' });

      const mockResponse = {
        count: 1,
        language: 'javascript',
        patterns: [
          {
            id: 'js-xss-innerhtml',
            name: 'XSS via innerHTML',
            type: 'xss',
            description: 'XSS vulnerability via innerHTML',
            severity: 'high',
            patterns: ['innerHTML.*='],
            languages: ['javascript'],
            recommendation: 'Use textContent instead',
            cwe_id: 'CWE-79',
            owasp_category: 'A03:2021',
            test_cases: { vulnerable: [], safe: [] },
            // Enhanced pattern fields
            ast_rules: [
              {
                type: 'AssignmentExpression',
                pattern: {
                  left: {
                    type: 'MemberExpression',
                    property: { name: 'innerHTML' }
                  }
                }
              }
            ],
            context_rules: [
              {
                type: 'taint_tracking',
                source: 'user_input',
                sink: 'innerHTML'
              }
            ],
            confidence_rules: {
              high: ['Direct user input to innerHTML'],
              medium: ['Indirect flow to innerHTML'],
              low: ['Complex data flow']
            }
          }
        ]
      };

      fetchMock.mockResolvedValueOnce({
        ok: true,
        json: async () => mockResponse
      });

      const result = await client.fetchPatterns('javascript');

      expect(result.patterns).toHaveLength(1);
      expect(result.patterns[0].patterns.ast).toBeDefined();
      expect(result.patterns[0].patterns.ast).toHaveLength(1);
      expect(result.patterns[0].contextRules).toBeDefined();
      expect(result.patterns[0].confidenceRules).toBeDefined();
      expect(result.fromCache).toBe(false);
    });

    test('should handle patterns without enhanced features', async () => {
      client = new PatternAPIClient({ apiKey: 'test-key' });
      
      const mockResponse = {
        count: 1,
        language: 'python',
        patterns: [
          {
            id: 'python-sql-injection',
            name: 'SQL Injection',
            type: 'sql_injection',
            description: 'SQL injection vulnerability',
            severity: 'critical',
            patterns: ['query.*\\+.*%'],
            languages: ['python'],
            recommendation: 'Use parameterized queries',
            cwe_id: 'CWE-89',
            owasp_category: 'A03:2021',
            test_cases: { vulnerable: [], safe: [] }
            // No enhanced pattern fields
          }
        ]
      };

      fetchMock.mockResolvedValueOnce({
        ok: true,
        json: async () => mockResponse
      });

      const result = await client.fetchPatterns('python');

      expect(result.patterns).toHaveLength(1);
      expect(result.patterns[0].patterns.ast).toBeUndefined();
      expect(result.patterns[0].patterns.context).toBeUndefined();
      expect(result.patterns[0].confidence).toBeUndefined();
      expect(result.fromCache).toBe(false);
    });
  });

  describe('Regex flags preservation (eval detection fix)', () => {
    test('should add "im" flags to regex patterns without explicit flags', async () => {
      client = new PatternAPIClient({ apiKey: 'test-key' });

      const mockResponse = {
        patterns: [
          {
            id: 'js-eval-user-input',
            name: 'Dangerous eval() with User Input',
            type: 'code_injection',
            description: 'Detects eval() with user input',
            severity: 'critical',
            // Plain string pattern without /pattern/flags format
            regex: '^(?!.*\\/\\/).*eval\\s*\\(.*?(?:req\\.|request\\.|params\\.|query\\.|body\\.|user|input|data|Code)',
            languages: ['javascript'],
            recommendation: 'Avoid eval()',
            cwe_id: 'CWE-94',
            owasp_category: 'A03:2021',
            test_cases: { vulnerable: [], safe: [] }
          }
        ]
      };

      fetchMock.mockResolvedValueOnce({
        ok: true,
        json: async () => mockResponse
      });

      const result = await client.fetchPatterns('javascript');

      expect(result.patterns).toHaveLength(1);
      const pattern = result.patterns[0];

      // Verify the regex has 'im' flags
      expect(pattern.patterns.regex).toHaveLength(1);
      const regex = pattern.patterns.regex[0];
      expect(regex).toBeInstanceOf(RegExp);
      expect(regex.flags).toContain('i'); // case-insensitive
      expect(regex.flags).toContain('m'); // multiline

      // Verify it matches indented eval() calls (multiline mode)
      const testCode = '      eval(request.responseText);';
      expect(regex.test(testCode)).toBe(true);
    });

    test('should preserve explicit flags when pattern uses /pattern/flags format', async () => {
      client = new PatternAPIClient({ apiKey: 'test-key' });

      const mockResponse = {
        patterns: [
          {
            id: 'test-pattern',
            name: 'Test Pattern',
            type: 'xss',
            description: 'Test',
            severity: 'high',
            // Pattern with explicit flags in /pattern/flags format
            regex: '/innerHTML.*=.*user/g',
            languages: ['javascript'],
            recommendation: 'Test',
            cwe_id: 'CWE-79',
            owasp_category: 'A03:2021',
            test_cases: { vulnerable: [], safe: [] }
          }
        ]
      };

      fetchMock.mockResolvedValueOnce({
        ok: true,
        json: async () => mockResponse
      });

      const result = await client.fetchPatterns('javascript');

      expect(result.patterns).toHaveLength(1);
      const regex = result.patterns[0].patterns.regex[0];

      // Should preserve the explicit 'g' flag
      expect(regex.flags).toContain('g');
      expect(regex.flags).not.toContain('i');
      expect(regex.flags).not.toContain('m');
    });
  });

  describe('Type mapping (code_injection support)', () => {
    test('should map "code_injection" type to VulnerabilityType.CODE_INJECTION', async () => {
      client = new PatternAPIClient({ apiKey: 'test-key' });

      const mockResponse = {
        patterns: [
          {
            id: 'js-eval-user-input',
            name: 'Dangerous eval()',
            type: 'code_injection', // This was previously unmapped
            description: 'Test',
            severity: 'critical',
            regex: 'eval\\(',
            languages: ['javascript'],
            recommendation: 'Avoid eval()',
            cwe_id: 'CWE-94',
            owasp_category: 'A03:2021',
            test_cases: { vulnerable: [], safe: [] }
          }
        ]
      };

      fetchMock.mockResolvedValueOnce({
        ok: true,
        json: async () => mockResponse
      });

      const result = await client.fetchPatterns('javascript');

      expect(result.patterns).toHaveLength(1);
      const pattern = result.patterns[0];

      // Should map to CODE_INJECTION, not fall back to IMPROPER_INPUT_VALIDATION
      expect(pattern.type).toBe(VulnerabilityType.CODE_INJECTION);
    });

    test('should still map other types correctly', async () => {
      client = new PatternAPIClient({ apiKey: 'test-key' });

      const mockResponse = {
        patterns: [
          {
            id: 'test-sql',
            name: 'SQL Injection',
            type: 'sql_injection',
            description: 'Test',
            severity: 'critical',
            regex: 'query.*',
            languages: ['javascript'],
            recommendation: 'Test',
            cwe_id: 'CWE-89',
            owasp_category: 'A03:2021',
            test_cases: { vulnerable: [], safe: [] }
          },
          {
            id: 'test-cmd',
            name: 'Command Injection',
            type: 'command_injection',
            description: 'Test',
            severity: 'critical',
            regex: 'exec\\(',
            languages: ['javascript'],
            recommendation: 'Test',
            cwe_id: 'CWE-78',
            owasp_category: 'A03:2021',
            test_cases: { vulnerable: [], safe: [] }
          }
        ]
      };

      fetchMock.mockResolvedValueOnce({
        ok: true,
        json: async () => mockResponse
      });

      const result = await client.fetchPatterns('javascript');

      expect(result.patterns).toHaveLength(2);
      expect(result.patterns[0].type).toBe(VulnerabilityType.SQL_INJECTION);
      expect(result.patterns[1].type).toBe(VulnerabilityType.COMMAND_INJECTION);
    });
  });
});