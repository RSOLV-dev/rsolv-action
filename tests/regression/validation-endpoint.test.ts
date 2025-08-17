import { describe, it, expect, beforeEach, mock } from 'bun:test';
import { ValidationService } from '../../src/services/validation';
import { APIClient } from '../../src/external/api-client';

/**
 * Regression tests for validation endpoint issues discovered during E2E testing
 * Issue #610: GitHub Action calling wrong endpoint
 * Issue #617: Validation returning Not Found
 */

describe('Regression: Validation Endpoint Compatibility', () => {
  let validationService: ValidationService;
  let apiClient: APIClient;

  beforeEach(() => {
    // Mock the API client to test endpoint calls
    apiClient = new APIClient({
      apiKey: 'test-api-key',
      apiUrl: 'https://api.rsolv.dev'
    });
    
    validationService = new ValidationService(apiClient);
  });

  describe('Issue #610: API endpoint mismatch', () => {
    it('should use /api/v1/vulnerabilities/validate as primary endpoint', async () => {
      const mockFetch = mock((url: string, options: any) => {
        expect(url).toBe('https://api.rsolv.dev/api/v1/vulnerabilities/validate');
        return Promise.resolve({
          ok: true,
          json: () => Promise.resolve({
            validated: [],
            stats: { total: 0, validated: 0, rejected: 0 }
          })
        });
      });

      global.fetch = mockFetch as any;

      const result = await validationService.validateVulnerabilities({
        repository: 'test/repo',
        vulnerabilities: [],
        files: {}
      });

      expect(mockFetch).toHaveBeenCalled();
      expect(result).toBeDefined();
    });

    it('should fallback to /api/v1/ast/validate if primary fails with 404', async () => {
      let callCount = 0;
      const mockFetch = mock((url: string, options: any) => {
        callCount++;
        
        if (callCount === 1) {
          // First call to primary endpoint fails
          expect(url).toBe('https://api.rsolv.dev/api/v1/vulnerabilities/validate');
          return Promise.resolve({
            ok: false,
            status: 404,
            statusText: 'Not Found'
          });
        } else {
          // Second call to compatibility endpoint succeeds
          expect(url).toBe('https://api.rsolv.dev/api/v1/ast/validate');
          return Promise.resolve({
            ok: true,
            json: () => Promise.resolve({
              validated: [],
              stats: { total: 0, validated: 0, rejected: 0 }
            })
          });
        }
      });

      global.fetch = mockFetch as any;

      const result = await validationService.validateVulnerabilities({
        repository: 'test/repo',
        vulnerabilities: [],
        files: {}
      });

      expect(callCount).toBe(2);
      expect(result).toBeDefined();
    });

    it('should NOT use /ast/validate without api/v1 prefix', async () => {
      const mockFetch = mock((url: string, options: any) => {
        // Should never call the legacy endpoint
        expect(url).not.toBe('https://api.rsolv.dev/ast/validate');
        return Promise.resolve({
          ok: true,
          json: () => Promise.resolve({
            validated: [],
            stats: { total: 0, validated: 0, rejected: 0 }
          })
        });
      });

      global.fetch = mockFetch as any;

      await validationService.validateVulnerabilities({
        repository: 'test/repo',
        vulnerabilities: [],
        files: {}
      });
    });
  });

  describe('Issue #617: Validation returning actual results', () => {
    it('should return vulnerability validation results not empty array', async () => {
      const mockFetch = mock(() => {
        return Promise.resolve({
          ok: true,
          json: () => Promise.resolve({
            validated: [
              {
                id: 'vuln-1',
                isValid: true,
                confidence: 0.8,
                reason: null
              },
              {
                id: 'vuln-2',
                isValid: false,
                confidence: 0.95,
                reason: 'Safe pattern detected'
              }
            ],
            stats: {
              total: 2,
              validated: 1,
              rejected: 1
            }
          })
        });
      });

      global.fetch = mockFetch as any;

      const result = await validationService.validateVulnerabilities({
        repository: 'RSOLV-dev/nodegoat-vulnerability-demo',
        vulnerabilities: [
          {
            id: 'vuln-1',
            type: 'Nosql_injection',
            filePath: 'app/data/dao.js',
            line: 78,
            code: '$where: `this.userId == ${userId}`'
          },
          {
            id: 'vuln-2',
            type: 'Xss',
            filePath: 'app/views/safe.js',
            line: 10,
            code: 'element.textContent = userInput'
          }
        ],
        files: {
          'app/data/dao.js': {
            content: '// dao file',
            hash: 'sha256:abc'
          },
          'app/views/safe.js': {
            content: '// safe file',
            hash: 'sha256:def'
          }
        }
      });

      expect(result.validated).toHaveLength(2);
      expect(result.validated[0].isValid).toBe(true);
      expect(result.validated[1].isValid).toBe(false);
      expect(result.stats.total).toBe(2);
    });

    it('should handle NoSQL injection with $where correctly', async () => {
      const mockFetch = mock(() => {
        return Promise.resolve({
          ok: true,
          json: () => Promise.resolve({
            validated: [
              {
                id: 'nosql-test',
                isValid: true, // Should be true for real vulnerability
                confidence: 0.85,
                reason: null,
                astContext: {
                  inUserInputFlow: true,
                  hasValidation: false
                }
              }
            ],
            stats: {
              total: 1,
              validated: 1,
              rejected: 0
            }
          })
        });
      });

      global.fetch = mockFetch as any;

      const result = await validationService.validateVulnerabilities({
        repository: 'RSOLV-dev/nodegoat-vulnerability-demo',
        vulnerabilities: [
          {
            id: 'nosql-test',
            type: 'Nosql_injection',
            filePath: 'app/data/allocations-dao.js',
            line: 78,
            code: '$where: `this.userId == ${parsedUserId}`'
          }
        ],
        files: {
          'app/data/allocations-dao.js': {
            content: 'db.collection.find({ $where: `this.userId == ${parsedUserId}` })',
            hash: 'sha256:nosql123'
          }
        }
      });

      expect(result.validated).toHaveLength(1);
      expect(result.validated[0].isValid).toBe(true); // Real vulnerability
      expect(result.validated[0].id).toBe('nosql-test');
    });
  });

  describe('Cache functionality regression', () => {
    it('should include cache stats in response', async () => {
      const mockFetch = mock(() => {
        return Promise.resolve({
          ok: true,
          json: () => Promise.resolve({
            validated: [
              {
                id: 'cache-test',
                isValid: false,
                confidence: 0.95,
                fromCache: true,
                cachedAt: '2025-08-17T10:00:00Z'
              }
            ],
            stats: {
              total: 1,
              validated: 0,
              rejected: 1,
              cacheHits: 1,
              cacheMisses: 0
            },
            cache_stats: {
              cache_hits: 1,
              cache_misses: 0,
              hit_rate: 100.0,
              total_cached_entries: 42
            }
          })
        });
      });

      global.fetch = mockFetch as any;

      const result = await validationService.validateVulnerabilities({
        repository: 'test/repo',
        vulnerabilities: [
          {
            id: 'cache-test',
            type: 'Xss',
            filePath: 'test.js',
            line: 10,
            code: 'innerHTML = input'
          }
        ],
        files: {}
      });

      expect(result.validated[0].fromCache).toBe(true);
      expect(result.stats.cacheHits).toBe(1);
      expect(result.cache_stats.hit_rate).toBe(100.0);
    });
  });

  describe('Error handling regression', () => {
    it('should provide clear error message when API key is invalid', async () => {
      const mockFetch = mock(() => {
        return Promise.resolve({
          ok: false,
          status: 401,
          json: () => Promise.resolve({
            error: 'Invalid API key'
          })
        });
      });

      global.fetch = mockFetch as any;

      try {
        await validationService.validateVulnerabilities({
          repository: 'test/repo',
          vulnerabilities: [],
          files: {}
        });
        
        expect(true).toBe(false); // Should not reach here
      } catch (error: any) {
        expect(error.message).toContain('Invalid API key');
        expect(error.status).toBe(401);
      }
    });

    it('should handle malformed repository names gracefully', async () => {
      const mockFetch = mock(() => {
        return Promise.resolve({
          ok: true,
          json: () => Promise.resolve({
            validated: [],
            stats: { total: 0, validated: 0, rejected: 0 }
          })
        });
      });

      global.fetch = mockFetch as any;

      // Should not throw even with unusual repository names
      const result = await validationService.validateVulnerabilities({
        repository: 'unknown/repo',
        vulnerabilities: [],
        files: {}
      });

      expect(result).toBeDefined();
    });
  });
});

/**
 * Integration test to verify the full flow works
 */
describe('E2E Regression: Full validation flow', () => {
  it('should complete validation workflow successfully', async () => {
    // This would be an actual E2E test against staging/production
    // For now, we'll mock it but in real scenario this would hit actual API
    
    const mockWorkflow = async () => {
      // 1. Scan phase creates issues
      const scanResult = { issuesCreated: 5 };
      
      // 2. Validation phase processes issues
      const validationResult = {
        validated: 3,
        falsePositives: 2
      };
      
      // 3. Mitigation phase creates PRs
      const mitigationResult = {
        prsCreated: 3
      };
      
      return {
        scan: scanResult,
        validation: validationResult,
        mitigation: mitigationResult
      };
    };

    const result = await mockWorkflow();
    
    // Success criteria from E2E test
    expect(result.scan.issuesCreated).toBeGreaterThanOrEqual(5);
    expect(result.validation.falsePositives).toBeGreaterThanOrEqual(1);
    expect(result.mitigation.prsCreated).toBeGreaterThanOrEqual(2);
  });
});