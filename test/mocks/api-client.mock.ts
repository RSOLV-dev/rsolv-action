/**
 * Mock implementation of RsolvApiClient for unit tests
 * Provides consistent, predictable responses without hitting real APIs
 */

import { jest, spyOn, mock } from 'bun:test';
const vi = { fn: jest.fn, clearAllMocks: jest.clearAllMocks, restoreAllMocks: jest.restoreAllMocks };

export class MockRsolvApiClient {
  constructor(public apiKey: string) {}
  
  getPatterns = vi.fn().mockResolvedValue([
    {
      id: 'sql-injection-1',
      type: 'sql_injection',
      severity: 'high',
      languages: ['javascript', 'typescript'],
      regex: 'query\\(.*\\$\\{.*\\}',
      description: 'SQL injection vulnerability'
    },
    {
      id: 'xss-1',
      type: 'xss',
      severity: 'medium',
      languages: ['javascript'],
      regex: 'innerHTML\\s*=.*\\$\\{',
      description: 'Cross-site scripting vulnerability'
    }
  ]);
  
  validateVulnerabilities = vi.fn().mockResolvedValue({
    validated: [
      {
        id: 'test-1',
        isValid: true,
        confidence: 0.95,
        reason: null
      }
    ],
    stats: {
      total: 1,
      validated: 1,
      rejected: 0
    }
  });
  
  exchangeCredentials = vi.fn().mockResolvedValue({
    credentials: {
      anthropic: {
        api_key: 'mock-anthropic-key',
        expires_at: new Date(Date.now() + 3600000).toISOString()
      },
      openai: {
        api_key: 'mock-openai-key',
        expires_at: new Date(Date.now() + 3600000).toISOString()
      }
    },
    usage: {
      remaining_fixes: 100,
      reset_at: new Date(Date.now() + 86400000).toISOString()
    }
  });
  
  refreshCredentials = vi.fn().mockResolvedValue({
    credentials: {
      anthropic: {
        api_key: 'mock-refreshed-anthropic-key',
        expires_at: new Date(Date.now() + 3600000).toISOString()
      }
    }
  });
  
  recordFixAttempt = vi.fn().mockResolvedValue({
    success: true,
    fixId: 'fix-123',
    message: 'Fix attempt recorded'
  });
  
  analyzeWithAST = vi.fn().mockResolvedValue({
    vulnerabilities: [],
    metadata: {
      language: 'javascript',
      parseTime: 10,
      analysisTime: 20
    }
  });
}

export function createMockApiClient(apiKey = 'test-api-key'): MockRsolvApiClient {
  return new MockRsolvApiClient(apiKey);
}