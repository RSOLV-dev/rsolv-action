import { describe, it, expect, vi } from 'vitest';
import { PatternAPIClient, type PatternData } from '../pattern-api-client.js';

vi.mock('../../utils/logger.js', () => ({
  logger: { info: vi.fn(), warn: vi.fn(), error: vi.fn(), debug: vi.fn() }
}));

function apiPattern(overrides: Partial<PatternData> & Record<string, unknown> = {}): PatternData {
  return {
    id: 'python-unsafe-pickle',
    name: 'Insecure Deserialization via pickle',
    type: 'deserialization',
    description: 'pickle.loads() can execute arbitrary code',
    severity: 'critical',
    regex: 'pickle\\.loads?\\s*\\(',
    languages: ['python'],
    recommendation: 'Use json.loads()',
    ...overrides
  } as PatternData;
}

const astRules = { node_type: 'Call', function_names: ['pickle.loads'] };
const contextRules = { exclude_paths: ['test'], check_data_source: true };
const confidenceRules = { base: 0.9, adjustments: { test_code: -0.8 } };

describe('PatternAPIClient#convertToSecurityPattern', () => {
  const client = new PatternAPIClient({ apiKey: 'test-key' });

  describe('when the enhanced API serves camelCase rule fields', () => {
    const converted = client.convertToSecurityPattern(apiPattern({
      astRules,
      contextRules,
      confidenceRules,
      minConfidence: 0.7,
      examples: { vulnerable: ['data = pickle.loads(user_data)'], safe: ['data = json.loads(user_data)'] }
    }));

    it('carries the AST, context and confidence rules onto the pattern', () => {
      expect(converted.astRules).toEqual(astRules);
      expect(converted.contextRules).toEqual(contextRules);
      expect(converted.confidenceRules).toEqual(confidenceRules);
      expect(converted.minConfidence).toBe(0.7);
    });

    it('takes the first vulnerable and safe example', () => {
      expect(converted.examples).toEqual({
        vulnerable: 'data = pickle.loads(user_data)',
        secure: 'data = json.loads(user_data)'
      });
    });
  });

  describe('when an older API serves snake_case rule fields', () => {
    const converted = client.convertToSecurityPattern(apiPattern({
      ast_rules: astRules,
      context_rules: contextRules,
      confidence_rules: confidenceRules,
      min_confidence: 0.6,
      test_cases: { vulnerable: ['pickle.load(f)'], safe: ['json.load(f)'] }
    }));

    it('still carries the rules', () => {
      expect(converted.astRules).toEqual(astRules);
      expect(converted.contextRules).toEqual(contextRules);
      expect(converted.confidenceRules).toEqual(confidenceRules);
      expect(converted.minConfidence).toBe(0.6);
      expect(converted.examples).toEqual({ vulnerable: 'pickle.load(f)', secure: 'json.load(f)' });
    });
  });

  describe('when the API sends null rules', () => {
    it('leaves them undefined, so detectors see no AST rules', () => {
      const converted = client.convertToSecurityPattern(apiPattern({ astRules: null, minConfidence: null }));

      expect(converted.astRules).toBeUndefined();
      expect(converted.minConfidence).toBeUndefined();
    });
  });
});
