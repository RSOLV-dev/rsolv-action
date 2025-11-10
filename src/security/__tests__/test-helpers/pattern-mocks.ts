/**
 * Test helpers for pattern API mocking
 * Reduces boilerplate in pattern-related tests
 */

import type { PatternData, PatternResponse } from '../../pattern-api-client.js';

/**
 * Default pattern fields that are common across all tests
 */
const DEFAULT_PATTERN_FIELDS = {
  description: 'eval() can execute arbitrary code',
  severity: 'critical' as const,
  patterns: ['eval\\s*\\('],
  recommendation: 'Avoid eval',
  cwe_id: 'CWE-94',
  owasp_category: 'A03:2021',
  test_cases: { vulnerable: [], safe: [] }
};

/**
 * Create a mock pattern with sensible defaults
 */
export function createMockPattern(overrides: Partial<PatternData> & { id: string; languages: string[] }): PatternData {
  return {
    name: `${overrides.languages?.[0] || 'language'} eval()`,
    type: 'code_injection',
    ...DEFAULT_PATTERN_FIELDS,
    ...overrides
  };
}

/**
 * Create a mock API response
 */
export function createMockResponse(patterns: PatternData[], language = 'javascript'): PatternResponse {
  return {
    count: patterns.length,
    language,
    patterns
  };
}

/**
 * Setup fetch mock to return patterns
 */
export function mockPatternFetch(fetchMock: any, patterns: PatternData[], language = 'javascript'): void {
  fetchMock.mockResolvedValueOnce({
    ok: true,
    json: async () => createMockResponse(patterns, language)
  });
}

/**
 * Common pattern configurations for different languages
 */
export const LANGUAGE_PATTERNS = {
  javascript: (overrides?: Partial<PatternData>) => createMockPattern({
    id: 'js-eval-user-input',
    languages: ['javascript'],
    ...overrides
  }),

  python: (overrides?: Partial<PatternData>) => createMockPattern({
    id: 'python-eval-user-input',
    languages: ['python'],
    ...overrides
  }),

  ruby: (overrides?: Partial<PatternData>) => createMockPattern({
    id: 'ruby-eval-user-input',
    languages: ['ruby'],
    recommendation: 'Use safer alternatives like JSON.parse or YAML.safe_load',
    ...overrides
  }),

  php: (overrides?: Partial<PatternData>) => createMockPattern({
    id: 'php-eval-user-input',
    languages: ['php'],
    ...overrides
  })
};

/**
 * RailsGoat-specific eval pattern with actual regex
 */
export function createRailsGoatPattern(): PatternData {
  return createMockPattern({
    id: 'js-eval-user-input',
    name: 'JavaScript eval() with user input',
    languages: ['javascript'],
    patterns: ['^(?!.*\\/\\/).*eval\\s*\\(.*?(?:req\\.|request\\.|params\\.|query\\.|body\\.|user|input|data|Code)'],
    recommendation: 'Avoid eval(). Use JSON.parse() for JSON data or find safer alternatives.',
    test_cases: {
      vulnerable: ['eval(request.responseText)'],
      safe: ['// eval(request.responseText)']
    }
  });
}
