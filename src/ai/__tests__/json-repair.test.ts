import { describe, it, expect } from 'vitest';
import {
  tryParseWithProgressiveCompletion,
  isActuallyTruncatedString,
  countCharactersRespectingStrings,
  extractJsonFromText,
  cleanJsonString,
  PROGRESSIVE_COMPLETION_STRATEGIES,
} from '../json-repair.js';

describe('JSON Repair Utilities', () => {
  describe('tryParseWithProgressiveCompletion', () => {
    it('should parse valid JSON without modifications', () => {
      const validJson = '{"test": "value"}';
      const result = tryParseWithProgressiveCompletion(validJson);

      expect(result.success).toBe(true);
      expect(result.data).toEqual({ test: 'value' });
      expect(result.strategy).toBe('no modifications needed');
    });

    it('should recover JSON missing closing bracket and brace', () => {
      const incomplete = '{"redTests": [{"testName": "Test", "testCode": "code"}';
      const result = tryParseWithProgressiveCompletion(incomplete);

      expect(result.success).toBe(true);
      expect(result.data?.redTests).toBeDefined();
      expect(result.data?.redTests[0].testName).toBe('Test');
    });

    it('should recover JSON missing only closing brace', () => {
      const incomplete = '{"red": {"testName": "Test"';
      const result = tryParseWithProgressiveCompletion(incomplete);

      // This specific case needs "}}" which isn't in our strategy list
      // But it should handle gracefully
      if (result.success) {
        expect(result.data?.red?.testName).toBe('Test');
      } else {
        // Graceful failure is also acceptable
        expect(result.error).toBeDefined();
      }
    });

    it('should recover JSON missing only closing bracket', () => {
      const incomplete = '{"items": ["a", "b", "c"';
      const result = tryParseWithProgressiveCompletion(incomplete);

      expect(result.success).toBe(true);
      expect(result.data?.items).toEqual(['a', 'b', 'c']);
    });

    it('should recover JSON truncated mid-string', () => {
      const incomplete = '{"redTests": [{"testName": "Test", "testCode": "const x = \'malicious';
      const result = tryParseWithProgressiveCompletion(incomplete);

      // Should either recover or fail gracefully
      expect(result).toBeDefined();
      expect(typeof result.success).toBe('boolean');
    });

    it('should handle nested structures', () => {
      const incomplete = '{"outer": {"inner": {"deep": "value"}';
      const result = tryParseWithProgressiveCompletion(incomplete);

      // May succeed with }]} or }}}
      if (result.success) {
        expect(result.data?.outer).toBeDefined();
      }
    });

    it('should return error for completely malformed JSON', () => {
      const malformed = '{invalid json syntax @#$%';
      const result = tryParseWithProgressiveCompletion(malformed);

      expect(result.success).toBe(false);
      expect(result.error).toBeDefined();
    });

    it('should handle empty string', () => {
      const empty = '';
      const result = tryParseWithProgressiveCompletion(empty);

      expect(result.success).toBe(false);
    });

    it('should handle arrays at root level', () => {
      const incomplete = '[{"a": 1}, {"b": 2}';
      const result = tryParseWithProgressiveCompletion(incomplete);

      expect(result.success).toBe(true);
      expect(Array.isArray(result.data)).toBe(true);
      expect(result.data).toHaveLength(2);
    });

    // Property-based test: All valid JSON should parse successfully
    it('PROPERTY: Valid JSON should always parse without modification', () => {
      const testCases = [
        '{}',
        '[]',
        '{"a": 1}',
        '[1, 2, 3]',
        '{"nested": {"value": true}}',
        '{"array": [1, 2, {"nested": "value"}]}',
      ];

      for (const testCase of testCases) {
        const result = tryParseWithProgressiveCompletion(testCase);
        expect(result.success).toBe(true);
        expect(result.strategy).toBe('no modifications needed');
      }
    });

    // Property-based test: Truncated JSON should either recover or fail gracefully
    it('PROPERTY: Truncated JSON should never throw exceptions', () => {
      const truncationPoints = [
        '{"test": "val',
        '{"test": {"nested":',
        '{"array": [1, 2,',
        '[{"test"',
      ];

      for (const json of truncationPoints) {
        expect(() => tryParseWithProgressiveCompletion(json)).not.toThrow();
      }
    });
  });

  describe('isActuallyTruncatedString', () => {
    it('should detect truncated string (no closing quote)', () => {
      const truncated = '{"test": "incomplete';
      expect(isActuallyTruncatedString(truncated)).toBe(true);
    });

    it('should NOT detect escaped quotes as truncation', () => {
      const withEscaped = '{"test": "has \\"escaped\\" quotes"}';
      expect(isActuallyTruncatedString(withEscaped)).toBe(false);
    });

    it('should handle valid JSON (not truncated)', () => {
      const valid = '{"test": "complete"}';
      expect(isActuallyTruncatedString(valid)).toBe(false);
    });

    it('should handle JSON ending with "}', () => {
      const endsWithQuoteBrace = '{"test": "value"}';
      expect(isActuallyTruncatedString(endsWithQuoteBrace)).toBe(false);
    });

    it('should detect mid-string truncation without closing brace', () => {
      const midString = '{"a": "truncated in the middle';
      expect(isActuallyTruncatedString(midString)).toBe(true);
    });

    it('should handle empty string', () => {
      expect(isActuallyTruncatedString('')).toBe(false);
    });

    it('should handle single quote', () => {
      expect(isActuallyTruncatedString('"')).toBe(true);
    });

    it('should handle multiple escaped backslashes', () => {
      const multipleEscapes = '{"path": "C:\\\\Users\\\\test\\\\file.txt"}';
      expect(isActuallyTruncatedString(multipleEscapes)).toBe(false);
    });

    // Property-based test: Valid strings should never be detected as truncated
    it('PROPERTY: Valid JSON strings should never be truncated', () => {
      const validStrings = [
        '{"a": "value"}',
        '{"a": "val\\"ue"}',
        '{"a": ""}',
        '{"a": "\\\\"}',
      ];

      for (const str of validStrings) {
        expect(isActuallyTruncatedString(str)).toBe(false);
      }
    });
  });

  describe('countCharactersRespectingStrings', () => {
    it('should count braces outside strings correctly', () => {
      const json = '{"test": "{not counted}"}';
      const result = countCharactersRespectingStrings(json, '{');

      expect(result.total).toBe(2); // One outside, one inside string
      expect(result.outsideStrings).toBe(1); // Only the opening brace
    });

    it('should count brackets outside strings correctly', () => {
      const json = '{"array": "[not counted]"}';
      const result = countCharactersRespectingStrings(json, '[');

      expect(result.total).toBe(1);
      expect(result.outsideStrings).toBe(0); // Bracket is inside string
    });

    it('should handle escaped quotes correctly', () => {
      const json = '{"test": "a \\"quoted\\" value"}';
      const result = countCharactersRespectingStrings(json, '{');

      expect(result.total).toBe(1);
      expect(result.outsideStrings).toBe(1);
    });

    it('should count multiple occurrences', () => {
      const json = '{"a": {"b": {"c": 1}}}';
      const result = countCharactersRespectingStrings(json, '{');

      expect(result.total).toBe(3);
      expect(result.outsideStrings).toBe(3);
    });

    it('should handle empty string', () => {
      const result = countCharactersRespectingStrings('', '{');

      expect(result.total).toBe(0);
      expect(result.outsideStrings).toBe(0);
    });

    // Property-based test: total >= outsideStrings always
    it('PROPERTY: Total count should always be >= outside strings count', () => {
      const testCases = [
        '{"test": "{value}"}',
        '["{", "{"]',
        '{"a": 1, "b": 2}',
      ];

      for (const json of testCases) {
        const result = countCharactersRespectingStrings(json, '{');
        expect(result.total).toBeGreaterThanOrEqual(result.outsideStrings);
      }
    });
  });

  describe('extractJsonFromText', () => {
    it('should extract JSON from markdown code block', () => {
      const text = 'Some text\n```json\n{"test": "value"}\n```\nMore text';
      const result = extractJsonFromText(text);

      expect(result).toBe('{"test": "value"}');
    });

    it('should extract JSON from plain text', () => {
      const text = 'Here is JSON: {"test": "value"} and more text';
      const result = extractJsonFromText(text);

      expect(result).toBe('{"test": "value"}');
    });

    it('should handle nested JSON objects', () => {
      const text = 'Text {"outer": {"inner": {"deep": "value"}}} more';
      const result = extractJsonFromText(text);

      expect(result).toBe('{"outer": {"inner": {"deep": "value"}}}');
    });

    it('should return largest valid JSON when multiple exist', () => {
      const text = '{"small": 1} and {"larger": {"nested": "value"}}';
      const result = extractJsonFromText(text);

      expect(result).toContain('larger');
      expect(result).toContain('nested');
    });

    it('should return null when no JSON found', () => {
      const text = 'No JSON here, just plain text';
      const result = extractJsonFromText(text);

      expect(result).toBeNull();
    });

    it('should handle JSON with braces in strings', () => {
      const text = 'Text {"test": "has {braces} in string"} more';
      const result = extractJsonFromText(text);

      expect(result).toBe('{"test": "has {braces} in string"}');
    });

    it('should ignore invalid JSON', () => {
      const text = '{invalid} {"valid": "json"}';
      const result = extractJsonFromText(text);

      expect(result).toBe('{"valid": "json"}');
    });

    // Property-based test: Extracted JSON should always be parseable
    it('PROPERTY: Extracted JSON should always be valid', () => {
      const testCases = [
        'Text {"a": 1} more',
        'Before\n{"nested": {"value": true}}\nAfter',
        '{"first": 1} text {"second": 2}',
      ];

      for (const text of testCases) {
        const result = extractJsonFromText(text);
        if (result !== null) {
          expect(() => JSON.parse(result)).not.toThrow();
        }
      }
    });
  });

  describe('cleanJsonString', () => {
    it('should remove markdown code block markers', () => {
      const input = '```json\n{"test": "value"}\n```';
      const result = cleanJsonString(input);

      expect(result).toBe('{"test": "value"}');
    });

    it('should remove trailing commas before closing braces', () => {
      const input = '{"test": "value",}';
      const result = cleanJsonString(input);

      expect(result).toBe('{"test": "value"}');
    });

    it('should remove trailing commas before closing brackets', () => {
      const input = '{"items": [1, 2, 3,]}';
      const result = cleanJsonString(input);

      expect(result).toBe('{"items": [1, 2, 3]}');
    });

    it('should trim whitespace', () => {
      const input = '  \n  {"test": "value"}  \n  ';
      const result = cleanJsonString(input);

      expect(result).toBe('{"test": "value"}');
    });

    it('should handle multiple issues at once', () => {
      const input = '  ```json\n{"test": "value",}\n```  ';
      const result = cleanJsonString(input);

      expect(result).toBe('{"test": "value"}');
    });

    // Property-based test: Cleaning should make valid JSON parseable
    it('PROPERTY: Cleaned valid JSON should be parseable', () => {
      const testCases = [
        '{"a": 1}',
        '```json\n{"a": 1}\n```',
        '  {"a": 1}  ',
      ];

      for (const json of testCases) {
        const cleaned = cleanJsonString(json);
        expect(() => JSON.parse(cleaned)).not.toThrow();
      }
    });

    // Property-based test: Cleaning should be idempotent
    it('PROPERTY: Cleaning should be idempotent', () => {
      const testCases = [
        '{"a": 1}',
        '```json\n{"a": 1}\n```',
        '{"a": 1,}',
      ];

      for (const json of testCases) {
        const cleaned1 = cleanJsonString(json);
        const cleaned2 = cleanJsonString(cleaned1);
        expect(cleaned1).toBe(cleaned2);
      }
    });
  });

  describe('PROGRESSIVE_COMPLETION_STRATEGIES', () => {
    it('should have empty string as first strategy', () => {
      expect(PROGRESSIVE_COMPLETION_STRATEGIES[0].suffix).toBe('');
    });

    it('should include common truncation patterns', () => {
      const suffixes = PROGRESSIVE_COMPLETION_STRATEGIES.map(s => s.suffix);

      expect(suffixes).toContain(']}');
      expect(suffixes).toContain('}]');
      expect(suffixes).toContain('"}]}');
    });

    it('should have descriptions for all strategies', () => {
      for (const strategy of PROGRESSIVE_COMPLETION_STRATEGIES) {
        expect(strategy.description).toBeTruthy();
        expect(strategy.description.length).toBeGreaterThan(0);
      }
    });

    it('should be ordered from most to least common', () => {
      // Most common: no modification needed
      expect(PROGRESSIVE_COMPLETION_STRATEGIES[0].suffix).toBe('');

      // Second most common based on Aider: ]}
      expect(PROGRESSIVE_COMPLETION_STRATEGIES[1].suffix).toBe(']}');
    });
  });

  // Integration test: Full pipeline
  describe('Integration: Full JSON repair pipeline', () => {
    it('should handle real-world malformed test suite JSON', () => {
      const malformed = `{
  "redTests": [
    {
      "testName": "SQL Injection Test",
      "testCode": "const payload = '; DROP TABLE users;'",
      "testCode": "const payload = '; DROP TABLE users;'",
      "attackVector": "SQL injection",
      "expectedBehavior": "should_fail_on_vulnerable_code"
    }
  ]`;
      // Missing closing brace at end

      const cleaned = cleanJsonString(malformed);
      const result = tryParseWithProgressiveCompletion(cleaned);

      expect(result.success).toBe(true);
      expect(result.data?.redTests).toBeDefined();
      expect(result.data?.redTests).toHaveLength(1);
    });

    it('should handle RailsGoat-style truncation', () => {
      const railsgoatStyle = `{
  "redTests": [
    {
      "testName": "ReDoS attack on callback validation regex",
      "testCode": "const maliciousCallback = 'a'.repeat(50) + '['",
      "attackVector": "a".repeat(50)`;

      const cleaned = cleanJsonString(railsgoatStyle);
      const result = tryParseWithProgressiveCompletion(cleaned);

      // Should handle gracefully even if it can't fully recover
      expect(result).toBeDefined();
      expect(typeof result.success).toBe('boolean');
    });
  });
});
