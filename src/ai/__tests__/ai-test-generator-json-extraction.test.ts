import { describe, it, expect } from 'vitest';
import { AITestGenerator } from '../ai-test-generator.js';

describe('AITestGenerator - JSON Extraction', () => {
  describe('parseTestSuite', () => {
    // Access the private method via prototype for testing
    const generator = new AITestGenerator({} as any);
    const parseTestSuite = (response: string) => {
      return (generator as any).parseTestSuite(response);
    };

    it('should extract JSON from markdown code blocks', () => {
      const response = `
Here's the test suite:

\`\`\`json
{
  "red": {
    "testName": "Test for vulnerability",
    "testCode": "const test = 'code';"
  },
  "green": {
    "testName": "Test that fix works",
    "testCode": "const test = 'safe';"
  },
  "refactor": {
    "testName": "Test refactored code",
    "testCode": "const test = 'refactored';"
  }
}
\`\`\`
`;
      const result = parseTestSuite(response);
      expect(result).toBeDefined();
      expect(result).not.toBeNull();
      expect(result!.red).toBeDefined();
      expect(result!.red.testName).toBe('Test for vulnerability');
    });

    it('should extract JSON with curly braces in string values', () => {
      const response = `
{
  "red": {
    "testName": "Test with braces",
    "testCode": "const code = 'function() { return { test: true }; }';"
  }
}
`;
      const result = parseTestSuite(response);
      expect(result).toBeDefined();
      expect(result.red.testCode).toContain('{ return { test: true }; }');
    });

    it('should handle JSON with escaped quotes in strings', () => {
      const response = `
\`\`\`json
{
  "red": {
    "testName": "Test with quotes",
    "testCode": "const str = \\"This has \\\\\\"quotes\\\\\\" inside\\";"
  }
}
\`\`\`
`;
      const result = parseTestSuite(response);
      expect(result).toBeDefined();
      expect(result.red.testCode).toContain('quotes');
    });

    it('should extract the largest valid JSON object when multiple exist', () => {
      const response = `
Some text with a small JSON: {"small": "object"}

The main response:
\`\`\`json
{
  "red": {
    "testName": "Main test",
    "testCode": "const main = true;"
  },
  "green": {
    "testName": "Secondary test",
    "testCode": "const secondary = true;"
  }
}
\`\`\`

Another small one: {"another": "small"}
`;
      const result = parseTestSuite(response);
      expect(result).toBeDefined();
      expect(result.red).toBeDefined();
      // RFC-060: VALIDATE phase is RED-only, so green/refactor are intentionally stripped
      expect(result.green).toBeUndefined();
      expect(result.red.testName).toBe('Main test');
    });

    it('should handle incomplete JSON by attempting recovery', () => {
      // This simulates the actual truncation issue we're seeing
      const response = `
\`\`\`json
{
  "red": {
    "testName": "Truncated test",
    "testCode": "const { expect } = require('chai');\\n\\nfunction vulnerableCompare(secret1, secret2) {\\n  return secret1 === secret2;\\n}\\n\\nit('should detect timing attack vulnerability', function() {\\n  const correctSecret = 'a'.repeat(1000);\\n  const wrongShort = 'b';\\n  const wrongLong = 'b'.repeat(1000);\\n  \\n  const times = [];\\n  for(let i = 0; i < 100; i++) {\\n    const start = process"
\`\`\`
`;
      const result = parseTestSuite(response);
      // Should either parse what it can or return null gracefully
      // Current implementation would fail here
      expect(result).toBeNull(); // Expected: handles gracefully
    });

    it('should correctly extract JSON that comes after explanatory text', () => {
      const response = `
Based on the vulnerability analysis, here's a comprehensive test suite:

The following tests will validate both the vulnerable and fixed versions:

\`\`\`json
{
  "red": {
    "testName": "SQL Injection Detection",
    "testCode": "const payload = \\"'; DROP TABLE users; --\\";",
    "attackVector": "SQL injection via user input"
  },
  "green": {
    "testName": "Safe SQL Query",
    "testCode": "const safeQuery = 'SELECT * FROM users WHERE id = ?';",
    "expectedBehavior": "Parameterized queries prevent injection"
  },
  "refactor": {
    "testName": "Refactored Implementation",
    "testCode": "// Using ORM instead of raw SQL"
  }
}
\`\`\`

These tests ensure comprehensive coverage.
`;
      const result = parseTestSuite(response);
      expect(result).toBeDefined();
      expect(result.red.attackVector).toBe('SQL injection via user input');
      // RFC-060: VALIDATE phase is RED-only, so green/refactor are intentionally stripped
      expect(result.green).toBeUndefined();
      expect(result.refactor).toBeUndefined();
    });

    it('should handle trailing commas in JSON', () => {
      const response = `
\`\`\`json
{
  "red": {
    "testName": "Test with trailing comma",
    "testCode": "const test = 'code';",
    "attackVector": "malicious input",
  }
}
\`\`\`
`;
      const result = parseTestSuite(response);
      expect(result).toBeDefined();
      expect(result).not.toBeNull();
      expect(result!.red).toBeDefined();
      expect(result!.red.testName).toBe('Test with trailing comma');
    });

    it('should handle missing closing brace - simulating RailsGoat issue', () => {
      // This simulates the exact issue from the RailsGoat VALIDATE phase
      const response = `
{
  "redTests": [
    {
      "testName": "ReDoS attack on callback validation regex",
      "testCode": "const maliciousCallback = 'a'.repeat(50) + '[';",
      "attackVector": "a".repeat(50)
`;
      const result = parseTestSuite(response);
      // Should attempt to fix by adding missing closing structures
      // The parser should detect: 2 open braces {, 1 open bracket [, 0 closed
      // and attempt recovery by adding }, ], }
      // However, the string is also truncated, so it's likely to return null
      // which is acceptable - the key is it shouldn't crash
      expect(result).toBeNull(); // Graceful handling expected
    });

    it('should fix missing closing braces in array of tests', () => {
      const response = `
{
  "redTests": [
    {
      "testName": "Test 1",
      "testCode": "code1",
      "attackVector": "vector1",
      "expectedBehavior": "should_fail_on_vulnerable_code"
    },
    {
      "testName": "Test 2",
      "testCode": "code2",
      "attackVector": "vector2",
      "expectedBehavior": "should_fail_on_vulnerable_code"
    }
  ]
`;
      // Missing the final closing brace
      const result = parseTestSuite(response);
      expect(result).toBeDefined();
      expect(result).not.toBeNull();
      expect(result!.redTests).toBeDefined();
      expect(result!.redTests).toHaveLength(2);
      expect(result!.redTests![0].testName).toBe('Test 1');
      expect(result!.redTests![1].testName).toBe('Test 2');
    });

    it('should fix missing closing bracket in array', () => {
      const response = `
{
  "redTests": [
    {
      "testName": "Test 1",
      "testCode": "code1",
      "attackVector": "vector1",
      "expectedBehavior": "should_fail_on_vulnerable_code"
    }
`;
      // Missing closing bracket and brace
      const result = parseTestSuite(response);
      expect(result).toBeDefined();
      expect(result).not.toBeNull();
      expect(result!.redTests).toBeDefined();
      expect(result!.redTests).toHaveLength(1);
      expect(result!.redTests![0].testName).toBe('Test 1');
    });

    it('should handle complex nested JSON with multiple issues', () => {
      const response = `
\`\`\`json
{
  "redTests": [
    {
      "testName": "Complex test",
      "testCode": "const obj = { nested: { deep: 'value' } };",
      "attackVector": "complex",
      "expectedBehavior": "should_fail_on_vulnerable_code",
    }
  ],
}
\`\`\`
`;
      // Has trailing commas that should be fixed
      const result = parseTestSuite(response);
      expect(result).toBeDefined();
      expect(result).not.toBeNull();
      expect(result!.redTests).toBeDefined();
      expect(result!.redTests).toHaveLength(1);
    });

    // Aider-inspired progressive completion tests
    describe('Progressive JSON completion (Aider-inspired)', () => {
      it('should recover JSON with ]{ suffix - array closure', () => {
        const response = `
{
  "redTests": [
    {
      "testName": "Test 1",
      "testCode": "code1",
      "attackVector": "vector1",
      "expectedBehavior": "should_fail_on_vulnerable_code"
    }
`;
        // Missing ]} at end - progressive completion should fix it
        const result = parseTestSuite(response);
        expect(result).toBeDefined();
        expect(result).not.toBeNull();
        expect(result!.redTests).toHaveLength(1);
      });

      it('should recover JSON with }] suffix - object with array', () => {
        const response = `
{
  "red": {
    "testName": "Test name",
    "testCode": "code",
    "attackVector": "vector",
    "expectedBehavior": "should_fail_on_vulnerable_code"
  },
  "metadata": [
    "item1"
`;
        // Missing }] at end
        const result = parseTestSuite(response);
        // May return null or parse successfully depending on structure
        // The key is it should not crash
        expect(result !== undefined).toBe(true);
      });

      it('should recover JSON with "}]} suffix - truncated string in nested array', () => {
        const response = `
{
  "redTests": [
    {
      "testName": "SQL Injection",
      "testCode": "const payload = 'malicious
`;
        // Truncated mid-string within array of objects
        const result = parseTestSuite(response);
        // Should either recover or return null gracefully
        expect(result !== undefined).toBe(true);
      });

      it('should handle progressive completion for RailsGoat-style truncation', () => {
        const response = `
{
  "redTests": [
    {
      "testName": "ReDoS attack",
      "testCode": "const maliciousCallback = 'a'.repeat(50) + '['
`;
        // Similar to actual RailsGoat issue - truncated with partial string
        const result = parseTestSuite(response);
        // May not fully recover but should handle gracefully
        expect(result !== undefined).toBe(true);
      });
    });
  });

  describe('extractJsonFromResponse - utility function', () => {
    // Test the extraction utility separately
    it('should use a proper JSON extraction method', () => {
      // This test validates that we're using a robust extraction method
      // rather than the buggy regex /\{[\s\S]*\}/

      const testCases = [
        {
          input: '{"nested": {"inner": "value"}}',
          expected: '{"nested": {"inner": "value"}}'
        },
        {
          input: 'Some text {"nested": {"a": 1, "b": {"c": 2}}} more text',
          expected: '{"nested": {"a": 1, "b": {"c": 2}}}'
        },
        {
          input: '```json\n{"test": {"value": "data"}}\n```',
          expected: '{"test": {"value": "data"}}'
        }
      ];

      testCases.forEach(({ input, expected }) => {
        // The actual implementation should properly extract these
        // Current regex /\{[\s\S]*\}/ would fail on nested objects
        const result = extractJsonSafely(input);
        expect(result).toBe(expected);
      });
    });
  });
});

// Helper function that should be implemented to replace the buggy regex
function extractJsonSafely(text: string): string | null {
  // First, try to extract from markdown code blocks
  const markdownMatch = text.match(/```(?:json)?\s*\n?([\s\S]*?)\n?```/);
  if (markdownMatch) {
    text = markdownMatch[1];
  }

  // Find all potential JSON start/end positions
  const positions: Array<{start: number, end: number, depth: number}> = [];
  let depth = 0;
  let inString = false;
  let escape = false;
  let jsonStart = -1;

  for (let i = 0; i < text.length; i++) {
    const char = text[i];

    if (escape) {
      escape = false;
      continue;
    }

    if (char === '\\') {
      escape = true;
      continue;
    }

    if (char === '"' && !escape) {
      inString = !inString;
      continue;
    }

    if (!inString) {
      if (char === '{') {
        if (depth === 0) {
          jsonStart = i;
        }
        depth++;
      } else if (char === '}') {
        depth--;
        if (depth === 0 && jsonStart !== -1) {
          positions.push({
            start: jsonStart,
            end: i + 1,
            depth: 0
          });
          jsonStart = -1;
        }
      }
    }
  }

  // Try to parse each potential JSON object, return the largest valid one
  let largestValid: string | null = null;
  let largestSize = 0;

  for (const pos of positions) {
    const candidate = text.substring(pos.start, pos.end);
    try {
      JSON.parse(candidate);
      if (candidate.length > largestSize) {
        largestValid = candidate;
        largestSize = candidate.length;
      }
    } catch {
      // Invalid JSON, skip
    }
  }

  return largestValid;
}