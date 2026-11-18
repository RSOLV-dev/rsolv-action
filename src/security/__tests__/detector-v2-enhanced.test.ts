import { describe, it, expect, vi } from 'vitest';
import { SecurityDetectorV2 } from '../detector-v2.js';
import type { PatternSource } from '../pattern-source.js';
import { VulnerabilityType, type SecurityPattern } from '../types.js';

vi.mock('../../utils/logger.js', () => ({
  logger: { info: vi.fn(), warn: vi.fn(), error: vi.fn(), debug: vi.fn() }
}));

function sourceOf(patterns: SecurityPattern[]): PatternSource {
  return {
    getPatternsByLanguage: async () => patterns,
    getPatternById: async () => null,
    getAllPatterns: async () => patterns
  } as unknown as PatternSource;
}

const evalPattern: SecurityPattern = {
  id: 'js-eval-user-input',
  name: 'Eval with user input',
  type: VulnerabilityType.CODE_INJECTION,
  severity: 'critical',
  description: 'eval() of user input',
  patterns: { regex: [/eval\s*\(/im] },
  languages: ['javascript'],
  cweId: 'CWE-95',
  owaspCategory: 'A03:2021',
  remediation: 'Do not eval user input',
  examples: { vulnerable: 'eval(req.body.x)', secure: 'JSON.parse(req.body.x)' }
};

describe('SecurityDetectorV2#detect', () => {
  describe('when an enhanced pattern has an AST rule the interpreter cannot match', () => {
    it('still reports what the pattern\'s regex matches', async () => {
      const enhanced = { ...evalPattern, astRules: { node_type: 'ImportDeclaration', unsupported_rule: true } };
      const detector = new SecurityDetectorV2(sourceOf([enhanced]));

      const found = await detector.detect('const x = 1;\neval(req.body.code);\n', 'javascript', 'app.js');

      expect(found.map(v => [v.type, v.line])).toEqual([[VulnerabilityType.CODE_INJECTION, 2]]);
      detector.cleanup();
    });
  });
});
