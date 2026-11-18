import { describe, it, expect, vi, afterEach } from 'vitest';
import { readFileSync, readdirSync } from 'fs';
import { SecurityDetectorV2 } from '../detector-v2.js';
import { ASTPatternInterpreter } from '../ast-pattern-interpreter.js';
import { PatternAPIClient, type PatternResponse } from '../pattern-api-client.js';
import type { PatternSource } from '../pattern-source.js';
import { VulnerabilityType, type SecurityPattern } from '../types.js';

vi.mock('../../utils/logger.js', () => ({
  logger: { info: vi.fn(), warn: vi.fn(), error: vi.fn(), debug: vi.fn() }
}));

const fixtures = new URL('./fixtures/', import.meta.url);
const served: PatternResponse = JSON.parse(readFileSync(new URL('patterns-python-enhanced.json', fixtures), 'utf8'));
const enhanced = served.patterns.map(p => new PatternAPIClient({ apiKey: 'k' }).convertToSecurityPattern(p));
// What main's client produced from the same response: it never read the camelCase rules.
const asOnMain = enhanced.map(p => ({ ...p, astRules: undefined, contextRules: undefined, confidenceRules: undefined, minConfidence: undefined }));
const demoDir = new URL('python-demo/', fixtures);
const demoFiles = readdirSync(demoDir).map(name => ({ name, code: readFileSync(new URL(name, demoDir), 'utf8') }));

function sourceOf(patterns: SecurityPattern[]): PatternSource {
  return {
    getPatternsByLanguage: async () => patterns,
    getPatternById: async () => null,
    getAllPatterns: async () => patterns
  } as unknown as PatternSource;
}

async function detectAll(detector: SecurityDetectorV2) {
  const results = [];
  for (const { name, code } of demoFiles) results.push(...await detector.detect(code, 'python', `app/${name}`));
  detector.cleanup();
  return results;
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
  examples: { vulnerable: 'eval(req.body.x)', secure: 'JSON.parse(req.body.x)' },
  astRules: { node_type: 'ImportDeclaration' }
};

describe('SecurityDetectorV2#detect', () => {
  afterEach(() => vi.restoreAllMocks());

  describe('by default, with enhanced rules populated', () => {
    it('finds exactly what main found in the demo files, snippets included', async () => {
      const withRules = await detectAll(new SecurityDetectorV2(sourceOf(enhanced)));
      const onMain = await detectAll(new SecurityDetectorV2(sourceOf(asOnMain)));

      expect(onMain.length).toBeGreaterThan(0);
      expect(withRules).toEqual(onMain);
    });

    it('still treats a parameterised SQL line as safe usage', async () => {
      const { code } = demoFiles.find(f => f.name === 'safe_usage.py')!;

      const found = await new SecurityDetectorV2(sourceOf(enhanced)).detect(code, 'python', 'app/safe_usage.py');

      expect(found.filter(v => v.type === VulnerabilityType.SQL_INJECTION)).toEqual([]);
    });

    it('never runs the AST interpreter, so a slow AST cannot hold up regex', async () => {
      const scanFile = vi.spyOn(ASTPatternInterpreter.prototype, 'scanFile').mockReturnValue(new Promise(() => {}));
      const detector = new SecurityDetectorV2(sourceOf([evalPattern]));

      const found = await detector.detect('const x = 1;\neval(req.body.code);\n', 'javascript', 'app.js');

      expect(scanFile).not.toHaveBeenCalled();
      expect(found.map(v => [v.type, v.line])).toEqual([[VulnerabilityType.CODE_INJECTION, 2]]);
      detector.cleanup();
    });
  });

  describe('when client-side AST is opted in', () => {
    it('hands the enhanced patterns to the AST interpreter instead of regex', async () => {
      const scanFile = vi.spyOn(ASTPatternInterpreter.prototype, 'scanFile').mockResolvedValue([]);
      const detector = new SecurityDetectorV2(sourceOf([evalPattern]), { clientAst: true });

      const found = await detector.detect('eval(req.body.code);\n', 'javascript', 'app.js');

      expect(scanFile).toHaveBeenCalledWith('app.js', expect.any(String), [evalPattern]);
      expect(found).toEqual([]);
      detector.cleanup();
    });
  });
});
