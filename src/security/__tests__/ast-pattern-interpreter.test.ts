import { describe, it, expect, afterEach } from 'vitest';
import { SecurityPattern, VulnerabilityType } from '../types.js';

/**
 * ASTPatternInterpreter decides whether a vulnerability is reported. Everything
 * downstream — issue creation, VALIDATE, MITIGATE — is gated on what it returns,
 * so a silent regression here reads as "the repo is clean" rather than as a
 * failure.
 *
 * These specs are deliberately one-behaviour-per-example. The previous version
 * packed a true positive and three false positives into a single `it`, so the
 * first failing expectation hid the other three, and the whole AST safety net
 * showed up in the suite as a single test.
 */

type CleanupCapable = { cleanup: () => void };

/**
 * Factory rather than a shared fixture: each spec states only the attributes it
 * depends on, so a spec about confidence does not silently rely on someone
 * else's regex.
 */
function sqlInjectionPattern(overrides: Partial<SecurityPattern> = {}): SecurityPattern {
  return {
    id: 'js-sql-injection-concat',
    name: 'SQL Injection via String Concatenation',
    type: VulnerabilityType.SQL_INJECTION,
    severity: 'critical',
    description: 'SQL injection through string concatenation',
    patterns: { regex: [/SELECT.*FROM.*\+/i, /INSERT.*VALUES.*\+/i] },
    languages: ['javascript'],
    frameworks: [],
    cweId: 'CWE-89',
    owaspCategory: 'A03:2021',
    remediation: 'Use parameterized queries',
    examples: {
      vulnerable: 'db.query("SELECT * FROM users WHERE id = " + userId)',
      secure: 'db.query("SELECT * FROM users WHERE id = ?", [userId])'
    },
    astRules: {
      node_type: 'BinaryExpression',
      operator: '+',
      context_analysis: {
        contains_sql_keywords: true,
        has_user_input_in_concatenation: true,
        within_db_call: true
      },
      ancestor_requirements: {
        has_db_method_call: '\\.(?:query|execute|exec|run|all|get)',
        max_depth: 3
      }
    },
    contextRules: {
      exclude_paths: ['test/', 'spec/', '__tests__/', 'fixtures/', 'mocks/'],
      exclude_if_parameterized: true,
      exclude_if_uses_orm_builder: true,
      exclude_if_logging_only: true,
      safe_if_input_validated: true
    },
    confidenceRules: {
      base: 0.3,
      adjustments: {
        direct_req_param_concat: 0.5,
        within_db_query_call: 0.3,
        has_sql_keywords: 0.2,
        uses_parameterized_query: -0.9,
        uses_orm_query_builder: -0.8,
        is_console_log: -1.0,
        has_input_validation: -0.7,
        in_test_file: -0.9
      }
    },
    minConfidence: 0.8,
    ...overrides
  };
}

const VULNERABLE_QUERY = `
  const userId = req.params.id;
  const query = "SELECT * FROM users WHERE id = " + userId;
  db.query(query, (err, results) => {
    res.json(results);
  });
`;

describe('ASTPatternInterpreter', () => {
  let interpreter: CleanupCapable | null = null;

  async function newInterpreter() {
    const { ASTPatternInterpreter } = await import('../ast-pattern-interpreter.js');
    const instance = new ASTPatternInterpreter();
    interpreter = instance as unknown as CleanupCapable;
    return instance;
  }

  afterEach(() => {
    interpreter?.cleanup();
    interpreter = null;
  });

  describe('scanFile', () => {
    describe('when the code concatenates user input into a database query', () => {
      it('reports the vulnerability', async () => {
        const subject = await newInterpreter();

        const findings = await subject.scanFile('api/users.js', VULNERABLE_QUERY, [
          sqlInjectionPattern()
        ]);

        expect(findings).toHaveLength(1);
      });

      it('reports it with confidence at or above the pattern threshold', async () => {
        const subject = await newInterpreter();

        const findings = await subject.scanFile('api/users.js', VULNERABLE_QUERY, [
          sqlInjectionPattern()
        ]);

        expect(findings[0].confidence).toBeGreaterThanOrEqual(0.8);
      });

      it('attributes the finding to the pattern that matched', async () => {
        const subject = await newInterpreter();

        const findings = await subject.scanFile('api/users.js', VULNERABLE_QUERY, [
          sqlInjectionPattern()
        ]);

        expect(findings[0].pattern.id).toBe('js-sql-injection-concat');
      });
    });

    describe('when the concatenated SQL is only logged', () => {
      it('does not report it', async () => {
        const subject = await newInterpreter();

        const findings = await subject.scanFile(
          'debug.js',
          `
            const query = "SELECT * FROM users WHERE id = " + userId;
            console.log("Query: " + query);
          `,
          [sqlInjectionPattern()]
        );

        expect(findings).toHaveLength(0);
      });
    });

    describe('when the query is parameterized', () => {
      it('does not report it', async () => {
        const subject = await newInterpreter();

        const findings = await subject.scanFile(
          'api/secure-users.js',
          `
            const userId = req.params.id;
            const query = "SELECT * FROM users WHERE id = ?";
            db.query(query, [userId], (err, results) => {
              res.json(results);
            });
          `,
          [sqlInjectionPattern()]
        );

        expect(findings).toHaveLength(0);
      });
    });

    describe('when the file is a test file', () => {
      it('does not report vulnerabilities found in it', async () => {
        const subject = await newInterpreter();

        const findings = await subject.scanFile(
          '__tests__/user.test.js',
          VULNERABLE_QUERY,
          [sqlInjectionPattern()]
        );

        expect(findings).toHaveLength(0);
      });

      // Guards the early return in scanFile: test files are skipped by PATH
      // before any parsing happens, so the exclusion must not depend on the
      // pattern's own contextRules.
      it('skips them even when the pattern declares no path exclusions', async () => {
        const subject = await newInterpreter();

        const findings = await subject.scanFile(
          'src/api/users.spec.ts',
          VULNERABLE_QUERY,
          [sqlInjectionPattern({ contextRules: undefined })]
        );

        expect(findings).toHaveLength(0);
      });
    });

    describe('when no pattern matches the regex pre-filter', () => {
      it('returns no findings', async () => {
        const subject = await newInterpreter();

        const findings = await subject.scanFile(
          'api/users.js',
          'const total = price + tax;',
          [sqlInjectionPattern()]
        );

        expect(findings).toHaveLength(0);
      });
    });

    describe('when the JavaScript cannot be parsed', () => {
      // The parse-failure path must degrade to regex, not throw and abort the
      // scan — one malformed file should not blind the whole run.
      it('degrades to the regex fallback instead of throwing', async () => {
        const subject = await newInterpreter();

        const findings = await subject.scanFile(
          'api/broken.js',
          'const query = "SELECT * FROM users WHERE id = " + userId; function ( { { {',
          [sqlInjectionPattern()]
        );

        expect(Array.isArray(findings)).toBe(true);
      });
    });

    describe('confidence thresholding', () => {
      // Scored with the adjustments stripped so the confidence is exactly the
      // declared base. Raising minConfidence on the full pattern proves nothing:
      // its adjustments saturate the score at 1.0, so every threshold <= 1 lets
      // it through.
      const unboostedPattern = (minConfidence: number) =>
        sqlInjectionPattern({
          minConfidence,
          confidenceRules: { base: 0.3, adjustments: {} }
        });

      it('drops a finding scoring below the pattern threshold', async () => {
        const subject = await newInterpreter();

        const findings = await subject.scanFile('api/users.js', VULNERABLE_QUERY, [
          unboostedPattern(0.8)
        ]);

        expect(findings).toHaveLength(0);
      });

      it('keeps the same finding when the threshold is at or below its score', async () => {
        const subject = await newInterpreter();

        const findings = await subject.scanFile('api/users.js', VULNERABLE_QUERY, [
          unboostedPattern(0.3)
        ]);

        expect(findings).toHaveLength(1);
      });

      it('caps confidence at 1.0 however many adjustments apply', async () => {
        const subject = await newInterpreter();

        const findings = await subject.scanFile('api/users.js', VULNERABLE_QUERY, [
          sqlInjectionPattern()
        ]);

        expect(findings[0].confidence).toBeLessThanOrEqual(1);
      });
    });

    describe('AST traversal', () => {
      /**
       * Smoke test that traversal actually reaches nodes: confidence is
       * accumulated DURING traversal from AST context, so a score above the
       * declared base (0.3) can only come from visitors having fired. A
       * traversal that silently visited nothing would return the bare base.
       *
       * Scope note, so nobody mistakes this for more than it is: this does NOT
       * detect a cross-major @babel/parser-vs-traverse mismatch. That was
       * measured, not assumed — reinstalling parser 8 against traverse/types 7
       * leaves all of these specs green, because traverse 7 reads Babel 8 ASTs
       * fine (verified for template literals, private fields, static blocks and
       * optional chaining). Aligning the Babel majors is still correct hygiene,
       * but it fixed a latent inconsistency, not an observed detection failure.
       */
      it('reaches AST nodes rather than silently visiting none', async () => {
        const subject = await newInterpreter();

        const findings = await subject.scanFile('api/users.js', VULNERABLE_QUERY, [
          sqlInjectionPattern()
        ]);

        expect(findings).toHaveLength(1);
        expect(findings[0].confidence).toBeGreaterThan(0.3);
      });
    });
  });
});
