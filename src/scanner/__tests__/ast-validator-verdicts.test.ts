import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { ASTValidator, type ValidationClient, type ValidationRequest, type ValidationResponse } from '../ast-validator.js';
import { VulnerabilityType, type Vulnerability } from '../../security/types.js';
import { logger } from '../../utils/logger.js';

vi.mock('../../utils/logger.js', () => ({
  logger: { info: vi.fn(), warn: vi.fn(), error: vi.fn(), debug: vi.fn() }
}));

type Verdict = Omit<ValidationResponse['validated'][number], 'id'>;

/** A platform double that echoes each request id with the verdict for that finding's file. */
function platformReturning(
  verdictFor: (file: string) => Verdict,
  extra: Partial<ValidationResponse> = {}
): ValidationClient & { requests: ValidationRequest[] } {
  const requests: ValidationRequest[] = [];
  return {
    requests,
    async validateVulnerabilities(request) {
      requests.push(request);
      return {
        validated: request.vulnerabilities.map(v => ({ id: v.id, ...verdictFor(v.file) })),
        stats: { total: request.vulnerabilities.length, validated: 0, rejected: 0 },
        ...extra
      };
    }
  };
}

function finding(filePath: string, overrides: Partial<Vulnerability> = {}): Vulnerability {
  return {
    type: VulnerabilityType.SQL_INJECTION,
    severity: 'high',
    line: 30,
    message: 'SQL injection',
    description: 'SQL built from user input',
    confidence: 80,
    filePath,
    snippet: 'cursor.execute("SELECT * FROM users WHERE id = %s" % user_id)',
    ...overrides
  };
}

const files = new Map([
  ['app/users.py', 'source'],
  ['app/admin.py', 'source']
]);

describe('ASTValidator#validateVulnerabilities', () => {
  beforeEach(() => vi.clearAllMocks());

  describe('when two files have a same-type finding on the same line', () => {
    it('applies each verdict only to its own file', async () => {
      const platform = platformReturning(file =>
        file === 'app/admin.py'
          ? { isValid: false, confidence: 0.9, reason: 'Safe pattern detected' }
          : { isValid: true, confidence: 0.9 });
      const real = finding('app/users.py');
      const safe = finding('app/admin.py');

      const kept = await new ASTValidator('key', platform).validateVulnerabilities([safe, real], files);

      expect(kept).toEqual([real]);
    });

    it('sends each finding a distinct request id', async () => {
      const platform = platformReturning(() => ({ isValid: true, confidence: 1 }));

      await new ASTValidator('key', platform)
        .validateVulnerabilities([finding('app/users.py'), finding('app/admin.py')], files);

      const ids = platform.requests[0].vulnerabilities.map(v => v.id);
      expect(new Set(ids).size).toBe(2);
    });
  });

  describe('under the legacy contract (no contractVersion, no exclusion)', () => {
    it('drops a finding the platform marks invalid', async () => {
      const platform = platformReturning(() => ({ isValid: false, confidence: 0.9, reason: 'In comment' }));

      const kept = await new ASTValidator('key', platform).validateVulnerabilities([finding('app/users.py')], files);

      expect(kept).toEqual([]);
    });
  });

  describe('under contract 2', () => {
    const contract2 = { contractVersion: 2 };

    it('keeps a hinted finding and carries the hint on it', async () => {
      const platform = platformReturning(
        () => ({ isValid: true, confidence: 0.9, staticHint: 'Safe pattern detected: using parameterized query' }),
        contract2
      );

      const [kept] = await new ASTValidator('key', platform).validateVulnerabilities([finding('app/users.py')], files);

      expect(kept.staticHint).toBe('Safe pattern detected: using parameterized query');
    });

    it('drops a finding excluded as non_executable', async () => {
      const platform = platformReturning(
        () => ({ isValid: false, confidence: 1, exclusion: 'non_executable', reason: 'Parser-confirmed comment' }),
        contract2
      );

      const kept = await new ASTValidator('key', platform).validateVulnerabilities([finding('app/users.py')], files);

      expect(kept).toEqual([]);
    });

    describe('when isValid is false without a recognised exclusion', () => {
      it.each([
        ['no exclusion', undefined],
        ['an unknown exclusion', 'customer_scope']
      ])('keeps the finding (%s) and logs it', async (_label, exclusion) => {
        const platform = platformReturning(() => ({ isValid: false, confidence: 0.9, reason: 'odd', exclusion }), contract2);
        const real = finding('app/users.py');

        const kept = await new ASTValidator('key', platform).validateVulnerabilities([real], files);

        expect(kept).toEqual([real]);
        expect(logger.warn).toHaveBeenCalledWith(expect.stringContaining('app/users.py:30'));
      });
    });
  });

  describe('the contractVersion it sends', () => {
    const original = process.env.RSOLV_VALIDATION_CONTRACT;
    afterEach(() => {
      if (original === undefined) delete process.env.RSOLV_VALIDATION_CONTRACT;
      else process.env.RSOLV_VALIDATION_CONTRACT = original;
    });

    it('is omitted by default, leaving the choice to the platform', async () => {
      delete process.env.RSOLV_VALIDATION_CONTRACT;
      const platform = platformReturning(() => ({ isValid: true, confidence: 1 }));

      await new ASTValidator('key', platform).validateVulnerabilities([finding('app/users.py')], files);

      expect(platform.requests[0]).not.toHaveProperty('contractVersion');
    });

    it('is 2 when RSOLV_VALIDATION_CONTRACT=2', async () => {
      process.env.RSOLV_VALIDATION_CONTRACT = '2';
      const platform = platformReturning(() => ({ isValid: true, confidence: 1 }));

      await new ASTValidator('key', platform).validateVulnerabilities([finding('app/users.py')], files);

      expect(platform.requests[0].contractVersion).toBe(2);
    });
  });
});
