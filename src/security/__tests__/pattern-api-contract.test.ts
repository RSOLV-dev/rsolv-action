/**
 * Contract between GET /api/v1/patterns?format=enhanced and the Action.
 *
 * The fixture is a real staging response. Refresh it with:
 *   curl -s -H "x-api-key: $RSOLV_API_KEY" \
 *     "https://api.rsolv-staging.com/api/v1/patterns?language=python&format=enhanced" \
 *     | jq . > src/security/__tests__/fixtures/patterns-python-enhanced.json
 */
import { describe, it, expect, vi } from 'vitest';
import { readFileSync } from 'fs';
import { PatternAPIClient, type PatternResponse } from '../pattern-api-client.js';

vi.mock('../../utils/logger.js', () => ({
  logger: { info: vi.fn(), warn: vi.fn(), error: vi.fn(), debug: vi.fn() }
}));

const response: PatternResponse = JSON.parse(
  readFileSync(new URL('./fixtures/patterns-python-enhanced.json', import.meta.url), 'utf8')
);
const client = new PatternAPIClient({ apiKey: 'test-key' });

function servedRegexCount(regex: string | string[] | undefined): number {
  return regex === undefined ? 0 : [regex].flat().length;
}

describe('the served enhanced Python patterns', () => {
  it('is a non-empty capture', () => {
    expect(response.patterns.length).toBeGreaterThan(0);
  });

  describe.each(response.patterns.map(p => [p.id, p] as const))('%s', (_id, served) => {
    const converted = client.convertToSecurityPattern(served);

    it('compiles every served regex with the Action\'s own compilation', () => {
      expect(servedRegexCount(served.regex)).toBeGreaterThan(0);
      expect(converted.patterns.regex).toHaveLength(servedRegexCount(served.regex));
    });

    it('matches at least one of its own vulnerable examples', () => {
      const examples = served.examples?.vulnerable ?? [];

      expect(examples.some(e => converted.patterns.regex.some(r => new RegExp(r.source, r.flags).test(e)))).toBe(true);
    });

    it('keeps the enhanced rules it was served', () => {
      expect(converted.astRules ?? null).toEqual(served.astRules ?? null);
      expect(converted.contextRules ?? null).toEqual(served.contextRules ?? null);
      expect(converted.confidenceRules ?? null).toEqual(served.confidenceRules ?? null);
    });
  });

  it('parses AST rules for every pattern that has them', () => {
    const served = response.patterns.filter(p => p.astRules && Object.keys(p.astRules).length > 0);
    const parsed = served.map(p => client.convertToSecurityPattern(p))
      .filter(p => p.astRules && Object.keys(p.astRules).length > 0);

    expect(served.length).toBeGreaterThan(0);
    expect(parsed).toHaveLength(served.length);
  });
});
