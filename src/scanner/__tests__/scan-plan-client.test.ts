import { describe, it, expect, vi, beforeEach } from 'vitest';
import { ScanPlanClient } from '../scan-plan-client.js';
import type { ScanPlanFinding, ScanPlanResponse } from '../types.js';

const MOCK_FINDINGS: ScanPlanFinding[] = [
  { cwe_id: 'CWE-89', severity: 'critical', file_path: 'src/db.ts', line: 42, type: 'sql_injection', confidence: 'high' },
  { cwe_id: 'CWE-79', severity: 'high', file_path: 'src/view.ts', line: 18, type: 'xss', confidence: 'medium' },
];

const MOCK_RESPONSE: ScanPlanResponse = {
  selected: [MOCK_FINDINGS[0]],
  deferred: [{ ...MOCK_FINDINGS[1], reason: 'capacity_exceeded' }],
  budget: {
    tier: 'pro',
    validate_limit: 25,
    validate_used: 24,
    validate_remaining: 1,
    overage_cap_cents: 0,
    overage_remaining_cents: 0,
    max_validations: 1,
    effective_cap: 1,
    period_ends_at: '2026-05-01T00:00:00Z',
    currency: 'usd',
  },
};

describe('ScanPlanClient', () => {
  let client: ScanPlanClient;

  beforeEach(() => {
    client = new ScanPlanClient({
      apiUrl: 'https://api.rsolv.dev',
      apiKey: 'test-key',
    });
    vi.restoreAllMocks();
  });

  it('returns plan on successful 200', async () => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValue(
      new Response(JSON.stringify(MOCK_RESPONSE), { status: 200 })
    );

    const result = await client.getPlan({
      findings: MOCK_FINDINGS,
      max_issues: 3,
      namespace: 'owner/repo',
    });

    expect(result).toEqual(MOCK_RESPONSE);
    expect(fetchSpy).toHaveBeenCalledWith(
      'https://api.rsolv.dev/api/v1/scan/plan',
      expect.objectContaining({
        method: 'POST',
        headers: expect.objectContaining({
          'Content-Type': 'application/json',
          'x-api-key': 'test-key',
        }),
      })
    );
  });

  it('returns null on transient 5xx failure', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(
      new Response('Internal Server Error', { status: 500 })
    );

    const result = await client.getPlan({
      findings: MOCK_FINDINGS,
      max_issues: 3,
      namespace: 'owner/repo',
    });

    expect(result).toBeNull();
  });

  it('throws on hard 401 failure', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(
      new Response(JSON.stringify({ error: 'Unauthorized' }), { status: 401 })
    );

    await expect(
      client.getPlan({ findings: MOCK_FINDINGS, max_issues: 3, namespace: 'owner/repo' })
    ).rejects.toThrow('Scan plan request failed: 401');
  });

  it('throws on hard 403 failure', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(
      new Response(JSON.stringify({ error: 'Forbidden' }), { status: 403 })
    );

    await expect(
      client.getPlan({ findings: MOCK_FINDINGS, max_issues: 3, namespace: 'owner/repo' })
    ).rejects.toThrow('Scan plan request failed: 403');
  });

  it('returns null on network error', async () => {
    vi.spyOn(globalThis, 'fetch').mockRejectedValue(new Error('Network unreachable'));

    const result = await client.getPlan({
      findings: MOCK_FINDINGS,
      max_issues: 3,
      namespace: 'owner/repo',
    });

    expect(result).toBeNull();
  });

  it('passes max_validations when provided', async () => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValue(
      new Response(JSON.stringify(MOCK_RESPONSE), { status: 200 })
    );

    await client.getPlan({
      findings: MOCK_FINDINGS,
      max_issues: 3,
      max_validations: 2,
      namespace: 'owner/repo',
    });

    const body = JSON.parse(fetchSpy.mock.calls[0][1]?.body as string);
    expect(body.max_validations).toBe(2);
  });
});
