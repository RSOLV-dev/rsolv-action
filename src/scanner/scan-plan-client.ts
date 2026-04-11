import { logger } from '../utils/logger.js';
import type { ScanPlanRequest, ScanPlanResponse } from './types.js';

interface ScanPlanClientOptions {
  apiUrl: string;
  apiKey: string;
}

/**
 * Client for POST /api/v1/scan/plan (RFC-146 Phase 2).
 *
 * Returns null on transient failures (5xx, timeout, network) — caller
 * falls back to conservative default. Throws on hard failures (401, 403, 400)
 * — these indicate misconfiguration.
 */
export class ScanPlanClient {
  private apiUrl: string;
  private apiKey: string;

  constructor(options: ScanPlanClientOptions) {
    this.apiUrl = options.apiUrl.replace(/\/$/, '');
    this.apiKey = options.apiKey;
  }

  async getPlan(request: ScanPlanRequest): Promise<ScanPlanResponse | null> {
    const url = `${this.apiUrl}/api/v1/scan/plan`;

    try {
      const response = await fetch(url, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'x-api-key': this.apiKey,
        },
        body: JSON.stringify(request),
      });

      if (response.ok) {
        return (await response.json()) as ScanPlanResponse;
      }

      // Hard failures — misconfiguration, don't retry
      if (response.status === 401 || response.status === 403 || response.status === 400) {
        const body = await response.text();
        throw new Error(`Scan plan request failed: ${response.status} — ${body}`);
      }

      // Transient failures — fall back to conservative default
      logger.warn(`[ScanPlanClient] Transient failure: ${response.status}`);
      return null;
    } catch (error) {
      // Network errors — fall back to conservative default
      if (error instanceof Error && error.message.startsWith('Scan plan request failed')) {
        throw error; // Re-throw hard failures
      }
      logger.warn(`[ScanPlanClient] Network error: ${error}`);
      return null;
    }
  }
}
