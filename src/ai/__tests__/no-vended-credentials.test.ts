/**
 * The action must never hold raw AI provider keys vended by the platform.
 *
 * Since RFC-096 the platform runs the AI loop; the action is a tool executor.
 * The legacy client for POST /api/v1/credentials/exchange (and /refresh)
 * handed raw provider keys to any RSOLV API key holder, so it is removed.
 */
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';
import { loadConfig } from '../../config/index.js';
import { getAiClient } from '../client.js';

vi.mock('../../utils/logger', () => ({
  logger: { debug: vi.fn(), info: vi.fn(), warn: vi.fn(), error: vi.fn() }
}));

const SRC_ROOT = path.resolve(__dirname, '../..');

function productionSourceFiles(dir: string): string[] {
  return fs.readdirSync(dir, { withFileTypes: true }).flatMap((entry) => {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      return ['__tests__', 'test', '__mocks__'].includes(entry.name) ? [] : productionSourceFiles(full);
    }
    return /\.ts$/.test(entry.name) && !/\.test\.ts$/.test(entry.name) ? [full] : [];
  });
}

describe('AI provider credentials', () => {
  let originalEnv: NodeJS.ProcessEnv;
  let fetchSpy: ReturnType<typeof vi.spyOn>;

  beforeEach(() => {
    originalEnv = { ...process.env };
    for (const key of Object.keys(process.env)) {
      if (key.startsWith('RSOLV_AI_')) delete process.env[key];
    }
    process.env.RSOLV_API_KEY = 'rsolv_test_key_only';
    process.env.RSOLV_CONFIG_PATH = '/nonexistent/rsolv.yml';
    fetchSpy = vi.spyOn(globalThis, 'fetch').mockRejectedValue(new Error('network disabled in test'));
  });

  afterEach(() => {
    process.env = originalEnv;
    fetchSpy.mockRestore();
  });

  describe('when the action is configured with only an RSOLV API key', () => {
    it('refuses to build an AI client instead of fetching provider keys from the platform', async () => {
      const config = await loadConfig();

      await expect(getAiClient(config.aiProvider)).rejects.toThrow('AI provider API key is required');

      const requestedUrls = fetchSpy.mock.calls.map(([input]) => String(input));
      expect(requestedUrls.filter((url) => /credentials\/(exchange|refresh)/.test(url))).toEqual([]);
    });

    it('exposes no vended-credentials switch in the loaded configuration', async () => {
      const config = await loadConfig();

      expect(config.aiProvider).not.toHaveProperty('useVendedCredentials');
    });
  });

  describe('the shipped source', () => {
    it('contains no client for the platform credential-vending endpoints', () => {
      expect(fs.existsSync(path.join(SRC_ROOT, 'credentials/manager.ts'))).toBe(false);
      expect(fs.existsSync(path.join(SRC_ROOT, 'credentials/singleton.ts'))).toBe(false);

      const offenders = productionSourceFiles(SRC_ROOT).filter((file) =>
        /credentials\/(exchange|refresh)/.test(fs.readFileSync(file, 'utf8'))
      );
      expect(offenders).toEqual([]);
    });
  });
});
