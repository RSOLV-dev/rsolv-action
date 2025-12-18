/**
 * RED TEST - Anthropic API Parameter Bug
 *
 * Issue: src/ai/client.ts sends BOTH temperature AND top_p to Anthropic API
 * Error: "temperature and top_p cannot both be specified for this model"
 *
 * This test verifies we only send temperature (preferred) and NOT top_p.
 */
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { getAiClient } from '../client.js';
import type { AiClient } from '../types.js';

// Mock the logger
vi.mock('../../utils/logger', () => ({
  logger: {
    debug: vi.fn(),
    info: vi.fn(),
    warn: vi.fn(),
    error: vi.fn()
  }
}));

// Mock credential manager
vi.mock('../../credentials/manager', () => ({
  RSOLVCredentialManager: class MockCredentialManager {
    private credentials = new Map<string, string>();

    async initialize(apiKey: string) {
      this.credentials.set('anthropic', 'test-anthropic-key');
      this.credentials.set('openai', 'test-openai-key');
    }

    getCredential(provider: string): string {
      return this.credentials.get(provider) || 'mock-key';
    }

    async reportUsage(provider: string, usage: any) {
      return Promise.resolve();
    }
  }
}));

describe('API Parameter Bug Fix - temperature and top_p conflict', () => {
  let fetchSpy: any;

  beforeEach(() => {
    // Spy on fetch to intercept API calls
    fetchSpy = vi.spyOn(global, 'fetch').mockResolvedValue({
      ok: true,
      status: 200,
      json: async () => ({
        content: [{ text: 'Mock response' }]
      }),
      headers: new Headers({
        'content-type': 'application/json'
      })
    } as Response);
  });

  afterEach(() => {
    fetchSpy.mockRestore();
    vi.clearAllMocks();
  });

  describe('Anthropic API calls', () => {
    it('should NOT send top_p parameter (only temperature)', async () => {
      const client: AiClient = await getAiClient({
        provider: 'anthropic',
        apiKey: 'test-key',
        model: 'claude-sonnet-4-5-20250929'
      });

      // Force real API call (not mock)
      process.env.FORCE_REAL_AI = 'true';

      try {
        await client.complete('test prompt', {
          temperature: 0.7,
          maxTokens: 1000
        });
      } catch (e) {
        // Expected to potentially fail, we're testing the request structure
      }

      // Verify fetch was called
      expect(fetchSpy).toHaveBeenCalled();

      // Get the request body that was sent
      const callArgs = fetchSpy.mock.calls[0];
      const requestBody = JSON.parse(callArgs[1].body);

      // RED TEST: This should FAIL initially because we're sending both
      expect(requestBody).toHaveProperty('temperature');
      expect(requestBody).not.toHaveProperty('top_p');

      delete process.env.FORCE_REAL_AI;
    });

    it('should send temperature when explicitly provided', async () => {
      const client: AiClient = await getAiClient({
        provider: 'anthropic',
        apiKey: 'test-key',
        model: 'claude-sonnet-4-5-20250929'
      });

      process.env.FORCE_REAL_AI = 'true';

      try {
        await client.complete('test prompt', {
          temperature: 0.5,
          maxTokens: 1000
        });
      } catch (e) {
        // Expected
      }

      const callArgs = fetchSpy.mock.calls[0];
      const requestBody = JSON.parse(callArgs[1].body);

      expect(requestBody.temperature).toBe(0.5);
      expect(requestBody).not.toHaveProperty('top_p');

      delete process.env.FORCE_REAL_AI;
    });

    it('should use default temperature (0.2) when not provided', async () => {
      const client: AiClient = await getAiClient({
        provider: 'anthropic',
        apiKey: 'test-key',
        model: 'claude-sonnet-4-5-20250929'
      });

      process.env.FORCE_REAL_AI = 'true';

      try {
        await client.complete('test prompt', {
          maxTokens: 1000
        });
      } catch (e) {
        // Expected
      }

      const callArgs = fetchSpy.mock.calls[0];
      const requestBody = JSON.parse(callArgs[1].body);

      expect(requestBody.temperature).toBe(0.2);
      expect(requestBody).not.toHaveProperty('top_p');

      delete process.env.FORCE_REAL_AI;
    });
  });

  describe('OpenAI API calls', () => {
    it('should NOT send top_p parameter (only temperature)', async () => {
      const client: AiClient = await getAiClient({
        provider: 'openai',
        apiKey: 'test-key',
        model: 'gpt-4'
      });

      process.env.FORCE_REAL_AI = 'true';

      try {
        await client.complete('test prompt', {
          temperature: 0.7,
          maxTokens: 1000
        });
      } catch (e) {
        // Expected
      }

      expect(fetchSpy).toHaveBeenCalled();

      const callArgs = fetchSpy.mock.calls[0];
      const requestBody = JSON.parse(callArgs[1].body);

      // OpenAI also prefers temperature over top_p for consistency
      expect(requestBody).toHaveProperty('temperature');
      expect(requestBody).not.toHaveProperty('top_p');

      delete process.env.FORCE_REAL_AI;
    });
  });

  describe('API Constraint Validation', () => {
    it('documents the Anthropic API constraint about temperature/top_p', () => {
      // This test documents the API constraint
      const constraint = {
        rule: 'temperature and top_p cannot both be specified',
        source: 'Anthropic API Documentation',
        solution: 'Use only temperature (preferred) or top_p, not both',
        httpStatus: 400,
        errorMessage: 'temperature and top_p cannot both be specified for this model'
      };

      expect(constraint.rule).toBe('temperature and top_p cannot both be specified');
      expect(constraint.httpStatus).toBe(400);
    });
  });
});
