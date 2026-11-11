/**
 * Tests for the AI client factory
 */
import { test, expect, vi, describe, beforeEach } from 'vitest';
import { getAiClient } from '../client.js';
import { MODELS } from '../../config/models.js';

// Mock the logger to avoid noisy logs
vi.mock('../../utils/logger', () => ({
  logger: {
    debug: vi.fn(() => {}),
    info: () => {},
    warn: () => {},
    error: () => {}
  }
}));

describe('AI Client Factory', () => {
  beforeEach(() => {
    // Reset environment for each test
    process.env.RSOLV_API_KEY = 'test-rsolv-key';
  });

  describe('Provider Support', () => {
    test('should return Ollama client for ollama provider', async () => {
      const client = await getAiClient({
        provider: 'ollama',
        apiKey: 'test-key'
      });
      
      expect(client).toBeDefined();
      expect(client.complete).toBeDefined();
      expect(typeof client.complete).toBe('function');
    });

    test('should return OpenAI client for openai provider', async () => {
      const client = await getAiClient({
        provider: 'openai',
        apiKey: 'test-key',
        model: 'gpt-4'
      });
      
      expect(client).toBeDefined();
      expect(client.complete).toBeDefined();
      expect(typeof client.complete).toBe('function');
    });

    test('should return Anthropic client for anthropic provider', async () => {
      const client = await getAiClient({
        provider: 'anthropic',
        apiKey: 'test-key',
        model: 'claude-sonnet-4-5-20250929'
      });
      
      expect(client).toBeDefined();
      expect(client.complete).toBeDefined();
      expect(typeof client.complete).toBe('function');
    });

    test('should return Anthropic client for claude-code provider', async () => {
      const client = await getAiClient({
        provider: 'claude-code',
        apiKey: 'test-key',
        model: 'claude-sonnet-4-5-20250929'
      });
      
      expect(client).toBeDefined();
      expect(client.complete).toBeDefined();
      expect(typeof client.complete).toBe('function');
    });

    test('should throw for unknown providers', async () => {
      await expect(
        getAiClient({
          // @ts-expect-error - Testing with invalid provider
          provider: 'unknown-provider',
          apiKey: 'test-key'
        })
      ).rejects.toThrow('Unsupported AI provider: unknown-provider');
    });
  });

  describe('API keys', () => {
    test('should throw when no provider API key is given', async () => {
      await expect(
        getAiClient({
          provider: 'anthropic',
          apiKey: ''
        })
      ).rejects.toThrow('AI provider API key is required');
    });
  });

  describe('Provider Configuration', () => {
    test('should handle provider comparison case-insensitively', async () => {
      const providers = ['OpenAI', 'OPENAI', 'openai'];
      
      for (const provider of providers) {
        const client = await getAiClient({
          provider: provider as any,
          apiKey: 'test-key'
        });
        
        expect(client).toBeDefined();
        expect(client.complete).toBeDefined();
      }
    });

    test('should pass through model configuration', async () => {
      const client = await getAiClient({
        provider: 'anthropic',
        apiKey: 'test-key',
        model: MODELS.CLAUDE_OPUS,
        temperature: 0.7,
        maxTokens: 4000
      });
      
      expect(client).toBeDefined();
    });
  });
});