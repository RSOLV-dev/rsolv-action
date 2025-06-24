/**
 * Tests for the AI client factory
 */
import { test, expect, mock, describe, beforeEach } from 'bun:test';
import { getAiClient } from '../client.js';

// Mock the logger to avoid noisy logs
const loggerPath = require.resolve('../../utils/logger');
mock.module(loggerPath, () => ({
  logger: {
    info: () => {},
    warn: () => {},
    error: () => {},
    debug: () => {}
  }
}));

// Mock the credential manager
const credentialManagerPath = require.resolve('../../credentials/manager');
mock.module(credentialManagerPath, () => ({
  RSOLVCredentialManager: class MockCredentialManager {
    private credentials = new Map<string, string>();
    
    async initialize(apiKey: string) {
      if (!apiKey) {
        throw new Error('RSOLV API key is required');
      }
      this.credentials.set('anthropic', 'vended-anthropic-key');
      this.credentials.set('openai', 'vended-openai-key');
      this.credentials.set('claude-code', 'vended-anthropic-key'); // Claude Code uses Anthropic
    }
    
    getCredential(provider: string): string {
      const credential = this.credentials.get(provider);
      if (!credential) {
        throw new Error(`No credential available for provider: ${provider}`);
      }
      return credential;
    }
    
    async reportUsage(provider: string, usage: any) {
      return Promise.resolve();
    }
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
        model: 'claude-3-sonnet'
      });
      
      expect(client).toBeDefined();
      expect(client.complete).toBeDefined();
      expect(typeof client.complete).toBe('function');
    });

    test('should return Anthropic client for claude-code provider', async () => {
      const client = await getAiClient({
        provider: 'claude-code',
        apiKey: 'test-key',
        model: 'claude-3-sonnet'
      });
      
      expect(client).toBeDefined();
      expect(client.complete).toBeDefined();
      expect(typeof client.complete).toBe('function');
    });

    test('should throw for unknown providers', async () => {
      await expect(async () => {
        await getAiClient({
          // @ts-expect-error - Testing with invalid provider
          provider: 'unknown-provider',
          apiKey: 'test-key'
        });
      }).toThrow('Unsupported AI provider: unknown-provider');
    });
  });

  describe('Vended Credentials', () => {
    test('should initialize credential manager when using vended credentials', async () => {
      const client = await getAiClient({
        provider: 'anthropic',
        apiKey: '',  // No direct API key
        useVendedCredentials: true
      });
      
      expect(client).toBeDefined();
      expect(client.complete).toBeDefined();
    });

    test('should handle missing RSOLV_API_KEY gracefully', async () => {
      process.env.RSOLV_API_KEY = '';
      
      // Should still create client but credential manager initialization might fail
      const client = await getAiClient({
        provider: 'anthropic',
        apiKey: '',
        useVendedCredentials: true
      });
      
      expect(client).toBeDefined();
      // Actual API calls would fail later due to missing credentials
    });

    test('should not require API key when using vended credentials', async () => {
      const client = await getAiClient({
        provider: 'openai',
        apiKey: '',  // Empty API key
        useVendedCredentials: true
      });
      
      expect(client).toBeDefined();
      expect(client.complete).toBeDefined();
    });

    test('should throw error when no API key and not using vended credentials', async () => {
      await expect(async () => {
        await getAiClient({
          provider: 'anthropic',
          apiKey: '',  // No API key
          useVendedCredentials: false
        });
      }).toThrow('AI provider API key is required');
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
        model: 'claude-3-opus',
        temperature: 0.7,
        maxTokens: 4000
      });
      
      expect(client).toBeDefined();
    });
  });
});