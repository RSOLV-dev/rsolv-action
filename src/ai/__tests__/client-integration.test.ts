import { describe, expect, test, beforeEach, afterEach, mock } from 'bun:test';
import { getAiClient } from '../client';
import { AiProviderConfig } from '../../types';

// Mock fetch globally
global.fetch = mock(() => Promise.resolve());

// Store original ENV
const originalEnv = process.env;

beforeEach(() => {
  // Reset environment, use production to avoid fallbacks
  process.env = { ...originalEnv, NODE_ENV: 'production' };
  // Clear and reset mocks
  mock.restore();
  (global.fetch as any).mockReset();
});

afterEach(() => {
  // Restore environment
  process.env = originalEnv;
});

describe('AI Client Direct API Integration', () => {
  test('should use direct API key for Anthropic when vending is disabled', async () => {
    // Mock AI response
    const mockResponse = {
      content: [{
        text: 'Response with direct API key'
      }]
    };

    (global.fetch as any).mockResolvedValueOnce({
      ok: true,
      json: async () => mockResponse
    });

    const config: AiProviderConfig = {
      provider: 'anthropic',
      apiKey: 'direct_ant_key_123',
      model: 'claude-3-sonnet-20240229',
      useVendedCredentials: false
    };

    const client = await getAiClient(config);
    const response = await client.complete('Test prompt');

    // Verify API was called with correct parameters
    expect((global.fetch as any).mock.calls.length).toBe(1);
    
    // Verify correct headers
    const fetchCall = (global.fetch as any).mock.calls[0];
    expect(fetchCall[0]).toBe('https://api.anthropic.com/v1/messages');
    expect(fetchCall[1].headers['X-API-Key']).toBe('direct_ant_key_123');

    expect(response).toBe('Response with direct API key');
  });

  test('should use direct API key for OpenAI when vending is disabled', async () => {
    // Mock OpenAI response
    const mockResponse = {
      choices: [{
        message: {
          content: 'GPT-4 response'
        }
      }]
    };

    (global.fetch as any).mockResolvedValueOnce({
      ok: true,
      json: async () => mockResponse
    });

    const config: AiProviderConfig = {
      provider: 'openai',
      apiKey: 'direct_oai_key',
      model: 'gpt-4',
      useVendedCredentials: false
    };

    const client = await getAiClient(config);
    const response = await client.complete('Test prompt');

    // Verify API was called with correct parameters
    expect((global.fetch as any).mock.calls.length).toBe(1);
    
    // Verify correct headers
    const fetchCall = (global.fetch as any).mock.calls[0];
    expect(fetchCall[0]).toBe('https://api.openai.com/v1/chat/completions');
    expect(fetchCall[1].headers['Authorization']).toBe('Bearer direct_oai_key');

    expect(response).toBe('GPT-4 response');
  });

  test('should handle API errors gracefully', async () => {
    // Mock error response
    (global.fetch as any).mockResolvedValueOnce({
      ok: false,
      status: 401,
      statusText: 'Unauthorized',
      json: async () => ({ error: { message: 'Invalid API key' } })
    });

    const config: AiProviderConfig = {
      provider: 'anthropic',
      apiKey: 'invalid_key',
      model: 'claude-3-sonnet-20240229',
      useVendedCredentials: false
    };

    const client = await getAiClient(config);
    
    try {
      await client.complete('Test prompt');
      throw new Error('Expected error was not thrown');
    } catch (error) {
      expect(error.message).toContain('Anthropic API error (401): Invalid API key');
    }
  });

  test('should throw error for missing API key', async () => {
    const config: AiProviderConfig = {
      provider: 'anthropic',
      model: 'claude-3-sonnet-20240229',
      useVendedCredentials: false
    };

    try {
      await getAiClient(config);
      throw new Error('Expected error was not thrown');
    } catch (error) {
      expect(error.message).toBe('Anthropic API key is required');
    }
  });
});