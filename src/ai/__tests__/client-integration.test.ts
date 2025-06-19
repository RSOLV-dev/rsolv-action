import { describe, expect, test, beforeEach, afterEach, mock } from 'bun:test';
import { getAiClient } from '../client';
import { AiProviderConfig } from '../../types';
import { setupFetchMock, mockAIResponse } from '../../../test-helpers/simple-mocks';

// Store original values
const originalFetch = global.fetch;
const originalEnv = { ...process.env };

describe('AI Client Direct API Integration', () => {
  let fetchMock: ReturnType<typeof setupFetchMock>;

  beforeEach(() => {
    // Reset environment, use production to avoid fallbacks
    process.env = { ...originalEnv, NODE_ENV: 'production' };
    // Clear mocks
    mock.restore();
    // Setup fetch mock
    fetchMock = setupFetchMock();
  });

  afterEach(() => {
    // Restore environment
    process.env = originalEnv;
    // Restore fetch
    global.fetch = originalFetch;
    // Clear mocks
    mock.restore();
  });
  test('should use direct API key for Anthropic when vending is disabled', async () => {
    // Mock AI response
    const mockResponse = mockAIResponse('Response with direct API key');

    fetchMock.mockResponseOnce({
      ok: true,
      json: mockResponse
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
    expect(fetchMock.mock.mock.calls.length).toBe(1);
    
    // Verify correct headers
    const fetchCall = fetchMock.mock.mock.calls[0];
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

    fetchMock.mockResponseOnce({
      ok: true,
      json: mockResponse
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
    expect(fetchMock.mock.mock.calls.length).toBe(1);
    
    // Verify correct headers
    const fetchCall = fetchMock.mock.mock.calls[0];
    expect(fetchCall[0]).toBe('https://api.openai.com/v1/chat/completions');
    expect(fetchCall[1].headers['Authorization']).toBe('Bearer direct_oai_key');

    expect(response).toBe('GPT-4 response');
  });

  test('should handle API errors gracefully', async () => {
    // Mock error response
    fetchMock.mockResponseOnce({
      ok: false,
      status: 401,
      statusText: 'Unauthorized',
      json: { error: { message: 'Invalid API key' } }
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
      expect(error.message).toContain('Invalid API key');
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
      expect(error.message).toBe('AI provider API key is required');
    }
  });
});