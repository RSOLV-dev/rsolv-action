import { describe, expect, test, beforeEach, mock } from 'bun:test';
import { getAiClient } from '../client';
import { RSOLVCredentialManager } from '../../credentials/manager';
import { AiProviderConfig } from '../../types';
import { vi } from 'vitest';

// Mock fetch for AI API calls
global.fetch = mock(() => Promise.resolve());

beforeEach(() => {
  mock.restore();
  (global.fetch as any).mockReset();
});

describe('AI Client with Credential Vending', () => {
  test('should use vended credentials for Anthropic API calls', async () => {
    // Mock the credential manager's methods
    const mockGetCredential = mock(() => 'temp_ant_xyz789');
    const mockReportUsage = mock(() => Promise.resolve());
    const mockInitialize = mock(() => Promise.resolve());
    
    // Override the RSOLVCredentialManager prototype
    RSOLVCredentialManager.prototype.getCredential = mockGetCredential;
    RSOLVCredentialManager.prototype.reportUsage = mockReportUsage;
    RSOLVCredentialManager.prototype.initialize = mockInitialize;

    // Mock AI API response
    const mockAIResponse = {
      content: [{
        text: 'This is a test response from Claude'
      }],
      usage: {
        total_tokens: 1500
      }
    };

    (global.fetch as any).mockResolvedValueOnce({
      ok: true,
      json: async () => mockAIResponse
    });

    // Set RSOLV API key
    process.env.RSOLV_API_KEY = 'rsolv_test_key';

    // Create AI client with vended credentials
    const config: AiProviderConfig = {
      provider: 'anthropic',
      model: 'claude-3-sonnet-20240229',
      temperature: 0.2,
      maxTokens: 2000,
      useVendedCredentials: true
    };

    const client = await getAiClient(config);
    const response = await client.complete('Test prompt');

    // Verify credential was retrieved
    expect(mockGetCredential).toHaveBeenCalledWith('anthropic');

    // Verify API was called with vended credential
    expect(global.fetch).toHaveBeenCalledWith(
      'https://api.anthropic.com/v1/messages',
      expect.objectContaining({
        headers: expect.objectContaining({
          'X-API-Key': 'temp_ant_xyz789'
        })
      })
    );

    // Verify usage was reported
    expect(mockReportUsage).toHaveBeenCalledWith('anthropic', {
      tokensUsed: 1500,
      requestCount: 1
    });

    expect(response).toBe('This is a test response from Claude');
  });

  test('should use vended credentials for OpenAI API calls', async () => {
    const mockGetCredential = mock(() => 'temp_oai_def456');
    const mockReportUsage = mock(() => Promise.resolve());
    const mockInitialize = mock(() => Promise.resolve());
    
    RSOLVCredentialManager.prototype.getCredential = mockGetCredential;
    RSOLVCredentialManager.prototype.reportUsage = mockReportUsage;
    RSOLVCredentialManager.prototype.initialize = mockInitialize;

    const mockAIResponse = {
      choices: [{
        message: {
          content: 'This is a test response from GPT-4'
        }
      }],
      usage: {
        total_tokens: 2000
      }
    };

    (global.fetch as any).mockResolvedValueOnce({
      ok: true,
      json: async () => mockAIResponse
    });

    const config: AiProviderConfig = {
      provider: 'openai',
      model: 'gpt-4',
      temperature: 0.2,
      maxTokens: 2000,
      useVendedCredentials: true
    };

    const client = await getAiClient(config);
    const response = await client.complete('Test prompt');

    expect(mockGetCredential).toHaveBeenCalledWith('openai');
    
    expect(global.fetch).toHaveBeenCalledWith(
      'https://api.openai.com/v1/chat/completions',
      expect.objectContaining({
        headers: expect.objectContaining({
          'Authorization': 'Bearer temp_oai_def456'
        })
      })
    );

    expect(response).toBe('This is a test response from GPT-4');
  });

  test('should handle credential refresh during long-running tasks', async () => {
    let callCount = 0;
    const mockGetCredential = mock(() => {
      callCount++;
      return callCount === 1 ? 'temp_ant_xyz789' : 'temp_ant_new123';
    });
    const mockReportUsage = mock(() => Promise.resolve());
    const mockInitialize = mock(() => Promise.resolve());
    
    RSOLVCredentialManager.prototype.getCredential = mockGetCredential;
    RSOLVCredentialManager.prototype.reportUsage = mockReportUsage;
    RSOLVCredentialManager.prototype.initialize = mockInitialize;

    const mockAIResponse = {
      content: [{
        text: 'Response with refreshed credential'
      }],
      usage: {
        total_tokens: 1000
      }
    };

    (global.fetch as any).mockResolvedValue({
      ok: true,
      json: async () => mockAIResponse
    });

    const config: AiProviderConfig = {
      provider: 'anthropic',
      model: 'claude-3-sonnet-20240229',
      useVendedCredentials: true
    };

    const client = await getAiClient(config);
    
    // Simulate multiple API calls over time
    await client.complete('First prompt');
    await client.complete('Second prompt');

    // Verify both credentials were used
    expect(mockGetCredential).toHaveBeenCalledTimes(2);
    
    // The second API call should use the refreshed credential
    const calls = (global.fetch as any).mock.calls;
    expect(calls[1][1].headers['X-API-Key']).toBe('temp_ant_new123');
  });

  test('should fallback to direct API key if vending is disabled', async () => {
    const mockAIResponse = {
      content: [{
        text: 'Response with direct API key'
      }]
    };

    (global.fetch as any).mockResolvedValueOnce({
      ok: true,
      json: async () => mockAIResponse
    });

    const config: AiProviderConfig = {
      provider: 'anthropic',
      apiKey: 'direct_ant_key_123',
      model: 'claude-3-sonnet-20240229',
      useVendedCredentials: false
    };

    const client = await getAiClient(config);
    await client.complete('Test prompt');

    // Should use direct API key
    expect(global.fetch).toHaveBeenCalledWith(
      'https://api.anthropic.com/v1/messages',
      expect.objectContaining({
        headers: expect.objectContaining({
          'X-API-Key': 'direct_ant_key_123'
        })
      })
    );
  });

  test('should handle vended credential errors gracefully', async () => {
    const mockGetCredential = mock(() => {
      throw new Error('No valid credential for anthropic');
    });
    const mockInitialize = mock(() => Promise.resolve());
    
    RSOLVCredentialManager.prototype.getCredential = mockGetCredential;
    RSOLVCredentialManager.prototype.initialize = mockInitialize;

    const config: AiProviderConfig = {
      provider: 'anthropic',
      model: 'claude-3-sonnet-20240229',
      useVendedCredentials: true
    };

    const client = await getAiClient(config);
    
    await expect(client.complete('Test prompt')).rejects.toThrow(
      'Failed to retrieve API key'
    );
  });
});