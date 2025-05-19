import { getAiClient } from '../client';
import { RSOLVCredentialManager } from '../../credentials/manager';
import { AiProviderConfig } from '../../types';

// Mock the credential manager
jest.mock('../../credentials/manager');

// Mock fetch for AI API calls
global.fetch = jest.fn();

beforeEach(() => {
  jest.clearAllMocks();
  (global.fetch as jest.Mock).mockReset();
});

describe('AI Client with Credential Vending', () => {
  it('should use vended credentials for Anthropic API calls', async () => {
    // Mock credential manager
    const mockManager = {
      getCredential: jest.fn().mockReturnValue('temp_ant_xyz789'),
      reportUsage: jest.fn().mockResolvedValue(undefined)
    };
    
    (RSOLVCredentialManager as jest.MockedClass<typeof RSOLVCredentialManager>).mockImplementation(
      () => mockManager as any
    );

    // Mock AI API response
    const mockAIResponse = {
      content: [{
        text: 'This is a test response from Claude'
      }]
    };

    (global.fetch as jest.Mock).mockResolvedValueOnce({
      ok: true,
      json: async () => mockAIResponse
    });

    // Create AI client with vended credentials
    const config: AiProviderConfig = {
      provider: 'anthropic',
      model: 'claude-3-sonnet-20240229',
      temperature: 0.2,
      maxTokens: 2000,
      useVendedCredentials: true  // New flag
    };

    const client = getAiClient(config);
    const response = await client.complete('Test prompt');

    // Verify credential was retrieved
    expect(mockManager.getCredential).toHaveBeenCalledWith('anthropic');

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
    expect(mockManager.reportUsage).toHaveBeenCalledWith('anthropic', {
      tokensUsed: expect.any(Number),
      requestCount: 1
    });

    expect(response).toBe('This is a test response from Claude');
  });

  it('should use vended credentials for OpenAI API calls', async () => {
    const mockManager = {
      getCredential: jest.fn().mockReturnValue('temp_oai_def456'),
      reportUsage: jest.fn().mockResolvedValue(undefined)
    };
    
    (RSOLVCredentialManager as jest.MockedClass<typeof RSOLVCredentialManager>).mockImplementation(
      () => mockManager as any
    );

    const mockAIResponse = {
      choices: [{
        message: {
          content: 'This is a test response from GPT-4'
        }
      }]
    };

    (global.fetch as jest.Mock).mockResolvedValueOnce({
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

    const client = getAiClient(config);
    const response = await client.complete('Test prompt');

    expect(mockManager.getCredential).toHaveBeenCalledWith('openai');
    
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

  it('should handle credential refresh during long-running tasks', async () => {
    const mockManager = {
      getCredential: jest.fn()
        .mockReturnValueOnce('temp_ant_xyz789')  // First call
        .mockReturnValueOnce('temp_ant_new123'), // After refresh
      reportUsage: jest.fn().mockResolvedValue(undefined)
    };
    
    (RSOLVCredentialManager as jest.MockedClass<typeof RSOLVCredentialManager>).mockImplementation(
      () => mockManager as any
    );

    const mockAIResponse = {
      content: [{
        text: 'Response with refreshed credential'
      }]
    };

    (global.fetch as jest.Mock).mockResolvedValueOnce({
      ok: true,
      json: async () => mockAIResponse
    });

    const config: AiProviderConfig = {
      provider: 'anthropic',
      model: 'claude-3-sonnet-20240229',
      useVendedCredentials: true
    };

    const client = getAiClient(config);
    
    // Simulate multiple API calls over time
    await client.complete('First prompt');
    await client.complete('Second prompt');

    // Verify both credentials were used
    expect(mockManager.getCredential).toHaveBeenCalledTimes(2);
    
    // The second API call should use the refreshed credential
    const secondCall = (global.fetch as jest.Mock).mock.calls[1];
    expect(secondCall[1].headers['X-API-Key']).toBe('temp_ant_new123');
  });

  it('should fallback to direct API key if vending is disabled', async () => {
    const mockAIResponse = {
      content: [{
        text: 'Response with direct API key'
      }]
    };

    (global.fetch as jest.Mock).mockResolvedValueOnce({
      ok: true,
      json: async () => mockAIResponse
    });

    const config: AiProviderConfig = {
      provider: 'anthropic',
      apiKey: 'direct_ant_key_123',
      model: 'claude-3-sonnet-20240229',
      useVendedCredentials: false  // Disabled
    };

    const client = getAiClient(config);
    await client.complete('Test prompt');

    // Should not use credential manager
    expect(RSOLVCredentialManager).not.toHaveBeenCalled();

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

  it('should handle vended credential errors gracefully', async () => {
    const mockManager = {
      getCredential: jest.fn().mockImplementation(() => {
        throw new Error('No valid credential for anthropic');
      })
    };
    
    (RSOLVCredentialManager as jest.MockedClass<typeof RSOLVCredentialManager>).mockImplementation(
      () => mockManager as any
    );

    const config: AiProviderConfig = {
      provider: 'anthropic',
      model: 'claude-3-sonnet-20240229',
      useVendedCredentials: true
    };

    const client = getAiClient(config);
    
    await expect(client.complete('Test prompt')).rejects.toThrow(
      'Failed to retrieve vended credential: No valid credential for anthropic'
    );
  });
});