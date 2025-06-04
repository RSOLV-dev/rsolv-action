import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { RSOLVCredentialManager } from '../../credentials/manager.js';

// Mock fetch globally
global.fetch = vi.fn();

describe('RSOLVCredentialManager', () => {
  let manager: RSOLVCredentialManager;
  
  beforeEach(() => {
    vi.clearAllMocks();
    // Clear any cached environment variables
    delete process.env.RSOLV_API_URL;
    manager = new RSOLVCredentialManager();
  });
  
  afterEach(() => {
    manager.cleanup();
  });

  describe('API URL configuration', () => {
    it('should use production API URL by default', async () => {
      const mockResponse = {
        ok: true,
        json: async () => ({
          credentials: {
            anthropic: {
              api_key: 'temp_ant_test123',
              expires_at: new Date(Date.now() + 3600000).toISOString()
            }
          },
          usage: {
            remaining_fixes: 100,
            reset_at: new Date(Date.now() + 86400000).toISOString()
          }
        })
      };
      
      (global.fetch as any).mockResolvedValueOnce(mockResponse);
      
      await manager.initialize('test_api_key');
      
      expect(global.fetch).toHaveBeenCalledWith(
        'https://api.rsolv.dev/api/v1/credentials/exchange',
        expect.any(Object)
      );
    });
    
    it('should allow overriding API URL via environment variable', async () => {
      const originalEnv = process.env.RSOLV_API_URL;
      process.env.RSOLV_API_URL = 'https://staging.api.rsolv.dev';
      
      // Create new manager to pick up env var
      const customManager = new RSOLVCredentialManager();
      
      const mockResponse = {
        ok: true,
        json: async () => ({
          credentials: {
            anthropic: {
              api_key: 'temp_ant_test123',
              expires_at: new Date(Date.now() + 3600000).toISOString()
            }
          },
          usage: {
            remaining_fixes: 100,
            reset_at: new Date(Date.now() + 86400000).toISOString()
          }
        })
      };
      
      (global.fetch as any).mockResolvedValueOnce(mockResponse);
      
      await customManager.initialize('test_api_key');
      
      expect(global.fetch).toHaveBeenCalledWith(
        'https://staging.api.rsolv.dev/api/v1/credentials/exchange',
        expect.any(Object)
      );
      
      // Restore env
      process.env.RSOLV_API_URL = originalEnv;
      customManager.cleanup();
    });
  });
  
  describe('credential exchange', () => {
    it('should exchange RSOLV API key for provider credentials', async () => {
      const mockCredentials = {
        anthropic: {
          api_key: 'temp_ant_test123',
          expires_at: new Date(Date.now() + 3600000).toISOString()
        },
        openai: {
          api_key: 'temp_oai_test456',
          expires_at: new Date(Date.now() + 3600000).toISOString()
        }
      };
      
      const mockResponse = {
        ok: true,
        json: async () => ({
          credentials: mockCredentials,
          usage: {
            remaining_fixes: 100,
            reset_at: new Date(Date.now() + 86400000).toISOString()
          }
        })
      };
      
      (global.fetch as any).mockResolvedValueOnce(mockResponse);
      
      await manager.initialize('test_api_key');
      
      // Verify we can get credentials
      const anthropicKey = manager.getCredential('anthropic');
      expect(anthropicKey).toBe('temp_ant_test123');
      
      const openaiKey = manager.getCredential('openai');
      expect(openaiKey).toBe('temp_oai_test456');
    });
    
    it('should include proper headers in exchange request', async () => {
      const mockResponse = {
        ok: true,
        json: async () => ({
          credentials: {},
          usage: { remaining_fixes: 100, reset_at: new Date().toISOString() }
        })
      };
      
      (global.fetch as any).mockResolvedValueOnce(mockResponse);
      
      await manager.initialize('test_api_key');
      
      expect(global.fetch).toHaveBeenCalledWith(
        expect.any(String),
        {
          method: 'POST',
          headers: {
            'Authorization': 'Bearer test_api_key',
            'Content-Type': 'application/json',
            'X-GitHub-Job': '',
            'X-GitHub-Run': ''
          },
          body: JSON.stringify({
            api_key: 'test_api_key',
            providers: ['anthropic', 'openai', 'openrouter'],
            ttl_minutes: 60
          })
        }
      );
    });
  });
});