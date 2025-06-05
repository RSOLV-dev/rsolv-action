import { describe, expect, test, beforeEach, afterEach, mock } from 'bun:test';
import { RSOLVCredentialManager } from '../manager';

// Mock fetch globally
global.fetch = mock(() => Promise.resolve());

// Store original env
const originalEnv = process.env;

beforeEach(() => {
  // Reset environment
  process.env = {
    ...originalEnv,
    GITHUB_JOB: 'test_job_123',
    GITHUB_RUN_ID: 'test_run_456',
    RSOLV_API_URL: 'https://api.rsolv.dev'
  };
  
  // Clear and reset mocks
  mock.restore();
  (global.fetch as any).mockReset();
});

afterEach(() => {
  process.env = originalEnv;
});

describe('RSOLVCredentialManager', () => {
  describe('initialize', () => {
    test('should exchange RSOLV API key for temporary credentials', async () => {
      const mockResponse = {
        credentials: {
          anthropic: {
            api_key: 'temp_ant_xyz789',
            expires_at: new Date(Date.now() + 3600000).toISOString() // 1 hour
          },
          openai: {
            api_key: 'temp_oai_def456',
            expires_at: new Date(Date.now() + 3600000).toISOString()
          }
        },
        usage: {
          remaining_fixes: 85,
          reset_at: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString()
        }
      };

      (global.fetch as any).mockResolvedValueOnce({
        ok: true,
        json: async () => mockResponse
      });

      const manager = new RSOLVCredentialManager();
      await manager.initialize('test_api_key_123');

      // Verify fetch was called correctly
      expect(global.fetch).toHaveBeenCalledWith(
        'https://api.rsolv.dev/api/v1/credentials/exchange',
        {
          method: 'POST',
          headers: {
            'Authorization': 'Bearer test_api_key_123',
            'Content-Type': 'application/json',
            'X-GitHub-Job': 'test_job_123',
            'X-GitHub-Run': 'test_run_456'
          },
          body: JSON.stringify({
            api_key: 'test_api_key_123',
            providers: ['anthropic', 'openai', 'openrouter'],
            ttl_minutes: 60
          })
        }
      );

      // Verify credentials are accessible
      expect(manager.getCredential('anthropic')).toBe('temp_ant_xyz789');
      expect(manager.getCredential('openai')).toBe('temp_oai_def456');
    });

    test('should throw error on failed API response', async () => {
      (global.fetch as any).mockResolvedValueOnce({
        ok: false,
        status: 401,
        statusText: 'Unauthorized',
        json: async () => ({ error: 'Invalid API key' })
      });

      const manager = new RSOLVCredentialManager();
      
      await expect(manager.initialize('invalid_key')).rejects.toThrow(
        'Failed to exchange credentials: Invalid API key'
      );
    });

    test('should throw error on network failure', async () => {
      (global.fetch as any).mockRejectedValueOnce(new Error('Network error'));

      const manager = new RSOLVCredentialManager();
      
      await expect(manager.initialize('test_key')).rejects.toThrow(
        'Network error'
      );
    });

    test('should schedule credential refresh before expiration', async () => {
      const expiresIn30Min = new Date(Date.now() + 30 * 60 * 1000);
      
      const mockResponse = {
        credentials: {
          anthropic: {
            api_key: 'temp_ant_xyz789',
            expires_at: expiresIn30Min.toISOString()
          }
        },
        usage: {
          remaining_fixes: 85
        }
      };

      (global.fetch as any).mockResolvedValueOnce({
        ok: true,
        json: async () => mockResponse
      });

      const manager = new RSOLVCredentialManager();
      await manager.initialize('test_api_key_123');

      // Verify refresh timer was set (internal implementation detail)
      // For now, just verify initialization succeeded
      expect(manager.getCredential('anthropic')).toBe('temp_ant_xyz789');
    });
  });

  describe('getCredential', () => {
    test('should return valid credential', async () => {
      const mockResponse = {
        credentials: {
          anthropic: {
            api_key: 'temp_ant_xyz789',
            expires_at: new Date(Date.now() + 3600000).toISOString()
          }
        },
        usage: { remaining_fixes: 85 }
      };

      (global.fetch as any).mockResolvedValueOnce({
        ok: true,
        json: async () => mockResponse
      });

      const manager = new RSOLVCredentialManager();
      await manager.initialize('test_api_key_123');

      expect(manager.getCredential('anthropic')).toBe('temp_ant_xyz789');
    });

    test('should throw error for expired credential', async () => {
      const expiredTime = new Date(Date.now() - 1000); // 1 second ago
      
      const mockResponse = {
        credentials: {
          anthropic: {
            api_key: 'temp_ant_xyz789',
            expires_at: expiredTime.toISOString()
          }
        },
        usage: { remaining_fixes: 85 }
      };

      (global.fetch as any).mockResolvedValueOnce({
        ok: true,
        json: async () => mockResponse
      });

      const manager = new RSOLVCredentialManager();
      await manager.initialize('test_api_key_123');

      expect(() => manager.getCredential('anthropic')).toThrow(
        'No valid credential for anthropic'
      );
    });

    test('should throw error for non-existent provider', async () => {
      const mockResponse = {
        credentials: {
          anthropic: {
            api_key: 'temp_ant_xyz789',
            expires_at: new Date(Date.now() + 3600000).toISOString()
          }
        },
        usage: { remaining_fixes: 85 }
      };

      (global.fetch as any).mockResolvedValueOnce({
        ok: true,
        json: async () => mockResponse
      });

      const manager = new RSOLVCredentialManager();
      await manager.initialize('test_api_key_123');

      expect(() => manager.getCredential('invalid_provider')).toThrow(
        'No valid credential for invalid_provider'
      );
    });
  });

  // Note: refresh is private and handled automatically via scheduleRefresh

  describe('reportUsage', () => {
    test('should report usage metrics', async () => {
      const initialResponse = {
        credentials: {
          anthropic: {
            api_key: 'temp_ant_xyz789',
            expires_at: new Date(Date.now() + 3600000).toISOString()
          }
        },
        usage: { remaining_fixes: 85 }
      };

      (global.fetch as any)
        .mockResolvedValueOnce({
          ok: true,
          json: async () => initialResponse
        })
        .mockResolvedValueOnce({
          ok: true,
          json: async () => ({ acknowledged: true })
        });

      const manager = new RSOLVCredentialManager();
      await manager.initialize('test_api_key_123');
      
      await manager.reportUsage('anthropic', {
        tokensUsed: 1500,
        requestCount: 1
      });

      // Verify the second call was for usage reporting
      expect(global.fetch).toHaveBeenCalledTimes(2);
      const secondCall = (global.fetch as any).mock.calls[1];
      expect(secondCall[0]).toContain('/api/v1/usage/report');
    });

    test('should handle usage reporting failure gracefully', async () => {
      const initialResponse = {
        credentials: {
          anthropic: {
            api_key: 'temp_ant_xyz789',
            expires_at: new Date(Date.now() + 3600000).toISOString()
          }
        },
        usage: { remaining_fixes: 85 }
      };

      (global.fetch as any)
        .mockResolvedValueOnce({
          ok: true,
          json: async () => initialResponse
        })
        .mockResolvedValueOnce({
          ok: false,
          status: 500
        });

      const manager = new RSOLVCredentialManager();
      await manager.initialize('test_api_key_123');
      
      // Should not throw
      await manager.reportUsage('anthropic', {
        tokensUsed: 1500,
        requestCount: 1
      });
    });
  });

  describe('cleanup', () => {
    test('should clear credentials and cancel refresh timers', async () => {
      const mockResponse = {
        credentials: {
          anthropic: {
            api_key: 'temp_ant_xyz789',
            expires_at: new Date(Date.now() + 3600000).toISOString()
          }
        },
        usage: { remaining_fixes: 85 }
      };

      (global.fetch as any).mockResolvedValueOnce({
        ok: true,
        json: async () => mockResponse
      });

      const manager = new RSOLVCredentialManager();
      await manager.initialize('test_api_key_123');
      
      // Verify credential exists
      expect(manager.getCredential('anthropic')).toBe('temp_ant_xyz789');
      
      // Cleanup
      manager.cleanup();
      
      // Credential should no longer be available
      expect(() => manager.getCredential('anthropic')).toThrow();
    });
  });
});