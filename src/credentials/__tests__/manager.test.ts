import { RSOLVCredentialManager } from '../manager';
import { logger } from '../../utils/logger';

// Mock fetch globally
global.fetch = jest.fn();

// Mock environment variables
const originalEnv = process.env;

beforeEach(() => {
  // Reset mocks
  jest.clearAllMocks();
  (global.fetch as jest.Mock).mockReset();
  
  // Set test environment
  process.env = {
    ...originalEnv,
    GITHUB_JOB: 'test_job_123',
    GITHUB_RUN_ID: 'test_run_456',
    RSOLV_API_URL: 'https://api.rsolv.dev'
  };
});

afterEach(() => {
  process.env = originalEnv;
});

describe('RSOLVCredentialManager', () => {
  describe('initialize', () => {
    it('should exchange RSOLV API key for temporary credentials', async () => {
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

      (global.fetch as jest.Mock).mockResolvedValueOnce({
        ok: true,
        json: async () => mockResponse
      });

      const manager = new RSOLVCredentialManager();
      await manager.initialize('rsolv_test_abc123');

      expect(global.fetch).toHaveBeenCalledWith(
        'https://api.rsolv.dev/v1/credentials/exchange',
        {
          method: 'POST',
          headers: {
            'Authorization': 'Bearer rsolv_test_abc123',
            'Content-Type': 'application/json',
            'X-GitHub-Job': 'test_job_123',
            'X-GitHub-Run': 'test_run_456'
          },
          body: JSON.stringify({
            providers: ['anthropic', 'openai', 'openrouter'],
            ttl_minutes: 60
          })
        }
      );

      // Test that credentials were stored
      expect(manager.getCredential('anthropic')).toBe('temp_ant_xyz789');
      expect(manager.getCredential('openai')).toBe('temp_oai_def456');
    });

    it('should throw error on failed API response', async () => {
      (global.fetch as jest.Mock).mockResolvedValueOnce({
        ok: false,
        status: 401,
        json: async () => ({ error: 'Invalid API key' })
      });

      const manager = new RSOLVCredentialManager();
      
      await expect(manager.initialize('invalid_key')).rejects.toThrow(
        'Failed to exchange credentials: Invalid API key'
      );
    });

    it('should throw error on network failure', async () => {
      (global.fetch as jest.Mock).mockRejectedValueOnce(new Error('Network error'));

      const manager = new RSOLVCredentialManager();
      
      await expect(manager.initialize('rsolv_test_abc123')).rejects.toThrow(
        'Network error'
      );
    });

    it('should schedule credential refresh before expiration', async () => {
      const expiresAt = new Date(Date.now() + 3600000); // 1 hour
      const mockResponse = {
        credentials: {
          anthropic: {
            api_key: 'temp_ant_xyz789',
            expires_at: expiresAt.toISOString()
          }
        }
      };

      (global.fetch as jest.Mock).mockResolvedValueOnce({
        ok: true,
        json: async () => mockResponse
      });

      const manager = new RSOLVCredentialManager();
      const refreshSpy = jest.spyOn(manager as any, 'scheduleRefresh');
      
      await manager.initialize('rsolv_test_abc123');

      expect(refreshSpy).toHaveBeenCalledWith(mockResponse.credentials);
    });
  });

  describe('getCredential', () => {
    it('should return valid credential', async () => {
      const mockResponse = {
        credentials: {
          anthropic: {
            api_key: 'temp_ant_xyz789',
            expires_at: new Date(Date.now() + 3600000).toISOString()
          }
        }
      };

      (global.fetch as jest.Mock).mockResolvedValueOnce({
        ok: true,
        json: async () => mockResponse
      });

      const manager = new RSOLVCredentialManager();
      await manager.initialize('rsolv_test_abc123');

      const credential = manager.getCredential('anthropic');
      expect(credential).toBe('temp_ant_xyz789');
    });

    it('should throw error for expired credential', async () => {
      const mockResponse = {
        credentials: {
          anthropic: {
            api_key: 'temp_ant_xyz789',
            expires_at: new Date(Date.now() - 1000).toISOString() // Expired
          }
        }
      };

      (global.fetch as jest.Mock).mockResolvedValueOnce({
        ok: true,
        json: async () => mockResponse
      });

      const manager = new RSOLVCredentialManager();
      await manager.initialize('rsolv_test_abc123');

      expect(() => manager.getCredential('anthropic')).toThrow(
        'No valid credential for anthropic'
      );
    });

    it('should throw error for non-existent provider', async () => {
      const mockResponse = {
        credentials: {
          anthropic: {
            api_key: 'temp_ant_xyz789',
            expires_at: new Date(Date.now() + 3600000).toISOString()
          }
        }
      };

      (global.fetch as jest.Mock).mockResolvedValueOnce({
        ok: true,
        json: async () => mockResponse
      });

      const manager = new RSOLVCredentialManager();
      await manager.initialize('rsolv_test_abc123');

      expect(() => manager.getCredential('mistral')).toThrow(
        'No valid credential for mistral'
      );
    });
  });

  describe('refresh', () => {
    it('should refresh expiring credentials', async () => {
      const initialResponse = {
        credentials: {
          anthropic: {
            api_key: 'temp_ant_xyz789',
            expires_at: new Date(Date.now() + 300000).toISOString() // 5 minutes
          }
        }
      };

      const refreshResponse = {
        credentials: {
          anthropic: {
            api_key: 'temp_ant_new123',
            expires_at: new Date(Date.now() + 3600000).toISOString() // 1 hour
          }
        }
      };

      (global.fetch as jest.Mock)
        .mockResolvedValueOnce({
          ok: true,
          json: async () => initialResponse
        })
        .mockResolvedValueOnce({
          ok: true,
          json: async () => refreshResponse
        });

      const manager = new RSOLVCredentialManager();
      await manager.initialize('rsolv_test_abc123');
      
      // Call refresh manually
      await (manager as any).refreshCredentials('anthropic');

      expect(global.fetch).toHaveBeenCalledTimes(2);
      expect(manager.getCredential('anthropic')).toBe('temp_ant_new123');
    });

    it('should handle refresh failure gracefully', async () => {
      const initialResponse = {
        credentials: {
          anthropic: {
            api_key: 'temp_ant_xyz789',
            expires_at: new Date(Date.now() + 300000).toISOString()
          }
        }
      };

      (global.fetch as jest.Mock)
        .mockResolvedValueOnce({
          ok: true,
          json: async () => initialResponse
        })
        .mockResolvedValueOnce({
          ok: false,
          status: 429,
          json: async () => ({ error: 'Rate limit exceeded' })
        });

      const manager = new RSOLVCredentialManager();
      await manager.initialize('rsolv_test_abc123');
      
      const loggerErrorSpy = jest.spyOn(logger, 'error');
      
      await expect((manager as any).refreshCredentials('anthropic')).rejects.toThrow();
      
      expect(loggerErrorSpy).toHaveBeenCalledWith(
        'Failed to refresh credentials for anthropic',
        expect.any(Error)
      );
    });
  });

  describe('reportUsage', () => {
    it('should report usage metrics', async () => {
      const initialResponse = {
        credentials: {
          anthropic: {
            api_key: 'temp_ant_xyz789',
            expires_at: new Date(Date.now() + 3600000).toISOString()
          }
        }
      };

      (global.fetch as jest.Mock)
        .mockResolvedValueOnce({
          ok: true,
          json: async () => initialResponse
        })
        .mockResolvedValueOnce({
          ok: true,
          json: async () => ({ status: 'recorded' })
        });

      const manager = new RSOLVCredentialManager();
      await manager.initialize('rsolv_test_abc123');
      
      await manager.reportUsage('anthropic', {
        tokensUsed: 1500,
        requestCount: 3
      });

      expect(global.fetch).toHaveBeenLastCalledWith(
        'https://api.rsolv.dev/v1/usage/report',
        {
          method: 'POST',
          headers: {
            'Authorization': 'Bearer rsolv_test_abc123',
            'Content-Type': 'application/json'
          },
          body: JSON.stringify({
            provider: 'anthropic',
            tokens_used: 1500,
            request_count: 3,
            job_id: 'test_job_123'
          })
        }
      );
    });

    it('should handle usage reporting failure gracefully', async () => {
      const initialResponse = {
        credentials: {
          anthropic: {
            api_key: 'temp_ant_xyz789',
            expires_at: new Date(Date.now() + 3600000).toISOString()
          }
        }
      };

      (global.fetch as jest.Mock)
        .mockResolvedValueOnce({
          ok: true,
          json: async () => initialResponse
        })
        .mockResolvedValueOnce({
          ok: false,
          status: 500,
          json: async () => ({ error: 'Internal server error' })
        });

      const manager = new RSOLVCredentialManager();
      await manager.initialize('rsolv_test_abc123');
      
      const loggerWarnSpy = jest.spyOn(logger, 'warn');
      
      // Should not throw, just log warning
      await manager.reportUsage('anthropic', {
        tokensUsed: 1500,
        requestCount: 3
      });
      
      expect(loggerWarnSpy).toHaveBeenCalledWith(
        'Failed to report usage',
        expect.any(Error)
      );
    });
  });

  describe('cleanup', () => {
    it('should clear credentials and cancel refresh timers', async () => {
      const mockResponse = {
        credentials: {
          anthropic: {
            api_key: 'temp_ant_xyz789',
            expires_at: new Date(Date.now() + 3600000).toISOString()
          }
        }
      };

      (global.fetch as jest.Mock).mockResolvedValueOnce({
        ok: true,
        json: async () => mockResponse
      });

      const manager = new RSOLVCredentialManager();
      await manager.initialize('rsolv_test_abc123');
      
      manager.cleanup();
      
      // Should throw after cleanup
      expect(() => manager.getCredential('anthropic')).toThrow(
        'No valid credential for anthropic'
      );
    });
  });
});