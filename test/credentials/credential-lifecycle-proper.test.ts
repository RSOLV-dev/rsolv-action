import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { RSOLVCredentialManager } from '../../src/credentials/manager.js';

// Mock fetch globally
global.fetch = vi.fn();

describe('Credential Lifecycle Issues - TDD', () => {
  let mockFetch: any;
  
  beforeEach(() => {
    vi.clearAllMocks();
    mockFetch = global.fetch as any;
  });

  describe('Current Problem: Multiple credential exchanges', () => {
    it('should demonstrate the problem - multiple managers create multiple exchanges', async () => {
      const apiKey = 'rsolv_test_full_access_no_quota_2025';
      
      // Mock successful responses for each exchange
      mockFetch
        .mockResolvedValueOnce({
          ok: true,
          json: async () => ({
            credentials: {
              anthropic: { api_key: 'vended-key-1', expires_at: new Date(Date.now() + 3600000).toISOString() }
            },
            usage: { remaining_fixes: 999999 }
          })
        })
        .mockResolvedValueOnce({
          ok: true,
          json: async () => ({
            credentials: {
              anthropic: { api_key: 'vended-key-2', expires_at: new Date(Date.now() + 3600000).toISOString() }
            },
            usage: { remaining_fixes: 999999 }
          })
        })
        .mockResolvedValueOnce({
          ok: false,
          status: 401,
          json: async () => ({ error: 'Invalid API key' })
        });
      
      // Simulate what happens in the workflow
      const manager1 = new RSOLVCredentialManager();
      await manager1.initialize(apiKey);
      
      const manager2 = new RSOLVCredentialManager();
      await manager2.initialize(apiKey);
      
      const manager3 = new RSOLVCredentialManager();
      await expect(manager3.initialize(apiKey)).rejects.toThrow('Failed to exchange credentials');
      
      // This shows the problem: 3 separate exchanges
      expect(mockFetch).toHaveBeenCalledTimes(3);
      
      manager1.cleanup();
      manager2.cleanup();
    });
  });

  describe('Testing the Singleton Solution', () => {
    // First, let's create the singleton class TDD-style
    class CredentialManagerSingleton {
      private static instances = new Map<string, RSOLVCredentialManager>();
      
      static async getInstance(apiKey: string): Promise<RSOLVCredentialManager> {
        if (!this.instances.has(apiKey)) {
          const manager = new RSOLVCredentialManager();
          await manager.initialize(apiKey);
          this.instances.set(apiKey, manager);
        }
        return this.instances.get(apiKey)!;
      }
      
      static cleanup() {
        this.instances.forEach(manager => manager.cleanup());
        this.instances.clear();
      }
    }
    
    it('should reuse the same credential manager instance', async () => {
      const apiKey = 'rsolv_test_singleton';
      
      mockFetch.mockResolvedValue({
        ok: true,
        json: async () => ({
          credentials: {
            anthropic: { api_key: 'vended-singleton', expires_at: new Date(Date.now() + 3600000).toISOString() }
          },
          usage: { remaining_fixes: 999999 }
        })
      });
      
      // Multiple requests should return same instance
      const manager1 = await CredentialManagerSingleton.getInstance(apiKey);
      const manager2 = await CredentialManagerSingleton.getInstance(apiKey);
      const manager3 = await CredentialManagerSingleton.getInstance(apiKey);
      
      expect(manager1).toBe(manager2);
      expect(manager2).toBe(manager3);
      expect(mockFetch).toHaveBeenCalledTimes(1); // Only one exchange!
      
      CredentialManagerSingleton.cleanup();
    });
  });

  describe('Testing Retry Logic', () => {
    it('should retry on failure with exponential backoff', async () => {
      const apiKey = 'rsolv_test_retry';
      
      // Mock fetch to fail twice, then succeed
      mockFetch
        .mockRejectedValueOnce(new Error('Network error'))
        .mockRejectedValueOnce(new Error('Network error'))
        .mockResolvedValueOnce({
          ok: true,
          json: async () => ({
            credentials: {
              anthropic: { api_key: 'vended-retry', expires_at: new Date(Date.now() + 3600000).toISOString() }
            },
            usage: { remaining_fixes: 999999 }
          })
        });
      
      // Create a manager with retry logic
      const initializeWithRetry = async (manager: RSOLVCredentialManager, apiKey: string, maxRetries = 3) => {
        for (let i = 0; i < maxRetries; i++) {
          try {
            await manager.initialize(apiKey);
            return;
          } catch (error) {
            if (i === maxRetries - 1) throw error;
            // Exponential backoff: 10ms, 20ms, 40ms (faster for tests)
            await new Promise(resolve => setTimeout(resolve, 10 * Math.pow(2, i)));
          }
        }
      };
      
      const manager = new RSOLVCredentialManager();
      await initializeWithRetry(manager, apiKey);
      
      expect(mockFetch).toHaveBeenCalledTimes(3);
      expect(await manager.getCredential('anthropic')).toBe('vended-retry');
      
      manager.cleanup();
    });
  });

  describe('Testing Credential Expiration Handling', () => {
    it('should detect expired credentials', async () => {
      const apiKey = 'rsolv_test_expiry';
      
      // Mock response with very short TTL
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => ({
          credentials: {
            anthropic: { 
              api_key: 'vended-expiring', 
              expires_at: new Date(Date.now() + 100).toISOString() // Expires in 100ms
            }
          },
          usage: { remaining_fixes: 999999 }
        })
      });
      
      const manager = new RSOLVCredentialManager();
      await manager.initialize(apiKey);
      
      // Credential should be valid immediately
      const cred1 = await manager.getCredential('anthropic');
      expect(cred1).toBe('vended-expiring');
      
      // Wait for expiration
      await new Promise(resolve => setTimeout(resolve, 150));
      
      // After expiration, getCredential should throw
      await expect(manager.getCredential('anthropic')).rejects.toThrow('expired');
      
      manager.cleanup();
    });
  });
});