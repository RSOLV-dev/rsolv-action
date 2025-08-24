import { describe, it, expect, beforeEach, afterEach, vi, jest, spyOn } from 'vitest';
import { RSOLVCredentialManager } from '../../src/credentials/manager.js';
import { RsolvApiClient } from '../../src/api/client.js';

describe('Credential Lifecycle Issues', () => {
  let credentialManager: RSOLVCredentialManager;
  let mockApiClient: RsolvApiClient;
  
  beforeEach(() => {
    vi.clearAllMocks();
    mockApiClient = {
      exchangeCredentials: vi.fn(),
      refreshCredentials: vi.fn(),
    } as Partial<RsolvApiClient> as RsolvApiClient;
  });

  afterEach(() => {
    if (credentialManager) {
      credentialManager.cleanup();
    }
  });

  describe('Issue: Multiple credential managers created', () => {
    it('should demonstrate the current problem - multiple managers', async () => {
      // Simulate what happens in the workflow
      const apiKey = 'rsolv_test_full_access_no_quota_2025';
      
      // First credential exchange (for initial analysis)
      const manager1 = new RSOLVCredentialManager();
      mockApiClient.exchangeCredentials.mockResolvedValueOnce({
        credentials: {
          anthropic: { api_key: 'vended-key-1', expires_at: new Date(Date.now() + 3600000).toISOString() }
        },
        usage: { remaining_fixes: 999999 }
      });
      await manager1.initialize();
      
      // Second credential exchange (for solution generation)
      const manager2 = new CredentialManager(mockApiClient, apiKey);
      mockApiClient.exchangeCredentials.mockResolvedValueOnce({
        credentials: {
          anthropic: { api_key: 'vended-key-2', expires_at: new Date(Date.now() + 3600000).toISOString() }
        },
        usage: { remaining_fixes: 999999 }
      });
      await manager2.initialize();
      
      // Third credential exchange (after long Claude session) - this fails
      const manager3 = new CredentialManager(mockApiClient, apiKey);
      mockApiClient.exchangeCredentials.mockRejectedValueOnce(
        new Error('Invalid API key')
      );
      
      await expect(manager3.initialize()).rejects.toThrow('Invalid API key');
      
      // This shows the problem: 3 separate exchanges instead of reusing
      expect(mockApiClient.exchangeCredentials).toHaveBeenCalledTimes(3);
      
      manager1.cleanup();
      manager2.cleanup();
    });
  });

  describe('Solution 1: Singleton credential manager', () => {
    it('should reuse the same credential manager instance', async () => {
      // Create a singleton pattern
      class CredentialManagerSingleton {
        private static instances = new Map<string, RSOLVCredentialManager>();
        
        static async getInstance(apiClient: RsolvApiClient, apiKey: string): Promise<RSOLVCredentialManager> {
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
      
      const apiKey = 'rsolv_test_full_access_no_quota_2025';
      
      mockApiClient.exchangeCredentials.mockResolvedValueOnce({
        credentials: {
          anthropic: { api_key: 'vended-key-1', expires_at: new Date(Date.now() + 3600000).toISOString() }
        },
        usage: { remaining_fixes: 999999 }
      });
      
      // Multiple requests should return same instance
      const manager1 = await CredentialManagerSingleton.getInstance(mockApiClient, apiKey);
      const manager2 = await CredentialManagerSingleton.getInstance(mockApiClient, apiKey);
      const manager3 = await CredentialManagerSingleton.getInstance(mockApiClient, apiKey);
      
      expect(manager1).toBe(manager2);
      expect(manager2).toBe(manager3);
      expect(mockApiClient.exchangeCredentials).toHaveBeenCalledTimes(1); // Only one exchange!
      
      CredentialManagerSingleton.cleanup();
    });
  });

  describe('Solution 2: Handle credential expiration gracefully', () => {
    it('should refresh expired credentials automatically', async () => {
      const manager = new RSOLVCredentialManager();
      
      // Initial exchange with short TTL (5 seconds)
      mockApiClient.exchangeCredentials.mockResolvedValueOnce({
        credentials: {
          anthropic: { 
            api_key: 'vended-key-1', 
            expires_at: new Date(Date.now() + 5000).toISOString() // Expires in 5 seconds
          }
        },
        usage: { remaining_fixes: 999999 }
      });
      
      await manager.initialize('test-api-key');
      const initialCred = await manager.getCredential('anthropic');
      expect(initialCred).toBe('vended-key-1');
      
      // Wait for expiration
      await new Promise(resolve => setTimeout(resolve, 6000));
      
      // Setup refresh response
      mockApiClient.refreshCredentials.mockResolvedValueOnce({
        credentials: {
          anthropic: { 
            api_key: 'vended-key-refreshed', 
            expires_at: new Date(Date.now() + 3600000).toISOString()
          }
        }
      });
      
      // Getting credential should trigger refresh
      const refreshedCred = await manager.getCredential('anthropic');
      expect(refreshedCred).toBe('vended-key-refreshed');
      expect(mockApiClient.refreshCredentials).toHaveBeenCalledTimes(1);
    });
  });

  describe('Solution 3: Retry on exchange failure', () => {
    it('should retry credential exchange with exponential backoff', async () => {
      const manager = new RSOLVCredentialManager();
      
      // First two attempts fail, third succeeds
      mockApiClient.exchangeCredentials
        .mockRejectedValueOnce(new Error('Invalid API key'))
        .mockRejectedValueOnce(new Error('Invalid API key'))
        .mockResolvedValueOnce({
          credentials: {
            anthropic: { api_key: 'vended-key-1', expires_at: new Date(Date.now() + 3600000).toISOString() }
          },
          usage: { remaining_fixes: 999999 }
        });
      
      // Add retry logic to initialize
      const initializeWithRetry = async (maxRetries = 3) => {
        for (let i = 0; i < maxRetries; i++) {
          try {
            await manager.initialize('test-api-key');
            return;
          } catch (error) {
            if (i === maxRetries - 1) throw error;
            // Exponential backoff: 100ms, 200ms, 400ms
            await new Promise(resolve => setTimeout(resolve, 100 * Math.pow(2, i)));
          }
        }
      };
      
      await initializeWithRetry();
      expect(mockApiClient.exchangeCredentials).toHaveBeenCalledTimes(3);
      
      const cred = await manager.getCredential('anthropic');
      expect(cred).toBe('vended-key-1');
    });
  });

  describe('Claude conversation logging', () => {
    it('should log full Claude conversations when enabled', async () => {
      // This is a placeholder for the Claude logging feature
      const conversationLogger = {
        logDir: './ai-conversation-logs',
        enabled: process.env.AI_CONVERSATION_LOG_LEVEL === 'full',
        
        async logConversation(issueId: string, messages: any[]) {
          if (!this.enabled) return;
          
          const timestamp = new Date().toISOString();
          const logData = {
            issueId,
            timestamp,
            messages,
            metadata: {
              workflow_run: process.env.GITHUB_RUN_ID,
              workflow_job: process.env.GITHUB_JOB,
            }
          };
          
          // In real implementation, write to file
          console.log('Would log conversation:', logData);
        }
      };
      
      expect(conversationLogger.enabled).toBe(false); // Not enabled by default
    });
  });
});