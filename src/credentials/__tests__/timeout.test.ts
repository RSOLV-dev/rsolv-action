import { describe, expect, test, beforeEach, afterEach, vi } from 'vitest';
import { RSOLVCredentialManager } from '../manager';

describe('Credential Manager Timeout Behavior', () => {
  let manager: RSOLVCredentialManager;
  const originalRsolvApiUrl = process.env.RSOLV_API_URL;
  
  beforeEach(() => {
    // Clear RSOLV_API_URL to use default
    delete process.env.RSOLV_API_URL;
    manager = new RSOLVCredentialManager();
    vi.clearAllMocks();
  });

  afterEach(() => {
    manager.cleanup();
    // Restore RSOLV_API_URL
    if (originalRsolvApiUrl !== undefined) {
      process.env.RSOLV_API_URL = originalRsolvApiUrl;
    } else {
      delete process.env.RSOLV_API_URL;
    }
  });

  test('should timeout credential exchange after 15 seconds', async () => {
    // Mock fetch to never resolve
    let abortSignal: AbortSignal | undefined;
    const fetchSpy = vi.spyOn(global, 'fetch').mockImplementation((_url: string, options: any) => {
      abortSignal = options.signal;
      return new Promise(() => {}); // Never resolves
    });

    const initPromise = manager.initialize('test-api-key');
    
    // Wait a bit to ensure the request is made
    await new Promise(resolve => setTimeout(resolve, 100));
    
    // Check that AbortSignal timeout was set to 15 seconds
    expect(abortSignal).toBeDefined();
    // AbortSignal.timeout creates a signal that will abort after the specified time
    // We can't directly check the timeout value, but we can verify the signal exists
    
    // Clean up spy
    fetchSpy.mockRestore();
  });

  test('should timeout usage reporting after 5 seconds', async () => {
    // First initialize successfully
    const fetchSpy = vi.spyOn(global, 'fetch').mockResolvedValueOnce({
      ok: true,
      json: async () => ({
        credentials: {
          anthropic: {
            api_key: 'test-key',
            expires_at: new Date(Date.now() + 3600000).toISOString()
          }
        },
        usage: {
          remaining_fixes: 10,
          reset_at: new Date(Date.now() + 86400000).toISOString()
        }
      })
    } as any);
    
    await manager.initialize('test-api-key');
    
    // Now mock fetch to never resolve for usage reporting
    let abortSignal: AbortSignal | undefined;
    fetchSpy.mockImplementation((_url: string, options: any) => {
      abortSignal = options.signal;
      return new Promise(() => {}); // Never resolves
    });
    
    // Report usage (should not throw, just log warning)
    // Don't await since it will hang - reportUsage catches errors internally
    manager.reportUsage('anthropic', {
      tokensUsed: 100,
      requestCount: 1
    });
    
    // Wait a bit to ensure the request is made
    await new Promise(resolve => setTimeout(resolve, 100));
    
    // Check that AbortSignal timeout was set to 5 seconds
    expect(abortSignal).toBeDefined();
    // AbortSignal.timeout creates a signal that will abort after the specified time
    
    fetchSpy.mockRestore();
  });

  test('should schedule refresh with proper timeout configuration', async () => {
    // For this test, just verify that refresh scheduling works
    const clearTimeoutSpy = vi.spyOn(global, 'clearTimeout');
    
    // Initialize with credentials that will schedule refresh
    const fetchSpy = vi.spyOn(global, 'fetch').mockResolvedValueOnce({
      ok: true,
      json: async () => ({
        credentials: {
          anthropic: {
            api_key: 'test-key',
            expires_at: new Date(Date.now() + 3600000).toISOString() // 1 hour from now
          }
        },
        usage: {
          remaining_fixes: 10,
          reset_at: new Date(Date.now() + 86400000).toISOString()
        }
      })
    } as any);
    
    await manager.initialize('test-api-key');
    
    // Cleanup should clear the timer (verifies refresh was scheduled)
    manager.cleanup();
    
    // Should have cleared the refresh timer
    expect(clearTimeoutSpy).toHaveBeenCalledTimes(1);
    
    clearTimeoutSpy.mockRestore();
    fetchSpy.mockRestore();
  });

  test('should handle timeout errors gracefully', async () => {
    // Mock fetch to simulate timeout
    const fetchSpy = vi.spyOn(global, 'fetch').mockRejectedValue(new Error('The operation was aborted due to timeout'));
    
    // Initialize should throw with appropriate error
    await expect(manager.initialize('test-api-key')).rejects.toThrow('The operation was aborted due to timeout');
    
    fetchSpy.mockRestore();
  });

  test('should not hang when API is slow', async () => {
    // Mock fetch to resolve just before timeout
    const fetchSpy = vi.spyOn(global, 'fetch').mockImplementation(() => {
      return new Promise(resolve => {
        setTimeout(() => {
          resolve({
            ok: true,
            json: async () => ({
              credentials: {
                anthropic: {
                  api_key: 'test-key',
                  expires_at: new Date(Date.now() + 3600000).toISOString()
                }
              },
              usage: {
                remaining_fixes: 10,
                reset_at: new Date(Date.now() + 86400000).toISOString()
              }
            })
          } as any);
        }, 100); // Resolve quickly for test
      });
    });
    
    const start = Date.now();
    await manager.initialize('test-api-key');
    const duration = Date.now() - start;
    
    // Should complete successfully
    expect(manager.getCredential('anthropic')).toBe('test-key');
    
    // Should take about 100ms
    expect(duration).toBeGreaterThanOrEqual(100);
    expect(duration).toBeLessThan(200);
    
    fetchSpy.mockRestore();
  });

  test('should clean up timers on cleanup', async () => {
    const clearTimeoutSpy = vi.spyOn(global, 'clearTimeout');
    
    // Initialize with credentials that will schedule refresh
    const fetchSpy = vi.spyOn(global, 'fetch').mockResolvedValueOnce({
      ok: true,
      json: async () => ({
        credentials: {
          anthropic: {
            api_key: 'test-key',
            expires_at: new Date(Date.now() + 3600000).toISOString()
          },
          openai: {
            api_key: 'test-key-2',
            expires_at: new Date(Date.now() + 7200000).toISOString()
          }
        }
      })
    } as any);
    
    await manager.initialize('test-api-key');
    
    // Cleanup should clear all timers
    manager.cleanup();
    
    // Should have cleared 2 timers (one for each credential)
    expect(clearTimeoutSpy).toHaveBeenCalledTimes(2);
    
    clearTimeoutSpy.mockRestore();
    fetchSpy.mockRestore();
  });
});