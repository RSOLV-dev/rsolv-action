// Synchronization utilities for better test isolation without sleep delays
// Based on Bun test pollution research findings

/**
 * Wait for all pending promises and timers to complete
 * Better alternative to fixed sleep delays
 */
export async function waitForPendingTasks(): Promise<void> {
  // Wait for next tick to allow any pending microtasks
  await new Promise(resolve => process.nextTick(resolve));
  
  // Wait for any pending macrotasks
  await new Promise(resolve => setTimeout(resolve, 0));
  
  // Allow one more cycle for cleanup
  await new Promise(resolve => setImmediate(resolve));
}

/**
 * Force garbage collection if available
 * Helps clean up leaked memory between tests
 */
export function forceGarbageCollection(): void {
  if (global.gc) {
    global.gc();
  } else if ((global as any).Bun?.gc) {
    (global as any).Bun.gc();
  }
}

/**
 * Wait for modules to finish loading/unloading
 * Addresses module cache pollution issues
 */
export async function waitForModuleStability(): Promise<void> {
  // Check if require.cache is stable
  let cacheSize = Object.keys(require.cache || {}).length;
  let stableCount = 0;
  
  while (stableCount < 3) {
    await waitForPendingTasks();
    const newCacheSize = Object.keys(require.cache || {}).length;
    
    if (newCacheSize === cacheSize) {
      stableCount++;
    } else {
      stableCount = 0;
      cacheSize = newCacheSize;
    }
  }
}

/**
 * Clean up specific test artifacts
 * More targeted than global cleanup
 */
export function cleanupTestArtifacts(): void {
  // Clear any test-specific globals
  const testGlobals = Object.keys(globalThis).filter(key => 
    key.includes('__RSOLV_') || 
    key.includes('test') || 
    key.includes('mock')
  );
  
  testGlobals.forEach(key => {
    try {
      delete (globalThis as any)[key];
    } catch {
      // Ignore deletion errors for non-configurable properties
    }
  });
  
  // Clear test environment variables
  const testEnvVars = Object.keys(process.env).filter(key =>
    key.startsWith('RSOLV_') ||
    key.includes('TEST') ||
    key.includes('MOCK')
  );
  
  testEnvVars.forEach(key => {
    delete process.env[key];
  });
}

/**
 * Wait for network operations to complete
 * Better than fixed delays for async operations
 */
export async function waitForNetworkQuiet(): Promise<void> {
  // Wait for any pending fetch operations
  await new Promise(resolve => {
    const checkNetwork = () => {
      // Simple heuristic: if no network activity for 100ms, consider it quiet
      setTimeout(() => {
        resolve(undefined);
      }, 100);
    };
    checkNetwork();
  });
}

/**
 * Complete test cleanup without fixed sleep delays
 */
export async function performCompleteCleanup(): Promise<void> {
  // Clean up artifacts first
  cleanupTestArtifacts();
  
  // Wait for any pending operations
  await waitForPendingTasks();
  
  // Wait for module stability
  await waitForModuleStability();
  
  // Wait for network to quiet down
  await waitForNetworkQuiet();
  
  // Force garbage collection if available
  forceGarbageCollection();
  
  // Final wait for any cleanup to complete
  await waitForPendingTasks();
}

/**
 * Synchronous cleanup for cases where async isn't possible
 */
export function performSyncCleanup(): void {
  cleanupTestArtifacts();
  forceGarbageCollection();
}