import { defineConfig } from 'vitest/config';
import path from 'path';

/**
 * Memory-optimized Vitest configuration for running memory-intensive tests
 * Use this config when running the full test suite or security/AI tests
 * 
 * Usage: npx vitest --config vitest.config.memory.ts
 */
export default defineConfig({
  test: {
    // Use node environment for consistency
    environment: 'node',
    
    // Increased timeouts for memory-intensive operations
    testTimeout: 30000,
    hookTimeout: 15000,
    teardownTimeout: 5000,
    
    // Enable globals
    globals: true,
    
    // Setup files
    setupFiles: ['./test/vitest-setup.ts'],
    
    // CRITICAL: Use forks pool for complete process isolation
    pool: 'forks',
    poolOptions: {
      forks: {
        // Process isolation settings
        isolate: true, // Each test file gets its own process
        singleFork: false, // Don't reuse forks
        maxForks: 1, // Run one test file at a time to minimize memory pressure
        minForks: 1,
        
        // Aggressive recycling - restart worker after each file
      }
    },
    
    // CRITICAL: Enable test isolation for proper cleanup
    isolate: true,
    
    // Single file at a time to prevent memory accumulation
    maxConcurrency: 1,
    maxWorkers: 1,
    minWorkers: 1,
    
    // Clear all mocks between tests
    mockReset: true,
    clearMocks: true,
    restoreMocks: true,
    
    // Memory monitoring
    logHeapUsage: true,
    
    // Reporter optimizations - use default with minimal output
    reporters: [['default', { summary: false }]], // Minimal output to save memory
    
    // Coverage disabled to save memory
    coverage: {
      enabled: false,
    },
    
    // Exclude non-essential files
    exclude: [
      '**/node_modules/**',
      '**/dist/**',
      '**/*.bun-backup',
      '**/vulnerable-apps/**',
      '**/archived-scripts/**',
      '**/*.md',
    ],
    
    // Bail on first failure to avoid running unnecessary tests
    bail: 1,
    
    // File parallelism disabled
    fileParallelism: false,
    
    // Cache disabled to ensure clean runs
    cache: false,
    
    // Disable watch mode features
    watch: false,
    
    // Custom hooks for memory management
    onConsoleLog(log, type) {
      // Suppress verbose logs to save memory
      if (type === 'stderr' || log.includes('[DEBUG]')) {
        return false;
      }
      return true;
    },
  },
  
  resolve: {
    alias: {
      '@': path.resolve(__dirname, './src'),
    },
  },
  
  // Optimize esbuild for memory
  esbuild: {
    target: 'node16',
    // Minimize memory usage during transformation
    keepNames: false,
  },
});