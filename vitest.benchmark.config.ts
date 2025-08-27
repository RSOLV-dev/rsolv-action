import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    include: ['**/*.bench.ts'],
    benchmark: {
      // Performance thresholds
      include: ['**/*.bench.ts'],
      exclude: ['node_modules', 'dist'],
      
      // Output options
      outputFile: 'benchmark-results.json',
      
      // Performance budgets - removed as it causes type error
    }
  }
});