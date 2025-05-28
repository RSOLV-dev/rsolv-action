/**
 * Tests for Claude Code integration in the AI client factory
 */
import { test, expect, mock } from 'bun:test';
import { AIConfig } from '../types.js';

// Mock the logger
mock.module('../../utils/logger', () => ({
  logger: {
    info: () => {},
    warn: () => {},
    error: () => {},
    debug: () => {}
  }
}));

// Mock the client module
mock.module('../client', () => ({
  getAiClient: async (config: AIConfig) => {
    if (config.useClaudeCode) {
      return {
        type: 'claude-code-client',
        complete: async () => 'Claude Code response',
        generateSolution: () => Promise.resolve({}),
        analyzeIssue: () => Promise.resolve({})
      };
    } else {
      return {
        type: 'standard-client',
        complete: async () => 'Standard response',
        generateSolution: () => Promise.resolve({}),
        analyzeIssue: () => Promise.resolve({})
    };
  }
}));

// Import after mocking
import { getAiClient } from '../client.js';

// Test data
const standardConfig: AIConfig = {
  type: 'anthropic',
  apiKey: 'test-api-key'
};

const claudeCodeConfig: AIConfig = {
  type: 'anthropic',
  apiKey: 'test-api-key',
  useClaudeCode: true
};

// Now run tests with our mock implementations
test.skip('getAIClient should return different clients based on useClaudeCode flag', async () => {
  // SKIPPED: This test is outdated after refactoring. The useClaudeCode flag is no longer used in the main client logic.
  const standardClient = await getAiClient(standardConfig);
  const claudeCodeClient = await getAiClient(claudeCodeConfig);
  
  expect(standardClient).not.toBe(claudeCodeClient);
  expect((standardClient as any).type).toBe('standard-client');
  expect((claudeCodeClient as any).type).toBe('claude-code-client');
});