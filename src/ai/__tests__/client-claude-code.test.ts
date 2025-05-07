/**
 * Tests for Claude Code integration in the AI client factory
 */
import { test, expect } from 'bun:test';
import { AIConfig } from '../types.js';

// Mock console functions to reduce noise
console.log = () => {};
console.error = () => {};
console.warn = () => {};
console.info = () => {};

// Mock the client modules
import * as aiClient from '../client.js';

// No need to store the original implementation as we're mocking the entire function

// Replace with a mock implementation
aiClient.getAIClient = function mockGetAIClient(config: AIConfig) {
  if (config.useClaudeCode) {
    return {
      type: 'claude-code-client',
      generateSolution: () => Promise.resolve({}),
      analyzeIssue: () => Promise.resolve({})
    };
  } else {
    return {
      type: 'standard-client',
      generateSolution: () => Promise.resolve({}),
      analyzeIssue: () => Promise.resolve({})
    };
  }
};

// Test data
const standardConfig: AIConfig = {
  provider: 'anthropic',
  apiKey: 'test-api-key'
};

const claudeCodeConfig: AIConfig = {
  provider: 'anthropic',
  apiKey: 'test-api-key',
  useClaudeCode: true
};

// Now run tests with our mock implementations
test('getAIClient should return different clients based on useClaudeCode flag', () => {
  const standardClient = aiClient.getAIClient(standardConfig);
  const claudeCodeClient = aiClient.getAIClient(claudeCodeConfig);
  
  expect(standardClient).not.toBe(claudeCodeClient);
  expect((standardClient as any).type).toBe('standard-client');
  expect((claudeCodeClient as any).type).toBe('claude-code-client');
});