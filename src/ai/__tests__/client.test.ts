/**
 * Tests for the AI client factory
 */
import { test, expect, mock } from 'bun:test';
import { getAiClient } from '../client.js';

// Mock the logger to avoid noisy logs
mock.module('../../utils/logger', () => ({
  info: () => {},
  warn: () => {},
  error: () => {},
  debug: () => {}
}));

// Simplified tests for client factory
test('getAiClient should return Ollama client for ollama provider', async () => {
  const client = await getAiClient({
    provider: 'ollama',
    apiKey: 'test-key'
  });
  
  expect(client).toBeDefined();
  expect(client.complete).toBeDefined();
  expect(typeof client.complete).toBe('function');
});

// Test that getAiClient returns OpenAI client
test('getAiClient should return OpenAI client for openai provider', async () => {
  const client = await getAiClient({
    provider: 'openai',
    apiKey: 'test-key',
    model: 'gpt-4'
  });
  
  expect(client).toBeDefined();
  expect(client.complete).toBeDefined();
  expect(typeof client.complete).toBe('function');
});

// Test that getAiClient throws for unknown providers
test('getAiClient should throw for unknown providers', async () => {
  await expect(async () => {
    await getAiClient({
      // @ts-expect-error - Testing with invalid provider
      provider: 'unknown-provider',
      apiKey: 'test-key'
    });
  }).toThrow('Unsupported AI provider: unknown-provider');
});