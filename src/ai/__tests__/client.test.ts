/**
 * Tests for the AI client factory
 */
import { test, expect, mock } from 'bun:test';
import { getAIClient } from '../client';
import { OllamaClient } from '../providers/ollama';

// Mock the logger to avoid noisy logs
mock.module('../../utils/logger', () => ({
  info: () => {},
  warn: () => {},
  error: () => {},
  debug: () => {}
}));

// Simplified tests for client factory
test('getAIClient should return Ollama client for ollama provider', () => {
  const client = getAIClient({
    provider: 'ollama',
    apiKey: 'test-key'
  });
  
  expect(client).toBeInstanceOf(OllamaClient);
});

// Test that getAIClient throws for unimplemented providers
test('getAIClient should throw for unimplemented providers', () => {
  expect(() => {
    getAIClient({
      provider: 'openai',
      apiKey: 'test-key'
    });
  }).toThrow('AI provider openai is not yet implemented');
});

// Test that getAIClient throws for unknown providers
test('getAIClient should throw for unknown providers', () => {
  expect(() => {
    getAIClient({
      // @ts-expect-error - Testing with invalid provider
      provider: 'unknown-provider',
      apiKey: 'test-key'
    });
  }).toThrow('Unknown AI provider: unknown-provider');
});