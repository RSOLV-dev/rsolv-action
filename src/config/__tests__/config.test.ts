import { test, expect, beforeEach } from 'bun:test';
import { loadConfig, validateInput } from '../index.js';
import { ActionConfig } from '../../types.js';

test('loadConfig should throw error when api_key is not provided', () => {
  expect(() => loadConfig({})).toThrow('Input required and not supplied: api_key');
});

test('loadConfig should load config with defaults when only api_key is provided', () => {
  const config = loadConfig({ 'api_key': 'test-api-key' });
  
  expect(config.apiKey).toBe('test-api-key');
  expect(config.issueTag).toBe('AUTOFIX');
  expect(config.expertReviewCommand).toBe('/request-expert-review');
  expect(config.debug).toBe(false);
  expect(config.skipSecurityCheck).toBe(false);
  expect(config.aiConfig.provider).toBe('anthropic');
  expect(config.aiConfig.apiKey).toBe('test-api-key');
  expect(config.aiConfig.modelName).toBe('claude-3-sonnet-20240229');
});

test('loadConfig should set up AI configuration correctly', () => {
  const config = loadConfig({
    'api_key': 'test-api-key',
    'ai_provider': 'anthropic',
    'anthropic_api_key': 'anthropic-api-key',
    'anthropic_model': 'claude-3-opus-20240229'
  });
  
  expect(config.aiConfig.provider).toBe('anthropic');
  expect(config.aiConfig.apiKey).toBe('anthropic-api-key');
  expect(config.aiConfig.modelName).toBe('claude-3-opus-20240229');
});

test('loadConfig should fallback to default api key if specific one not provided', () => {
  const config = loadConfig({
    'api_key': 'test-api-key',
    'ai_provider': 'anthropic'
  });
  
  expect(config.aiConfig.apiKey).toBe('test-api-key');
});

test('validateInput should return null for valid api_key', () => {
  const result = validateInput('api_key', 'valid-key-1234567890');
  expect(result).toBeNull();
});

test('validateInput should return error message for short api_key', () => {
  const result = validateInput('api_key', 'short');
  expect(result).toBe('API key must be at least 10 characters long');
});

test('validateInput should return null for valid issue_tag', () => {
  const result = validateInput('issue_tag', 'VALID_TAG-123');
  expect(result).toBeNull();
});

test('validateInput should return error message for invalid issue_tag', () => {
  const result = validateInput('issue_tag', 'INVALID TAG!');
  expect(result).toBe('Issue tag must only contain alphanumeric characters, underscores, and hyphens');
});

test('validateInput should return null for valid ai_provider', () => {
  const result = validateInput('ai_provider', 'anthropic');
  expect(result).toBeNull();
});

test('validateInput should return error message for invalid ai_provider', () => {
  const result = validateInput('ai_provider', 'unknown');
  expect(result).toBe('AI provider must be one of: anthropic, openrouter, openai, mistral, ollama');
});

test('validateInput should return null for unknown input', () => {
  const result = validateInput('unknown_input', 'some value');
  expect(result).toBeNull();
});