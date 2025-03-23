import { test, expect, beforeEach } from 'bun:test';
import { loadConfig, validateInput } from '../index';
import { ActionConfig } from '../../types';

test('loadConfig should throw error when api_key is not provided', () => {
  expect(() => loadConfig({})).toThrow('Input required and not supplied: api_key');
});

test('loadConfig should load config with defaults when only api_key is provided', () => {
  const config = loadConfig({ 'api_key': 'test-api-key' });
  
  expect(config).toEqual({
    apiKey: 'test-api-key',
    issueTag: 'AUTOFIX',
    expertReviewCommand: '/request-expert-review',
    debug: false,
    skipSecurityCheck: false
  });
});

test('loadConfig should override defaults with provided values', () => {
  const config = loadConfig({
    'api_key': 'test-api-key',
    'issue_tag': 'CUSTOM_TAG',
    'expert_review_command': '/custom-review',
    'debug': 'true',
    'skip_security_check': 'true'
  });
  
  expect(config).toEqual({
    apiKey: 'test-api-key',
    issueTag: 'CUSTOM_TAG',
    expertReviewCommand: '/custom-review',
    debug: true,
    skipSecurityCheck: true
  });
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

test('validateInput should return null for unknown input', () => {
  const result = validateInput('unknown_input', 'some value');
  expect(result).toBeNull();
});