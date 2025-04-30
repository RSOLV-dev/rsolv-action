import { test, expect, mock, beforeEach } from 'bun:test';
import {
  processWebhookPayload,
  isEligibleForAutomation,
  isRateLimited,
  processExpertReviewRequest,
  ExpertReviewRequest,
  resetRateLimits,
  customerRateLimits
} from '../webhook';
import { IssueContext } from '../../types';

// Mock the security utility
mock.module('../../utils/security', () => ({
  validateApiKey: mock((apiKey: string) => Promise.resolve(apiKey === 'valid-api-key'))
}));

// Mock nodemailer
mock.module('nodemailer', () => ({
  createTransport: () => ({
    sendMail: mock(() => Promise.resolve())
  })
}));

// Mock the logger
mock.module('../../utils/logger', () => ({
  error: mock(() => {}),
  warning: mock(() => {}),
  info: mock(() => {}),
  debug: mock(() => {})
}));

// Setup for tests
beforeEach(() => {
  // Reset any in-memory data between tests using our exported function
  resetRateLimits();
});

test('processWebhookPayload should validate API key', async () => {
  const result = await processWebhookPayload({
    source: 'jira',
    apiKey: 'invalid-key',
    issue: {
      id: '123',
      title: 'Test Issue',
      description: 'Test Description',
      url: 'https://jira.example.com/browse/ISSUE-123',
      labels: ['bug']
    },
    repository: {
      owner: 'test-owner',
      name: 'test-repo',
      branch: 'main'
    }
  });
  
  expect(result).toBeNull();
});

test('processWebhookPayload should convert external issue to IssueContext', async () => {
  const result = await processWebhookPayload({
    source: 'jira',
    apiKey: 'valid-api-key',
    issue: {
      id: '123',
      title: 'Test Issue',
      description: 'Test Description',
      url: 'https://jira.example.com/browse/ISSUE-123',
      labels: ['bug']
    },
    repository: {
      owner: 'test-owner',
      name: 'test-repo',
      branch: 'main'
    }
  });
  
  expect(result).not.toBeNull();
  expect(result?.id).toBe('123');
  expect(result?.source).toBe('jira');
  expect(result?.title).toBe('Test Issue');
  expect(result?.body).toBe('Test Description');
  expect(result?.labels).toContain('bug');
  expect(result?.repository.owner).toBe('test-owner');
  expect(result?.repository.name).toBe('test-repo');
  expect(result?.repository.branch).toBe('main');
  expect(result?.url).toBe('https://jira.example.com/browse/ISSUE-123');
});

test('isEligibleForAutomation should check automation tag and body', () => {
  const issueContext: IssueContext = {
    id: '123',
    source: 'jira',
    title: 'Test Issue',
    body: 'Test Description',
    labels: ['bug', 'AUTOFIX'],
    repository: {
      owner: 'test-owner',
      name: 'test-repo'
    },
    metadata: {}
  };
  
  expect(isEligibleForAutomation(issueContext, 'AUTOFIX')).toBe(true);
  expect(isEligibleForAutomation(issueContext, 'DIFFERENT_TAG')).toBe(false);
  
  const emptyBodyContext = {
    ...issueContext,
    body: ''
  };
  expect(isEligibleForAutomation(emptyBodyContext, 'AUTOFIX')).toBe(false);
});

test('isRateLimited should limit based on daily and monthly usage', () => {
  // Test that a new customer is not rate limited
  expect(isRateLimited('customer-1')).toBe(false);
  
  // Directly simulate exceeding daily limit
  customerRateLimits['customer-1'] = {
    dailyLimit: 1,
    monthlyLimit: 5,
    dailyUsed: 1, // Already used their daily limit
    monthlyUsed: 1,
    lastReset: new Date()
  };
  
  // Now it should be rate limited
  expect(isRateLimited('customer-1')).toBe(true);
  
  // Different customer should not be rate limited
  expect(isRateLimited('customer-2')).toBe(false);
  
  // Reset for next test
  resetRateLimits();
});

test('processExpertReviewRequest should validate API key and check rate limits', async () => {
  const request: ExpertReviewRequest = {
    prNumber: 123,
    prUrl: 'https://github.com/test-owner/test-repo/pull/123',
    repository: {
      owner: 'test-owner',
      name: 'test-repo'
    },
    issueTitle: 'Fix the bug',
    requestedBy: 'user123',
    customerName: 'ACME Corp'
  };
  
  // Invalid API key should fail
  const invalidResult = await processExpertReviewRequest(request, 'invalid-key');
  expect(invalidResult).toBe(false);
  
  // Valid API key should succeed
  const validResult = await processExpertReviewRequest(request, 'valid-api-key');
  expect(validResult).toBe(true);
  
  // Second request should be rate limited
  const rateLimitedResult = await processExpertReviewRequest(request, 'valid-api-key');
  expect(rateLimitedResult).toBe(false);
});