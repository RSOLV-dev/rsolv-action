import { test, expect, mock } from 'bun:test';
import { IssueContext } from '../../types.js';

// Functions we want to test
let extractIssueContextFromEvent: (context?: any) => IssueContext | null;
let hasAutomationTag: (issueContext: IssueContext, automationTag: string) => boolean;
let isEligibleForAutomation: (issueContext: IssueContext, automationTag: string) => boolean;

// Mock GitHub context
const createMockContext = (eventName: string, payload: any) => ({
  eventName,
  payload,
  repo: {
    owner: 'testOwner',
    repo: 'testRepo'
  }
});

// Test data
const mockIssueContext: IssueContext = {
  id: '123',
  source: 'github',
  title: 'Test Issue',
  body: 'This is a test issue body',
  labels: ['bug', 'AUTOFIX'],
  repository: {
    owner: 'testOwner',
    name: 'testRepo'
  },
  metadata: {
    htmlUrl: 'https://github.com/testOwner/testRepo/issues/123',
    user: 'testUser',
    state: 'open',
    createdAt: '2023-01-01T00:00:00Z',
    updatedAt: '2023-01-02T00:00:00Z'
  },
  url: 'https://github.com/testOwner/testRepo/issues/123'
};

// Import modules after defining mocks
import * as issuesModule from '../issues.js';

// Extract function references
extractIssueContextFromEvent = issuesModule.extractIssueContextFromEvent;
hasAutomationTag = issuesModule.hasAutomationTag;
isEligibleForAutomation = issuesModule.isEligibleForAutomation;

// Tests for extractIssueContextFromEvent
test('extractIssueContextFromEvent should return null for unsupported event types', () => {
  const context = createMockContext('push', {});
  
  const result = extractIssueContextFromEvent(context);
  
  expect(result).toBeNull();
});

test('extractIssueContextFromEvent should return null for non-labeled issues events', () => {
  const context = createMockContext('issues', { action: 'opened' });
  
  const result = extractIssueContextFromEvent(context);
  
  expect(result).toBeNull();
});

test('extractIssueContextFromEvent should extract context from labeled issue event', () => {
  const context = createMockContext('issues', { 
    action: 'labeled',
    label: { name: 'AUTOFIX' },
    issue: {
      number: 123,
      title: 'Test Issue',
      body: 'This is a test issue body',
      labels: [{ name: 'bug' }, { name: 'AUTOFIX' }],
      html_url: 'https://github.com/testOwner/testRepo/issues/123',
      user: { login: 'testUser' },
      state: 'open',
      created_at: '2023-01-01T00:00:00Z',
      updated_at: '2023-01-02T00:00:00Z'
    }
  });
  
  const result = extractIssueContextFromEvent(context);
  
  expect(result).not.toBeNull();
  expect(result?.id).toBe('123');
  expect(result?.source).toBe('github');
  expect(result?.title).toBe('Test Issue');
  expect(result?.labels).toContain('AUTOFIX');
  expect(result?.labels).toContain('bug');
});

test('extractIssueContextFromEvent should handle workflow_dispatch event with missing issue number', () => {
  const context = createMockContext('workflow_dispatch', { inputs: {} });
  
  const result = extractIssueContextFromEvent(context);
  
  expect(result).toBeNull();
});

// Tests for hasAutomationTag
test('hasAutomationTag should return true when the issue has the automation tag', () => {
  const result = hasAutomationTag(mockIssueContext, 'AUTOFIX');
  
  expect(result).toBe(true);
});

test('hasAutomationTag should return false when the issue does not have the automation tag', () => {
  const result = hasAutomationTag(mockIssueContext, 'DIFFERENT_TAG');
  
  expect(result).toBe(false);
});

// Tests for isEligibleForAutomation
test('isEligibleForAutomation should return true for eligible issues', () => {
  const result = isEligibleForAutomation(mockIssueContext, 'AUTOFIX');
  
  expect(result).toBe(true);
});

test('isEligibleForAutomation should return false when issue has no automation tag', () => {
  const context = { ...mockIssueContext, labels: ['bug'] };
  
  const result = isEligibleForAutomation(context, 'AUTOFIX');
  
  expect(result).toBe(false);
});

test('isEligibleForAutomation should return false when issue body is empty', () => {
  const context = { ...mockIssueContext, body: '' };
  
  const result = isEligibleForAutomation(context, 'AUTOFIX');
  
  expect(result).toBe(false);
});