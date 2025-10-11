import { describe, it, expect } from 'vitest';
import type { IssueContext } from '../../types/index.js';

/**
 * Documents that IssueContext uses 'number', not 'issueNumber'
 * Prevents regression where code might try to access issue.issueNumber
 */
describe('IssueContext.number property', () => {
  const mockIssue: IssueContext = {
    id: 'github-123',
    number: 851,
    title: 'Test Issue',
    body: 'Test body',
    labels: ['rsolv:detected'],
    assignees: [],
    repository: {
      owner: 'test-owner',
      name: 'test-repo',
      fullName: 'test-owner/test-repo',
      defaultBranch: 'main',
      language: 'javascript'
    },
    source: 'github',
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
    metadata: {
      htmlUrl: 'https://github.com/test-owner/test-repo/issues/851',
      state: 'open',
      locked: false
    }
  };

  it('has number property, not issueNumber', () => {
    expect(mockIssue.number).toBe(851);
    // @ts-expect-error - issueNumber does not exist on IssueContext
    expect(mockIssue.issueNumber).toBeUndefined();
  });

  it('works in result objects', () => {
    const result = { issueId: mockIssue.number };
    expect(result.issueId).toBe(851);
  });

  it('works in string templates', () => {
    expect(`Issue #${mockIssue.number}`).toBe('Issue #851');
  });
});