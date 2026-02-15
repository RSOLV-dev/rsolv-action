import { describe, it, expect, vi, beforeEach } from 'vitest';
import { IssueCreator } from '../issue-creator.js';
import type { ForgeAdapter } from '../../forge/forge-adapter.js';

vi.mock('../../utils/logger.js', () => ({
  logger: {
    info: vi.fn(),
    warn: vi.fn(),
    error: vi.fn(),
    debug: vi.fn(),
  }
}));

function createMockForgeAdapter(): ForgeAdapter {
  return {
    listIssues: vi.fn().mockResolvedValue([]),
    createIssue: vi.fn().mockResolvedValue({ number: 1, title: 'test', url: 'https://github.com/test/repo/issues/1', labels: [], state: 'open' }),
    updateIssue: vi.fn().mockResolvedValue(undefined),
    addLabels: vi.fn().mockResolvedValue(undefined),
    createComment: vi.fn().mockResolvedValue(undefined),
    getFileContent: vi.fn().mockResolvedValue(''),
    listTree: vi.fn().mockResolvedValue([]),
    createPullRequest: vi.fn().mockResolvedValue({ number: 1, title: 'test', url: '', state: 'open', labels: [] }),
    createBranch: vi.fn().mockResolvedValue(undefined),
    getDefaultBranch: vi.fn().mockResolvedValue('main'),
  } as ForgeAdapter;
}

describe('Dismissal Labels', () => {
  let issueCreator: IssueCreator;

  beforeEach(() => {
    issueCreator = new IssueCreator(createMockForgeAdapter());
  });

  // Access private checkSkipStatus via bracket notation
  function checkSkipStatus(labels: string[]): string | null {
    return (issueCreator as Record<string, unknown>)['checkSkipStatus'].call(issueCreator, labels) as string | null;
  }

  it('should return skip:validated for rsolv:validated label', () => {
    expect(checkSkipStatus(['rsolv:validated'])).toBe('skip:validated');
  });

  it('should return skip:false-positive for rsolv:false-positive label', () => {
    expect(checkSkipStatus(['rsolv:false-positive'])).toBe('skip:false-positive');
  });

  it('should return skip:dismissed for rsolv:wont-fix label', () => {
    expect(checkSkipStatus(['rsolv:wont-fix'])).toBe('skip:dismissed');
  });

  it('should return skip:dismissed for rsolv:accepted-risk label', () => {
    expect(checkSkipStatus(['rsolv:accepted-risk'])).toBe('skip:dismissed');
  });

  it('should return skip:dismissed for rsolv:deferred label', () => {
    expect(checkSkipStatus(['rsolv:deferred'])).toBe('skip:dismissed');
  });

  it('should return null for unrelated labels', () => {
    expect(checkSkipStatus(['bug', 'enhancement'])).toBeNull();
  });

  it('should return null for empty labels', () => {
    expect(checkSkipStatus([])).toBeNull();
  });

  it('should prioritize validated over dismissed', () => {
    // If both validated and wont-fix are present, validated takes precedence
    expect(checkSkipStatus(['rsolv:validated', 'rsolv:wont-fix'])).toBe('skip:validated');
  });

  it('should prioritize false-positive over dismissed', () => {
    expect(checkSkipStatus(['rsolv:false-positive', 'rsolv:deferred'])).toBe('skip:false-positive');
  });
});
