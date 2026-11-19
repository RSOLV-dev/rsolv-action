import { describe, it, expect, vi, beforeEach } from 'vitest';
import { renderStaticHint } from '../../scanner/static-hint.js';

const { issuesGet } = vi.hoisted(() => ({ issuesGet: vi.fn() }));

vi.mock('@octokit/rest', () => ({
  Octokit: vi.fn().mockImplementation(function () {
    return { issues: { get: issuesGet } };
  })
}));

describe('getIssue', () => {
  beforeEach(() => {
    vi.stubEnv('GITHUB_TOKEN', 'test-token');
    issuesGet.mockResolvedValue({
      data: {
        id: 1,
        number: 7,
        title: 'CWE-89: SQL injection',
        body: ['### Description', 'User input reaches SQL.', renderStaticHint('it is parameterized'), '### Code'].join('\n'),
        labels: [],
        assignees: [],
        created_at: '2026-11-18T00:00:00Z',
        updated_at: '2026-11-18T00:00:00Z'
      }
    });
  });

  describe('when the issue body carries a static hint', () => {
    it('hands every consumer the body without it', async () => {
      const { getIssue } = await import('../api.js');

      const issue = await getIssue('o', 'r', 7);

      expect(issue.body).toBe(['### Description', 'User input reaches SQL.', '### Code'].join('\n'));
    });
  });
});
