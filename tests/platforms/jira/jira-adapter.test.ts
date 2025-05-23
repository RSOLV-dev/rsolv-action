import { describe, it, expect, beforeEach, vi, Mock } from 'vitest';
import { JiraAdapter } from '../../../src/platforms/jira/jira-adapter';
import type { PlatformConfig, UnifiedIssue } from '../../../src/platforms/types';

// Mock fetch globally
global.fetch = vi.fn() as Mock;

describe('JiraAdapter', () => {
  let adapter: JiraAdapter;
  const mockConfig: PlatformConfig = {
    jira: {
      host: 'test.atlassian.net',
      email: 'test@example.com',
      apiToken: 'test-token',
      autofixLabel: 'autofix'
    }
  };

  beforeEach(() => {
    vi.clearAllMocks();
    adapter = new JiraAdapter(mockConfig.jira!);
  });

  describe('authenticate', () => {
    it('should authenticate successfully with valid credentials', async () => {
      const mockFetch = fetch as Mock;
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => ({ accountId: '123', emailAddress: 'test@example.com' })
      } as Response);

      await adapter.authenticate();

      expect(mockFetch).toHaveBeenCalledWith(
        'https://test.atlassian.net/rest/api/3/myself',
        {
          headers: {
            'Authorization': `Basic ${Buffer.from('test@example.com:test-token').toString('base64')}`,
            'Accept': 'application/json'
          }
        }
      );
    });

    it('should throw error on authentication failure', async () => {
      const mockFetch = fetch as Mock;
      mockFetch.mockResolvedValueOnce({
        ok: false,
        status: 401,
        statusText: 'Unauthorized'
      } as Response);

      await expect(adapter.authenticate()).rejects.toThrow('Failed to authenticate with Jira: 401 Unauthorized');
    });
  });

  describe('searchIssues', () => {
    it('should search issues with autofix label', async () => {
      const mockFetch = fetch as Mock;
      const mockJiraIssues = {
        issues: [
          {
            id: '10001',
            key: 'PROJ-123',
            fields: {
              summary: 'Fix deprecated API usage',
              description: 'Need to update deprecated API calls',
              labels: ['autofix', 'technical-debt'],
              status: { name: 'To Do' },
              created: '2025-05-23T10:00:00.000Z',
              updated: '2025-05-23T12:00:00.000Z',
              assignee: {
                accountId: '456',
                displayName: 'John Doe',
                emailAddress: 'john@example.com'
              },
              reporter: {
                accountId: '789',
                displayName: 'Jane Smith',
                emailAddress: 'jane@example.com'
              }
            }
          }
        ]
      };

      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => mockJiraIssues
      } as Response);

      const issues = await adapter.searchIssues('labels = "autofix"');

      expect(mockFetch).toHaveBeenCalledWith(
        'https://test.atlassian.net/rest/api/3/search',
        {
          method: 'POST',
          headers: {
            'Authorization': `Basic ${Buffer.from('test@example.com:test-token').toString('base64')}`,
            'Accept': 'application/json',
            'Content-Type': 'application/json'
          },
          body: JSON.stringify({
            jql: 'labels = "autofix"',
            fields: ['summary', 'description', 'labels', 'status', 'created', 'updated', 'assignee', 'reporter']
          })
        }
      );

      expect(issues).toHaveLength(1);
      const issue = issues[0];
      expect(issue).toMatchObject({
        id: '10001',
        platform: 'jira',
        key: 'PROJ-123',
        title: 'Fix deprecated API usage',
        description: 'Need to update deprecated API calls',
        labels: ['autofix', 'technical-debt'],
        status: 'To Do',
        url: 'https://test.atlassian.net/browse/PROJ-123'
      });
    });

    it('should handle empty search results', async () => {
      const mockFetch = fetch as Mock;
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => ({ issues: [] })
      } as Response);

      const issues = await adapter.searchIssues('labels = "autofix"');
      expect(issues).toHaveLength(0);
    });
  });

  describe('addComment', () => {
    it('should add comment to issue', async () => {
      const mockFetch = fetch as Mock;
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => ({ id: '123' })
      } as Response);

      await adapter.addComment('PROJ-123', 'RSOLV has created a pull request for this issue');

      expect(mockFetch).toHaveBeenCalledWith(
        'https://test.atlassian.net/rest/api/3/issue/PROJ-123/comment',
        {
          method: 'POST',
          headers: {
            'Authorization': `Basic ${Buffer.from('test@example.com:test-token').toString('base64')}`,
            'Accept': 'application/json',
            'Content-Type': 'application/json'
          },
          body: JSON.stringify({
            body: {
              type: 'doc',
              version: 1,
              content: [
                {
                  type: 'paragraph',
                  content: [
                    {
                      type: 'text',
                      text: 'RSOLV has created a pull request for this issue'
                    }
                  ]
                }
              ]
            }
          })
        }
      );
    });
  });

  describe('linkExternalResource', () => {
    it('should create remote link to GitHub PR', async () => {
      const mockFetch = fetch as Mock;
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => ({ id: '456' })
      } as Response);

      await adapter.linkExternalResource(
        'PROJ-123',
        'https://github.com/owner/repo/pull/42',
        'Fix: Update deprecated API calls'
      );

      expect(mockFetch).toHaveBeenCalledWith(
        'https://test.atlassian.net/rest/api/3/issue/PROJ-123/remotelink',
        {
          method: 'POST',
          headers: {
            'Authorization': `Basic ${Buffer.from('test@example.com:test-token').toString('base64')}`,
            'Accept': 'application/json',
            'Content-Type': 'application/json'
          },
          body: JSON.stringify({
            object: {
              url: 'https://github.com/owner/repo/pull/42',
              title: 'Fix: Update deprecated API calls',
              icon: {
                url16x16: 'https://github.com/favicon.ico',
                title: 'GitHub Pull Request'
              }
            }
          })
        }
      );
    });
  });

  describe('updateStatus', () => {
    it('should update issue status', async () => {
      // First, get available transitions
      const mockFetch = fetch as Mock;
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => ({
          transitions: [
            { id: '21', name: 'In Progress' },
            { id: '31', name: 'Done' }
          ]
        })
      } as Response);

      // Then update status
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => ({})
      } as Response);

      await adapter.updateStatus('PROJ-123', 'In Progress');

      // Verify getting transitions
      expect(mockFetch).toHaveBeenNthCalledWith(
        1,
        'https://test.atlassian.net/rest/api/3/issue/PROJ-123/transitions',
        expect.objectContaining({
          headers: expect.objectContaining({
            'Authorization': `Basic ${Buffer.from('test@example.com:test-token').toString('base64')}`
          })
        })
      );

      // Verify updating status
      expect(mockFetch).toHaveBeenNthCalledWith(
        2,
        'https://test.atlassian.net/rest/api/3/issue/PROJ-123/transitions',
        expect.objectContaining({
          method: 'POST',
          body: JSON.stringify({
            transition: { id: '21' }
          })
        })
      );
    });
  });
});