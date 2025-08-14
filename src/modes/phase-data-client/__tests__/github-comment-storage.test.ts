import { describe, test, expect, beforeEach, mock } from 'bun:test';
import { PhaseDataClient } from '../index';

describe('PhaseDataClient GitHub Comment Storage', () => {
  let client: PhaseDataClient;
  let mockCreateIssueComment: any;
  let mockGetGitHubClient: any;
  
  beforeEach(() => {
    // Reset mocks
    mockCreateIssueComment = mock();
    mockGetGitHubClient = mock();
    
    // Set GITHUB_TOKEN for tests
    process.env.GITHUB_TOKEN = 'test-token';
    
    // Create client
    client = new PhaseDataClient('test-api-key');
  });
  
  describe('storePhaseResults', () => {
    test('should store validation data in GitHub comment', async () => {
      // Arrange
      const validationData = {
        validation: {
          'issue-123': {
            validated: true,
            vulnerabilities: [],
            hasSpecificVulnerabilities: false,
            confidence: 'none' as const,
            timestamp: '2025-08-14T12:00:00.000Z'
          }
        }
      };
      
      const metadata = {
        repo: 'owner/repo',
        issueNumber: 123,
        commitSha: 'abc123'
      };
      
      // Mock the GitHub API
      mock.module('../../github/api.js', () => ({
        createIssueComment: mockCreateIssueComment.mockResolvedValue(undefined)
      }));
      
      // Act
      const result = await client.storePhaseResults('validate', validationData, metadata);
      
      // Assert
      expect(result.success).toBe(true);
      expect(result.storage).toBe('platform');
      expect(mockCreateIssueComment).toHaveBeenCalledWith(
        'owner',
        'repo',
        123,
        expect.stringContaining('RSOLV_PHASE_DATA:validate:abc123')
      );
    });
  });
  
  describe('retrievePhaseResults', () => {
    test('should retrieve validation data from GitHub comments', async () => {
      // Arrange
      const expectedData = {
        validation: {
          'issue-123': {
            validated: true,
            vulnerabilities: [],
            hasSpecificVulnerabilities: false,
            confidence: 'none',
            timestamp: '2025-08-14T12:00:00.000Z'
          }
        }
      };
      
      const mockComments = [
        {
          body: `<!-- RSOLV_PHASE_DATA:validate:abc123
${JSON.stringify({ phase: 'validate', data: expectedData })}
-->
Phase data stored for validate phase`
        }
      ];
      
      // Mock the GitHub API
      mock.module('../../github/api.js', () => ({
        getGitHubClient: () => ({
          rest: {
            issues: {
              listComments: mockGetGitHubClient.mockResolvedValue({ data: mockComments })
            }
          }
        })
      }));
      
      // Act
      const result = await client.retrievePhaseResults('owner/repo', 123, 'abc123');
      
      // Assert
      expect(result).toEqual(expectedData);
    });
    
    test('should return null when no matching phase data found', async () => {
      // Arrange
      const mockComments = [
        {
          body: 'Regular comment without phase data'
        }
      ];
      
      // Mock the GitHub API
      mock.module('../../github/api.js', () => ({
        getGitHubClient: () => ({
          rest: {
            issues: {
              listComments: mockGetGitHubClient.mockResolvedValue({ data: mockComments })
            }
          }
        })
      }));
      
      // Act
      const result = await client.retrievePhaseResults('owner/repo', 123, 'xyz789');
      
      // Assert
      expect(result).toBeNull();
    });
  });
});