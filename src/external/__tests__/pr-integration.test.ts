import { describe, it, expect, beforeEach, mock, afterEach } from 'bun:test';
import { RsolvApiClient } from '../api-client.js';

// Mock node-fetch
const mockFetch = mock();
mock.module('node-fetch', () => ({
  default: mockFetch
}));

// Mock the PR creation workflow integration
describe('PR Integration with Fix Attempt Recording', () => {
  let apiClient: RsolvApiClient;

  beforeEach(() => {
    mockFetch.mockClear();
    apiClient = new RsolvApiClient({
      baseUrl: 'https://api.rsolv.dev',
      apiKey: 'test-api-key'
    });
  });

  afterEach(() => {
    // Clean up any environment variables
    delete process.env.RSOLV_API_KEY;
    delete process.env.RSOLV_API_URL;
  });

  it('should record fix attempt after successful PR creation', async () => {
    // Mock successful API response
    const mockResponse = {
      ok: true,
      status: 201,
      json: mock().mockResolvedValue({
        id: 123,
        status: 'pending',
        github_org: 'test-org',
        repo_name: 'test-repo',
        pr_number: 456,
        billing_status: 'not_billed'
      })
    };
    
    mockFetch.mockResolvedValue(mockResponse);

    // Simulate PR data
    const issueContext = {
      number: 789,
      title: 'Fix security vulnerability',
      url: 'https://github.com/test-org/test-repo/issues/789',
      repository: {
        owner: 'test-org',
        name: 'test-repo'
      }
    };

    const prData = {
      number: 456,
      html_url: 'https://github.com/test-org/test-repo/pull/456',
      head: {
        ref: 'rsolv/789-fix-security'
      }
    };

    const prTitle = '[RSOLV] Fix security vulnerability (fixes #789)';

    // Record fix attempt
    const result = await apiClient.recordFixAttempt({
      github_org: issueContext.repository.owner,
      repo_name: issueContext.repository.name,
      issue_number: issueContext.number,
      pr_number: prData.number,
      pr_title: prTitle,
      pr_url: prData.html_url,
      issue_title: issueContext.title,
      issue_url: issueContext.url,
      api_key_used: 'test-api-key',
      metadata: {
        branch: prData.head.ref,
        labels: ['rsolv:automated'],
        created_by: 'rsolv-action'
      }
    });

    // Verify the API was called correctly
    expect(mockFetch).toHaveBeenCalledWith(
      'https://api.rsolv.dev/api/v1/fix-attempts',
      {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': 'Bearer test-api-key'
        },
        body: JSON.stringify({
          github_org: 'test-org',
          repo_name: 'test-repo',
          issue_number: 789,
          pr_number: 456,
          pr_title: '[RSOLV] Fix security vulnerability (fixes #789)',
          pr_url: 'https://github.com/test-org/test-repo/pull/456',
          issue_title: 'Fix security vulnerability',
          issue_url: 'https://github.com/test-org/test-repo/issues/789',
          api_key_used: 'test-api-key',
          metadata: {
            branch: 'rsolv/789-fix-security',
            labels: ['rsolv:automated'],
            created_by: 'rsolv-action'
          }
        })
      }
    );

    // Verify successful result
    expect(result.success).toBe(true);
    expect(result.data?.id).toBe(123);
    expect(result.data?.billing_status).toBe('not_billed');
  });

  it('should handle PR without issue reference', async () => {
    // Mock successful API response
    const mockResponse = {
      ok: true,
      status: 201,
      json: mock().mockResolvedValue({
        id: 124,
        status: 'pending',
        github_org: 'test-org',
        repo_name: 'test-repo',
        pr_number: 789
      })
    };
    
    mockFetch.mockResolvedValue(mockResponse);

    // Simulate PR without issue reference
    const prData = {
      number: 789,
      html_url: 'https://github.com/test-org/test-repo/pull/789',
      head: {
        ref: 'rsolv/performance-improvements'
      }
    };

    const prTitle = '[RSOLV] Performance improvements';

    // Record fix attempt
    const result = await apiClient.recordFixAttempt({
      github_org: 'test-org',
      repo_name: 'test-repo',
      pr_number: prData.number,
      pr_title: prTitle,
      pr_url: prData.html_url,
      api_key_used: 'test-api-key',
      metadata: {
        branch: prData.head.ref,
        labels: ['rsolv:automated'],
        created_by: 'rsolv-action'
      }
    });

    // Verify the API was called without issue fields
    expect(mockFetch).toHaveBeenCalledWith(
      'https://api.rsolv.dev/api/v1/fix-attempts',
      expect.objectContaining({
        body: expect.stringContaining('"pr_number":789')
      })
    );

    // Should not contain issue fields
    const requestBody = JSON.parse(mockFetch.mock.calls[0][1].body);
    expect(requestBody.issue_number).toBeUndefined();
    expect(requestBody.issue_title).toBeUndefined();
    expect(requestBody.issue_url).toBeUndefined();

    // Verify successful result
    expect(result.success).toBe(true);
    expect(result.data?.id).toBe(124);
  });

  it('should handle API errors gracefully without failing PR creation', async () => {
    // Mock API error response
    const mockResponse = {
      ok: false,
      status: 422,
      json: mock().mockResolvedValue({
        errors: {
          repo_name: ['can\'t be blank']
        }
      })
    };
    
    mockFetch.mockResolvedValue(mockResponse);

    // Record fix attempt
    const result = await apiClient.recordFixAttempt({
      github_org: 'test-org',
      repo_name: '',  // Invalid data
      pr_number: 456,
      pr_title: '[RSOLV] Test fix',
      pr_url: 'https://github.com/test-org/test-repo/pull/456',
      api_key_used: 'test-api-key',
      metadata: {
        labels: ['rsolv:automated'],
        created_by: 'rsolv-action'
      }
    });

    // Verify error is handled gracefully
    expect(result.success).toBe(false);
    expect(result.error).toContain('API Error: 422');
    
    // This confirms that API errors won't break PR creation
    // In the actual implementation, this error is logged but doesn't throw
  });

  it('should handle network errors gracefully', async () => {
    // Mock network error
    mockFetch.mockRejectedValue(new Error('Connection timeout'));

    // Record fix attempt
    const result = await apiClient.recordFixAttempt({
      github_org: 'test-org',
      repo_name: 'test-repo',
      pr_number: 456,
      pr_title: '[RSOLV] Test fix',
      pr_url: 'https://github.com/test-org/test-repo/pull/456',
      api_key_used: 'test-api-key',
      metadata: {
        labels: ['rsolv:automated'],
        created_by: 'rsolv-action'
      }
    });

    // Verify network error is handled gracefully
    expect(result.success).toBe(false);
    expect(result.error).toBe('Connection timeout');
    
    // This confirms that network issues won't break PR creation
  });

  it('should use environment variables for configuration', async () => {
    // Set environment variables
    process.env.RSOLV_API_URL = 'https://staging-api.rsolv.dev';
    process.env.RSOLV_API_KEY = 'staging-key';

    // Create client with env vars
    const envClient = new RsolvApiClient({
      baseUrl: process.env.RSOLV_API_URL,
      apiKey: process.env.RSOLV_API_KEY
    });

    // Mock successful response
    const mockResponse = {
      ok: true,
      status: 201,
      json: mock().mockResolvedValue({ id: 999 })
    };
    
    mockFetch.mockResolvedValue(mockResponse);

    // Make request
    await envClient.recordFixAttempt({
      github_org: 'test-org',
      repo_name: 'test-repo',
      pr_number: 123,
      pr_title: '[RSOLV] Test',
      pr_url: 'https://github.com/test-org/test-repo/pull/123',
      api_key_used: 'staging-key',
      metadata: {}
    });

    // Verify correct URL and auth header
    expect(mockFetch).toHaveBeenCalledWith(
      'https://staging-api.rsolv.dev/api/v1/fix-attempts',
      expect.objectContaining({
        headers: expect.objectContaining({
          'Authorization': 'Bearer staging-key'
        })
      })
    );
  });
});