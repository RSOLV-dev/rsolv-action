import { describe, it, expect, beforeEach, mock } from 'bun:test';
import { RsolvApiClient } from '../api-client.js';

// Mock node-fetch
const mockFetch = mock();
mock.module('node-fetch', () => ({
  default: mockFetch
}));

describe('RsolvApiClient', () => {
  let client: RsolvApiClient;
  
  beforeEach(() => {
    mockFetch.mockClear();
    client = new RsolvApiClient({
      baseUrl: 'https://api.rsolv.dev',
      apiKey: 'test-key'
    });
  });

  describe('recordFixAttempt', () => {
    it('should successfully record a fix attempt', async () => {
      const mockResponse = {
        ok: true,
        status: 201,
        json: mock().mockResolvedValue({
          id: 123,
          status: 'pending',
          github_org: 'test-org',
          repo_name: 'test-repo',
          pr_number: 456
        })
      };
      
      mockFetch.mockResolvedValue(mockResponse);
      
      const fixAttempt = {
        github_org: 'test-org',
        repo_name: 'test-repo',
        issue_number: 789,
        pr_number: 456,
        pr_title: '[RSOLV] Fix authentication vulnerability',
        pr_url: 'https://github.com/test-org/test-repo/pull/456',
        issue_title: 'Security vulnerability in login',
        issue_url: 'https://github.com/test-org/test-repo/issues/789',
        api_key_used: 'test-key',
        metadata: {
          branch: 'rsolv/789-fix-auth',
          labels: ['rsolv:automated', 'security'],
          created_by: 'rsolv-action'
        }
      };
      
      const result = await client.recordFixAttempt(fixAttempt);
      
      expect(mockFetch).toHaveBeenCalledWith(
        'https://api.rsolv.dev/api/v1/fix-attempts',
        {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'Authorization': 'Bearer test-key'
          },
          body: JSON.stringify(fixAttempt)
        }
      );
      
      expect(result).toEqual({
        success: true,
        data: {
          id: 123,
          status: 'pending',
          github_org: 'test-org',
          repo_name: 'test-repo',
          pr_number: 456
        }
      });
    });
    
    it('should handle PR without issue reference', async () => {
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
      
      const fixAttempt = {
        github_org: 'test-org',
        repo_name: 'test-repo',
        pr_number: 789,
        pr_title: '[RSOLV] Performance improvements',
        pr_url: 'https://github.com/test-org/test-repo/pull/789',
        api_key_used: 'test-key',
        metadata: {
          branch: 'rsolv/perf-improvements',
          labels: ['rsolv:automated', 'performance'],
          created_by: 'rsolv-action'
        }
      };
      
      const result = await client.recordFixAttempt(fixAttempt);
      
      expect(result.success).toBe(true);
      expect(result.data?.id).toBe(124);
    });
    
    it('should handle API errors gracefully', async () => {
      const mockResponse = {
        ok: false,
        status: 422,
        json: mock().mockResolvedValue({
          errors: {
            repo_name: ["can't be blank"],
            pr_number: ["can't be blank"]
          }
        })
      };
      
      mockFetch.mockResolvedValue(mockResponse);
      
      const fixAttempt = {
        github_org: 'test-org',
        // Missing required fields
      };
      
      const result = await client.recordFixAttempt(fixAttempt as any);
      
      expect(result).toEqual({
        success: false,
        error: 'API Error: 422 - {"errors":{"repo_name":["can\'t be blank"],"pr_number":["can\'t be blank"]}}'
      });
    });
    
    it('should handle network errors', async () => {
      mockFetch.mockRejectedValue(new Error('Network error'));
      
      const fixAttempt = {
        github_org: 'test-org',
        repo_name: 'test-repo',
        pr_number: 456
      };
      
      const result = await client.recordFixAttempt(fixAttempt as any);
      
      expect(result).toEqual({
        success: false,
        error: 'Network error'
      });
    });
    
    it('should handle duplicate fix attempts', async () => {
      const mockResponse = {
        ok: false,
        status: 409,
        json: mock().mockResolvedValue({
          error: 'Fix attempt already exists for this PR'
        })
      };
      
      mockFetch.mockResolvedValue(mockResponse);
      
      const fixAttempt = {
        github_org: 'test-org',
        repo_name: 'test-repo',
        pr_number: 456
      };
      
      const result = await client.recordFixAttempt(fixAttempt as any);
      
      expect(result).toEqual({
        success: false,
        error: 'API Error: 409 - {"error":"Fix attempt already exists for this PR"}'
      });
    });
  });
});