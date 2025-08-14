import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { PhaseExecutor } from '../index.js';
import { ActionConfig } from '../../../types/index.js';
import * as fs from 'fs/promises';

describe('PhaseExecutor - Mitigate with Auto-Validation Flow', () => {
  let executor: PhaseExecutor;
  let mockConfig: ActionConfig;
  const testDir = '.rsolv/phase-data';
  
  beforeEach(async () => {
    // Clean up test directory
    try {
      await fs.rm(testDir, { recursive: true, force: true });
    } catch (e) {
      // Directory might not exist
    }
    await fs.mkdir(testDir, { recursive: true });
    
    mockConfig = {
      apiKey: 'test-api-key',
      rsolvApiKey: 'rsolv_test_key',
      aiProvider: {
        provider: 'claude-code',
        model: 'test-model',
        useVendedCredentials: false,
        temperature: 0.2,
        maxTokens: 4000,
        contextLimit: 100000,
        timeout: 3600000
      },
      repository: {
        owner: 'test-owner',
        name: 'test-repo'
      },
      createIssues: false,
      useGitBasedEditing: true,
      enableSecurityAnalysis: true
    } as ActionConfig;
    
    executor = new PhaseExecutor(mockConfig);
    
    // Mock GitHub API
    const githubApi = await import('../../../github/api.js');
    vi.spyOn(githubApi, 'getIssue').mockResolvedValue({
      id: 'issue-1',
      number: 789,
      title: 'Security Issue',
      body: '## Vulnerabilities\n- XSS in file.js',
      labels: ['rsolv:automate'], // Has automate but not validated
      repository: {
        owner: 'test-owner',
        name: 'test-repo',
        fullName: 'test-owner/test-repo'
      }
    });
    vi.spyOn(githubApi, 'updateIssueLabels').mockResolvedValue(undefined);
    vi.spyOn(githubApi, 'createIssueComment').mockResolvedValue(undefined);
    
    // Mock validation enricher
    const enricherModule = await import('../../../validation/enricher.js');
    vi.spyOn(enricherModule.ValidationEnricher.prototype, 'enrichIssue').mockResolvedValue({
      issueNumber: 789,
      originalIssue: {} as any,
      validationTimestamp: new Date(),
      vulnerabilities: [
        { 
          file: 'test.js', 
          line: 10, 
          type: 'XSS',
          confidence: 'high',
          description: 'Cross-site scripting'
        }
      ],
      enriched: true,
      labelAdded: true
    });
  });
  
  afterEach(async () => {
    vi.clearAllMocks();
    try {
      await fs.rm(testDir, { recursive: true, force: true });
    } catch (e) {
      // Ignore cleanup errors
    }
  });
  
  it('should run validation and then proceed with mitigation when rsolv:automate is present', async () => {
    // Mock processIssues to verify it gets called with right data
    const processIssuesModule = await import('../../../ai/unified-processor.js');
    const mockProcessIssues = vi.fn().mockResolvedValue([{
      issueId: 'issue-1',
      success: true,
      pullRequestUrl: 'https://github.com/test/repo/pull/1'
    }]);
    vi.spyOn(processIssuesModule, 'processIssues').mockImplementation(mockProcessIssues);
    
    // Execute mitigate - should auto-run validation first
    const result = await executor.executeMitigate({
      repository: {
        owner: 'test-owner',
        name: 'test-repo',
        defaultBranch: 'main'
      },
      issueNumber: 789
    });
    
    // Should succeed
    expect(result.success).toBe(true);
    expect(result.phase).toBe('mitigate');
    
    // processIssues should have been called
    expect(mockProcessIssues).toHaveBeenCalled();
    
    // Check the issue passed to processIssues has validation data
    const [issues, config] = mockProcessIssues.mock.calls[0];
    expect(issues).toHaveLength(1);
    expect(issues[0].validationData).toBeDefined();
    expect(issues[0].specificVulnerabilities).toHaveLength(1);
  });
  
  it('should fail gracefully when validation finds no vulnerabilities', async () => {
    // Mock enricher to return no vulnerabilities
    const enricherModule = await import('../../../validation/enricher.js');
    vi.spyOn(enricherModule.ValidationEnricher.prototype, 'enrichIssue').mockResolvedValue({
      issueNumber: 789,
      originalIssue: {} as any,
      validationTimestamp: new Date(),
      vulnerabilities: [], // No vulnerabilities found
      enriched: true,
      labelAdded: true
    });
    
    const result = await executor.executeMitigate({
      repository: {
        owner: 'test-owner',
        name: 'test-repo',
        defaultBranch: 'main'
      },
      issueNumber: 789
    });
    
    // Should fail with false positive message
    expect(result.success).toBe(false);
    expect(result.error).toContain('No specific vulnerabilities found');
    expect(result.data?.falsePositive).toBe(true);
  });
});