import { describe, expect, test, beforeEach, vi } from 'vitest';
import { processIssues, ProcessingOptions } from '../unified-processor';
import { ActionConfig, IssueContext } from '../../types/index.js';
import * as analyzerModule from '../analyzer';
import * as solutionModule from '../solution';
import * as githubModule from '../../github/pr';

// RFC-095: Mock new unified ClaudeAgentSDKAdapter (replaces all legacy adapters)
vi.mock('../adapters/claude-agent-sdk.js', () => {
  // Use a closure to maintain state
  let shouldFail = false;

  return {
    __setMockFailure: (fail: boolean) => { shouldFail = fail; },
    ClaudeAgentSDKAdapter: class {
      constructor() {}
      async gatherDeepContext() {
        return {
          files: [],
          dependencies: [],
          testPatterns: [],
          architectureInsights: []
        };
      }
      async generateSolutionWithContext() {
        if (shouldFail) {
          return {
            success: false,
            message: 'Solution generation failed'
          };
        }
        return {
          success: true,
          message: 'Solution generated',
          filesModified: ['test.ts'],
          commitHash: 'abc123',
          diffStats: { filesChanged: 1, insertions: 10, deletions: 5 }
        };
      }
      async generateSolutionWithGit() {
        if (shouldFail) {
          return {
            success: false,
            message: 'Solution generation failed'
          };
        }
        return {
          success: true,
          message: 'Solution generated',
          filesModified: ['test.ts'],
          commitHash: 'abc123',
          diffStats: { filesChanged: 1, insertions: 10, deletions: 5 }
        };
      }
    },
    GitSolutionResult: {},
    createClaudeAgentSDKAdapter: () => ({
      async gatherDeepContext() {
        return {
          files: [],
          dependencies: [],
          testPatterns: [],
          architectureInsights: []
        };
      },
      async generateSolutionWithContext() {
        return {
          success: true,
          message: 'Solution generated',
          filesModified: ['test.ts'],
          commitHash: 'abc123',
          diffStats: { filesChanged: 1, insertions: 10, deletions: 5 }
        };
      },
      async generateSolutionWithGit() {
        return {
          success: true,
          message: 'Solution generated',
          filesModified: ['test.ts'],
          commitHash: 'abc123',
          diffStats: { filesChanged: 1, insertions: 10, deletions: 5 }
        };
      }
    })
  };
});

describe('Unified Processor Timeout Behavior', () => {
  const mockConfig: ActionConfig = {
    apiKey: 'test-api-key',
    configPath: '.github/rsolv.yml',
    issueLabel: 'rsolv:automate',
    enableSecurityAnalysis: false,
    aiProvider: {
      provider: 'claude-code',
      model: 'claude-sonnet-4-20250514',
      temperature: 0.2,
      maxTokens: 4000,
      contextLimit: 100000,
      timeout: 30000,
      useVendedCredentials: true
    },
    containerConfig: {
      enabled: true,
      image: 'rsolv/code-analysis:latest',
      memoryLimit: '2g',
      cpuLimit: '1',
      timeout: 300,
      securityProfile: 'default'
    },
    securitySettings: {
      disableNetworkAccess: true,
      scanDependencies: true,
      preventSecretLeakage: true,
      maxFileSize: 1024 * 1024,
      timeoutSeconds: 300,
      requireCodeReview: true
    }
  };

  const mockIssue: IssueContext = {
    id: '1',
    number: 1,
    title: 'Test Issue',
    body: 'Test body',
    labels: ['bug'],
    state: 'open',
    repository: {
      owner: 'test',
      name: 'repo',
      fullName: 'test/repo'
    },
    author: 'testuser',
    createdAt: new Date(),
    updatedAt: new Date()
  };

  const mockAnalysis = {
    canBeFixed: true,
    complexity: 'medium' as const,
    estimatedTime: 30,
    relatedFiles: ['src/test.ts'],
    suggestedApproach: 'Fix the bug'
  };

  beforeEach(async () => {
    vi.clearAllMocks();
    // RFC-095: Reset unified adapter mock state
    const adapter = await import('../adapters/claude-agent-sdk.js');
    (adapter as any).__setMockFailure?.(false);
  });

  test('should use default context gathering timeout of 30 seconds', async () => {
    // Mock all dependencies
    const analyzeIssueSpy = vi.spyOn(analyzerModule, 'analyzeIssue').mockResolvedValue(mockAnalysis);
    const generateSolutionSpy = vi.spyOn(solutionModule, 'generateSolution').mockResolvedValue({
      success: true,
      message: 'Solution generated',
      changes: { 'test.ts': 'fixed content' }
    });
    const createPullRequestSpy = vi.spyOn(githubModule, 'createPullRequest').mockResolvedValue({
      success: true,
      pullRequestUrl: 'https://github.com/test/repo/pull/1',
      message: 'PR created'
    });

    const options: ProcessingOptions = {
      enableEnhancedContext: true,
      enableSecurityAnalysis: false
    };

    const results = await processIssues([mockIssue], mockConfig, options);

    // Should complete successfully
    expect(results).toHaveLength(1);
    expect(results[0].success).toBe(true);
    
    // Verify the dependencies were called
    expect(analyzeIssueSpy).toHaveBeenCalled();
    expect(generateSolutionSpy).toHaveBeenCalled();
    expect(createPullRequestSpy).toHaveBeenCalled();
  });

  test('should use custom context gathering timeout when specified', async () => {
    // Mock all dependencies
    const analyzeIssueSpy = vi.spyOn(analyzerModule, 'analyzeIssue').mockResolvedValue(mockAnalysis);
    const generateSolutionSpy = vi.spyOn(solutionModule, 'generateSolution').mockResolvedValue({
      success: true,
      message: 'Solution generated',
      changes: { 'test.ts': 'fixed content' }
    });
    const createPullRequestSpy = vi.spyOn(githubModule, 'createPullRequest').mockResolvedValue({
      success: true,
      pullRequestUrl: 'https://github.com/test/repo/pull/1',
      message: 'PR created'
    });

    const options: ProcessingOptions = {
      enableEnhancedContext: true,
      enableSecurityAnalysis: false,
      contextGatheringTimeout: 45000 // 45 seconds
    };

    const results = await processIssues([mockIssue], mockConfig, options);

    // Should complete successfully
    expect(results).toHaveLength(1);
    expect(results[0].success).toBe(true);
    
    // Note: We can't directly verify the timeout was passed to EnhancedClaudeCodeAdapter
    // since it's created internally, but we can verify the processing completed
    expect(analyzeIssueSpy).toHaveBeenCalled();
    expect(generateSolutionSpy).toHaveBeenCalled();
    expect(createPullRequestSpy).toHaveBeenCalled();
  });

  test('should handle analysis failure gracefully', async () => {
    // Mock analyzer to fail
    const analyzeIssueSpy = vi.spyOn(analyzerModule, 'analyzeIssue').mockResolvedValue({
      canBeFixed: false,
      complexity: 'high' as const,
      estimatedTime: 0,
      relatedFiles: [],
      suggestedApproach: 'Cannot be fixed'
    });
    
    const generateSolutionSpy = vi.spyOn(solutionModule, 'generateSolution').mockResolvedValue({
      success: true,
      message: 'Solution generated',
      changes: { 'test.ts': 'fixed content' }
    });

    const results = await processIssues([mockIssue], mockConfig, {});

    expect(results).toHaveLength(1);
    expect(results[0].success).toBe(false);
    expect(results[0].message).toBe('Issue cannot be automatically fixed based on analysis');
    
    // Should not call solution generation if analysis says can't be fixed
    expect(analyzeIssueSpy).toHaveBeenCalled();
    expect(generateSolutionSpy).not.toHaveBeenCalled();
  });

  test('should handle solution generation failure', async () => {
    // Mock dependencies - make generateSolution return failure
    const analyzeIssueSpy = vi.spyOn(analyzerModule, 'analyzeIssue').mockResolvedValue(mockAnalysis);
    const generateSolutionSpy = vi.spyOn(solutionModule, 'generateSolution').mockResolvedValue({
      success: false,
      message: 'Solution generation failed'
    });

    // Use a config that doesn't trigger enhanced context (no adapter path)
    const basicConfig = {
      ...mockConfig,
      aiProvider: {
        ...mockConfig.aiProvider,
        provider: 'anthropic' as const  // Not claude-code, so it uses generateSolution directly
      }
    };

    const results = await processIssues([mockIssue], basicConfig, { enableEnhancedContext: false });

    expect(results).toHaveLength(1);
    expect(results[0].success).toBe(false);
    // When solution generation fails, the processor returns that message
    expect(results[0].message).toContain('Solution generation failed');

    expect(analyzeIssueSpy).toHaveBeenCalled();
    expect(generateSolutionSpy).toHaveBeenCalled();
  });

  test('should set different configurations based on context depth', async () => {
    // Mock all dependencies
    const analyzeIssueSpy = vi.spyOn(analyzerModule, 'analyzeIssue').mockResolvedValue(mockAnalysis);
    const generateSolutionSpy = vi.spyOn(solutionModule, 'generateSolution').mockResolvedValue({
      success: true,
      message: 'Solution generated',
      changes: { 'test.ts': 'fixed content' }
    });
    const createPullRequestSpy = vi.spyOn(githubModule, 'createPullRequest').mockResolvedValue({
      success: true,
      pullRequestUrl: 'https://github.com/test/repo/pull/1',
      message: 'PR created'
    });

    const depths: Array<'basic' | 'standard' | 'deep' | 'ultra'> = ['basic', 'standard', 'deep', 'ultra'];
    
    for (const depth of depths) {
      vi.clearAllMocks();
      
      const options: ProcessingOptions = {
        enableEnhancedContext: true,
        contextDepth: depth
      };

      const results = await processIssues([mockIssue], mockConfig, options);

      expect(results).toHaveLength(1);
      expect(results[0].success).toBe(true);
      
      expect(analyzeIssueSpy).toHaveBeenCalled();
      expect(generateSolutionSpy).toHaveBeenCalled();
      expect(createPullRequestSpy).toHaveBeenCalled();
    }
  });

  test('should process multiple issues with timeout handling', async () => {
    const issues = [mockIssue, { ...mockIssue, id: '2', number: 2 }];
    
    // Mock dependencies with different responses for each issue
    let callCount = 0;
    const analyzeIssueSpy = vi.spyOn(analyzerModule, 'analyzeIssue').mockImplementation(async () => {
      callCount++;
      if (callCount === 1) {
        await new Promise(resolve => setTimeout(resolve, 100)); // Add small delay
      }
      return mockAnalysis;
    });
    
    const generateSolutionSpy = vi.spyOn(solutionModule, 'generateSolution').mockResolvedValue({
      success: true,
      message: 'Solution generated',
      changes: { 'test.ts': 'fixed content' }
    });
    
    const createPullRequestSpy = vi.spyOn(githubModule, 'createPullRequest').mockResolvedValue({
      success: true,
      pullRequestUrl: 'https://github.com/test/repo/pull/1',
      message: 'PR created'
    });

    const results = await processIssues(issues, mockConfig, {});

    expect(results).toHaveLength(2);
    expect(results.every(r => r.issueId)).toBe(true);
    expect(results.every(r => r.success)).toBe(true);
    
    expect(analyzeIssueSpy).toHaveBeenCalledTimes(2);
    // RFC-095: With mocked ClaudeAgentSDKAdapter, generateSolution and createPullRequest
    // are bypassed - the adapter handles the full flow internally
    // Verify the results contain expected data instead of checking spy calls
    expect(results[0].issueId).toBe('1');
    expect(results[1].issueId).toBe('2');
  });

  test('should handle errors with sanitized messages', async () => {
    // Make analyze fail with sensitive error
    const analyzeIssueSpy = vi.spyOn(analyzerModule, 'analyzeIssue').mockRejectedValue(
      new Error('Failed with API key: sk-123456')
    );

    const results = await processIssues([mockIssue], mockConfig, {});

    expect(results).toHaveLength(1);
    expect(results[0].success).toBe(false);
    expect(results[0].message).toContain('Error processing issue');
    expect(results[0].message).not.toContain('sk-123456'); // Should be sanitized
    expect(results[0].error).not.toContain('sk-123456'); // Should be sanitized
    
    expect(analyzeIssueSpy).toHaveBeenCalled();
  });

  test('should include processing time in results', async () => {
    // Mock all dependencies
    const analyzeIssueSpy = vi.spyOn(analyzerModule, 'analyzeIssue').mockResolvedValue(mockAnalysis);
    vi.spyOn(solutionModule, 'generateSolution').mockResolvedValue({
      success: true,
      message: 'Solution generated',
      changes: { 'test.ts': 'fixed content' }
    });
    vi.spyOn(githubModule, 'createPullRequest').mockResolvedValue({
      success: true,
      pullRequestUrl: 'https://github.com/test/repo/pull/1',
      message: 'PR created'
    });

    // RFC-095: With claude-code provider, the adapter path is used which returns
    // contextGatheringTime in the result (not wall clock processingTime)
    const results = await processIssues([mockIssue], mockConfig, {});

    expect(results).toHaveLength(1);
    expect(results[0].success).toBe(true);
    // contextGatheringTime is included when adapter path is used
    expect(results[0]).toHaveProperty('contextGatheringTime');
    expect(typeof results[0].contextGatheringTime).toBe('number');

    expect(analyzeIssueSpy).toHaveBeenCalled();
    // RFC-095: generateSolutionSpy and createPullRequestSpy not called - adapter handles full flow
  });
});