import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { PhaseExecutor } from '../index.js';
import { ActionConfig } from '../../../types/index.js';
import * as fs from 'fs/promises';
import * as path from 'path';

describe('PhaseExecutor - Phase Data Persistence', () => {
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
      useGitBasedEditing: true
    } as ActionConfig;
    
    executor = new PhaseExecutor(mockConfig);
  });
  
  afterEach(async () => {
    // Clean up
    try {
      await fs.rm(testDir, { recursive: true, force: true });
    } catch (e) {
      // Ignore cleanup errors
    }
  });
  
  it('should store and retrieve validation data with correct structure', async () => {
    const issueNumber = 123;
    const repoOwner = 'test-owner';
    const repoName = 'test-repo';
    
    // Create validation data as executeValidate would
    const validationData = {
      issueNumber: issueNumber,
      validated: true,
      enriched: true,
      vulnerabilities: [
        { file: 'test.js', line: 10, type: 'XSS', confidence: 'high' }
      ],
      timestamp: new Date().toISOString(),
      hasSpecificVulnerabilities: true,
      confidence: 'high'
    };
    
    // Store the data as executeValidate does
    await executor.storePhaseData('validation', {
      [`issue-${issueNumber}`]: validationData
    }, {
      repo: `${repoOwner}/${repoName}`,
      issueNumber: issueNumber,
      commitSha: 'test-commit-sha'
    });
    
    // Now retrieve it as executeMitigate does
    const retrievedData = await executor.phaseDataClient.retrievePhaseResults(
      `${repoOwner}/${repoName}`,
      issueNumber,
      'test-commit-sha'
    );
    
    // Check the structure - this is what executeMitigate expects
    const issueKey = `issue-${issueNumber}`;
    const validation = retrievedData?.validation?.[issueKey];
    
    // This should work but currently fails
    expect(validation).toBeDefined();
    expect(validation?.hasSpecificVulnerabilities).toBe(true);
    expect(validation?.vulnerabilities).toHaveLength(1);
    expect(validation?.confidence).toBe('high');
  });
  
  it('should handle the actual structure returned by retrievePhaseResults', async () => {
    const issueNumber = 456;
    const repoOwner = 'test-owner';
    const repoName = 'test-repo';
    
    // Store validation data
    const validationData = {
      issueNumber: issueNumber,
      validated: true,
      vulnerabilities: [
        { file: 'app.js', line: 20, type: 'SQLi', confidence: 'medium' }
      ],
      hasSpecificVulnerabilities: true,
      confidence: 'medium'
    };
    
    await executor.storePhaseData('validation', {
      [`issue-${issueNumber}`]: validationData
    }, {
      repo: `${repoOwner}/${repoName}`,
      issueNumber: issueNumber,
      commitSha: 'test-sha-2'
    });
    
    // Retrieve the data
    const retrievedData = await executor.phaseDataClient.retrievePhaseResults(
      `${repoOwner}/${repoName}`,
      issueNumber,
      'test-sha-2'
    );
    
    // Log the actual structure to understand what we get
    console.log('Retrieved data structure:', JSON.stringify(retrievedData, null, 2));
    
    // The actual structure might be different - let's test what it really is
    // This will help us understand the mismatch
    expect(retrievedData).toBeDefined();
    
    // Test different possible structures
    if (retrievedData?.validation) {
      console.log('Has validation key at top level');
      const issueKey = `issue-${issueNumber}`;
      if (retrievedData.validation[issueKey]) {
        console.log('Has issue key under validation');
        expect(retrievedData.validation[issueKey].hasSpecificVulnerabilities).toBe(true);
      }
    } else if (retrievedData?.data?.validation) {
      console.log('Has data.validation structure');
      const issueKey = `issue-${issueNumber}`;
      if (retrievedData.data.validation[issueKey]) {
        console.log('Has issue key under data.validation');
        expect(retrievedData.data.validation[issueKey].hasSpecificVulnerabilities).toBe(true);
      }
    } else {
      console.log('Unknown structure:', Object.keys(retrievedData || {}));
    }
  });
});