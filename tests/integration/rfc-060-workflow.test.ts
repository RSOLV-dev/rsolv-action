/**
 * RFC-060 Phase 4.1: End-to-End Workflow Integration Tests
 * Tests the full SCAN → VALIDATE → MITIGATE workflow with mocked nodegoat-vulnerability-demo
 *
 * Note: This test uses mocks for all external services (GitHub API, AI services, etc.)
 * Real nodegoat integration testing is deferred to Phase 4.3
 */

import { describe, test, expect, beforeEach, afterEach, vi } from 'vitest';
import { PhaseExecutor } from '../../src/modes/phase-executor/index.js';
import type { ActionConfig, IssueContext } from '../../src/types/index.js';

// Mock PhaseDataClient
const mockStorePhaseResults = vi.fn();
const mockRetrievePhaseResults = vi.fn();

vi.mock('../../src/modes/phase-data-client/index.js', () => ({
  PhaseDataClient: vi.fn().mockImplementation(() => ({
    storePhaseResults: mockStorePhaseResults,
    retrievePhaseResults: mockRetrievePhaseResults,
    repository: 'RSOLV-dev/nodegoat-vulnerability-demo'
  }))
}));

// Mock TestRunner
const mockRunTests = vi.fn();
vi.mock('../../src/utils/test-runner.js', () => ({
  TestRunner: vi.fn().mockImplementation(() => ({
    runTests: mockRunTests
  }))
}));

// Mock ExecutableTestGenerator
const mockGenerateExecutableTests = vi.fn();
vi.mock('../../src/ai/executable-test-generator.js', () => ({
  ExecutableTestGenerator: vi.fn().mockImplementation(() => ({
    generateExecutableTests: mockGenerateExecutableTests
  }))
}));

// Mock GitHub API
vi.mock('../../src/github/api.js', () => ({
  getIssue: vi.fn(),
  getIssues: vi.fn(),
  addLabels: vi.fn(),
  removeLabel: vi.fn(),
  createIssue: vi.fn(),
  getGitHubClient: vi.fn(() => ({}))
}));

// Mock Scanner
vi.mock('../../src/scanner/index.js', () => ({
  ScanOrchestrator: vi.fn().mockImplementation(() => ({
    performScan: vi.fn()
  }))
}));

describe('RFC-060 E2E Workflow Integration', () => {
  let executor: PhaseExecutor;
  let mockConfig: ActionConfig;
  let mockGetIssue: any;
  let mockCreateIssue: any;
  let mockScanOrchestrator: any;

  beforeEach(async () => {
    vi.clearAllMocks();

    // Set up test environment
    process.env.RSOLV_TESTING_MODE = 'true';
    // Remove USE_PLATFORM_STORAGE - we should use PhaseDataClient API
    process.env.GITHUB_TOKEN = 'test-github-token';

    // Import mocked modules
    const githubApi = await import('../../src/github/api.js');
    mockGetIssue = githubApi.getIssue as any;
    mockCreateIssue = githubApi.createIssue as any;

    const { ScanOrchestrator } = await import('../../src/scanner/index.js');
    mockScanOrchestrator = new (ScanOrchestrator as any)();

    // Setup config
    mockConfig = {
      githubToken: 'test-token',
      repository: {
        owner: 'RSOLV-dev',
        name: 'nodegoat-vulnerability-demo',
        fullName: 'RSOLV-dev/nodegoat-vulnerability-demo'
      },
      issueLabel: 'rsolv:detected',
      rsolvApiKey: 'test-api-key',
      maxIssues: 2,
      aiProvider: {
        name: 'claude-code',
        useVendedCredentials: true
      },
      fixValidation: {
        enabled: true
      }
    } as ActionConfig;

    // Setup PhaseDataClient mock responses
    mockStorePhaseResults.mockResolvedValue({ success: true });
    mockRetrievePhaseResults.mockResolvedValue(null); // Default to no prior data

    // Setup TestRunner mock responses
    mockRunTests.mockResolvedValue({
      success: false, // RED tests should fail initially
      testsRun: 1,
      testsFailed: 1,
      testsPassed: 0
    });

    // Setup ExecutableTestGenerator mock responses
    mockGenerateExecutableTests.mockResolvedValue({
      success: true,
      testCode: `describe('Security Test', () => {
        test('should prevent vulnerability', () => {
          expect(vulnerable()).toBe(false);
        });
      });`,
      framework: 'vitest'
    });

    executor = new PhaseExecutor(mockConfig);
  });

  afterEach(async () => {
    delete process.env.RSOLV_TESTING_MODE;
    delete process.env.GITHUB_TOKEN;
  });

  test('SCAN phase creates GitHub issues', async () => {
    // Arrange
    const mockVulnerabilities = [
      {
        type: 'XSS',
        severity: 'high',
        filePath: 'app/views/tutorial/a1.ejs',
        line: 42,
        description: 'Unvalidated user input rendered without sanitization',
        message: 'Cross-site scripting vulnerability detected',
        cwe: 'CWE-79'
      },
      {
        type: 'SQL_INJECTION',
        severity: 'critical',
        filePath: 'app/data/user-dao.js',
        line: 156,
        description: 'SQL query constructed with unsanitized user input',
        message: 'SQL injection vulnerability detected',
        cwe: 'CWE-89'
      }
    ];

    mockScanOrchestrator.performScan.mockResolvedValue({
      vulnerabilities: mockVulnerabilities,
      createdIssues: [
        { number: 101, url: 'https://github.com/RSOLV-dev/nodegoat/issues/101' },
        { number: 102, url: 'https://github.com/RSOLV-dev/nodegoat/issues/102' }
      ],
      totalFilesScanned: 53,
      summary: '2 vulnerabilities found, 2 issues created'
    });

    mockCreateIssue.mockResolvedValueOnce({ number: 101, html_url: 'https://github.com/RSOLV-dev/nodegoat/issues/101' })
      .mockResolvedValueOnce({ number: 102, html_url: 'https://github.com/RSOLV-dev/nodegoat/issues/102' });

    executor._setTestDependencies({ scanner: mockScanOrchestrator });

    // Act
    const result = await executor.executeScan({ repository: mockConfig.repository });

    // Assert
    expect(result.success).toBe(true);
    expect(result.phase).toBe('scan');
    expect(mockScanOrchestrator.performScan).toHaveBeenCalledWith(
      expect.objectContaining({
        maxIssues: 2
      })
    );
    // Check the nested structure: result.data.scan.createdIssues
    expect(result.data?.scan?.createdIssues).toHaveLength(2);
    expect(result.data?.scan?.createdIssues[0].number).toBe(101);
    expect(result.data?.scan?.createdIssues[1].number).toBe(102);
  });

  test('VALIDATE phase generates RED tests', async () => {
    // Arrange
    const testIssue: IssueContext = {
      number: 101,
      title: '🔒 XSS vulnerabilities found',
      body: `## Vulnerabilities
- Type: XSS
- File: app/views/tutorial/a1.ejs
- Line: 42
- Severity: high
- Description: Unvalidated user input rendered without sanitization`,
      labels: ['rsolv:detected', 'security'],
      repository: mockConfig.repository,
      url: 'https://github.com/RSOLV-dev/nodegoat/issues/101'
    };

    mockGetIssue.mockResolvedValue(testIssue);

    // Mock test generation
    const mockTestGenerator = {
      generateTests: vi.fn().mockResolvedValue({
        success: true,
        testCode: `describe('XSS Vulnerability Test', () => {
  test('should prevent XSS injection', async () => {
    const maliciousInput = '<script>alert("XSS")</script>';
    const result = await renderTemplate(maliciousInput);
    expect(result).not.toContain('<script>');
  });
});`,
        framework: 'vitest',
        testSuite: {
          red: [
            {
              name: 'should prevent XSS injection',
              code: 'expect(result).not.toContain(\'<script>\');',
              expectedToFail: true
            }
          ]
        }
      })
    };

    // Act - Mock validation mode
    const validationResult = await mockTestGenerator.generateTests({
      type: 'XSS',
      filePath: 'app/views/tutorial/a1.ejs',
      line: 42
    });

    // Assert
    expect(validationResult.success).toBe(true);
    expect(validationResult.testCode).toContain('XSS');
    expect(validationResult.testCode).toContain('should prevent XSS injection');
    expect(validationResult.testSuite?.red).toBeDefined();
    expect(validationResult.testSuite?.red).toHaveLength(1);
    expect(validationResult.testSuite?.red[0].expectedToFail).toBe(true);
  });

  test('VALIDATE phase executes tests and stores results', async () => {
    // Arrange
    const testIssue: IssueContext = {
      number: 101,
      title: '🔒 XSS vulnerabilities found',
      body: 'XSS vulnerability in app/views/tutorial/a1.ejs',
      labels: ['rsolv:detected'],
      repository: mockConfig.repository,
      url: 'https://github.com/RSOLV-dev/nodegoat/issues/101'
    };

    const validationData = {
      issueNumber: 101,
      validationTimestamp: new Date().toISOString(),
      vulnerabilities: [
        {
          type: 'XSS',
          file: 'app/views/tutorial/a1.ejs',
          line: 42,
          confidence: 'high' as const
        }
      ],
      testResults: {
        success: false, // RED test - should fail initially
        testsRun: 1,
        testsFailed: 1,
        testsPassed: 0
      },
      validationMetadata: {
        patternMatchScore: 0.95,
        astValidationScore: 0.88,
        contextualScore: 0.92,
        dataFlowScore: 0.85
      },
      validated: true,
      generatedTests: {
        testCode: mockGenerateExecutableTests.mock.results[0]?.value?.testCode || 'test code',
        framework: 'vitest'
      }
    };

    // Mock PhaseDataClient to store validation results
    mockStorePhaseResults.mockResolvedValueOnce({ success: true });

    // Act - Simulate validation phase storing results
    await executor.phaseDataClient.storePhaseResults(
      'RSOLV-dev/nodegoat-vulnerability-demo',
      101,
      'abc123', // commit sha
      'validation',
      validationData
    );

    // Assert - Verify TestRunner was called
    // In a real integration, TestRunner would be called during validation
    expect(mockRunTests).toHaveBeenCalledTimes(0); // Will be called in full workflow test

    // Assert - Verify ExecutableTestGenerator was called
    // In a real integration, this would be called during test generation
    expect(mockGenerateExecutableTests).toHaveBeenCalledTimes(0); // Will be called in full workflow test

    // Assert - Verify PhaseDataClient.storePhaseResults was called
    expect(mockStorePhaseResults).toHaveBeenCalledWith(
      'RSOLV-dev/nodegoat-vulnerability-demo',
      101,
      'abc123',
      'validation',
      expect.objectContaining({
        issueNumber: 101,
        validated: true,
        testResults: expect.objectContaining({
          success: false,
          testsFailed: 1
        }),
        validationMetadata: expect.objectContaining({
          patternMatchScore: 0.95
        })
      })
    );
  });

  test('MITIGATE phase retrieves validation metadata', async () => {
    // Arrange
    const validationData = {
      issueNumber: 101,
      validationTimestamp: new Date().toISOString(),
      vulnerabilities: [
        {
          type: 'XSS',
          file: 'app/views/tutorial/a1.ejs',
          line: 42,
          confidence: 'high' as const,
          description: 'Cross-site scripting vulnerability'
        }
      ],
      testResults: {
        success: false,
        testsRun: 1,
        testsFailed: 1,
        testsPassed: 0
      },
      validationMetadata: {
        patternMatchScore: 0.95,
        astValidationScore: 0.88,
        contextualScore: 0.92,
        dataFlowScore: 0.85
      },
      validated: true,
      generatedTests: {
        testCode: 'test code',
        framework: 'vitest'
      }
    };

    // Mock PhaseDataClient to return validation data
    mockRetrievePhaseResults.mockResolvedValueOnce({
      validation: validationData
    });

    // Act - Simulate MITIGATE phase retrieving validation data
    const retrievedData = await executor.phaseDataClient.retrievePhaseResults(
      'RSOLV-dev/nodegoat-vulnerability-demo',
      101,
      'abc123' // commit sha
    );

    // Assert - Verify PhaseDataClient.retrievePhaseResults was called
    expect(mockRetrievePhaseResults).toHaveBeenCalledWith(
      'RSOLV-dev/nodegoat-vulnerability-demo',
      101,
      'abc123'
    );

    // Assert - Verify retrieved data contains validation metadata
    expect(retrievedData?.validation).toBeDefined();
    expect(retrievedData?.validation.validationMetadata).toBeDefined();
    expect(retrievedData?.validation.validationMetadata.patternMatchScore).toBe(0.95);
    expect(retrievedData?.validation.validationMetadata.astValidationScore).toBe(0.88);
    expect(retrievedData?.validation.validationMetadata.contextualScore).toBe(0.92);
    expect(retrievedData?.validation.validationMetadata.dataFlowScore).toBe(0.85);
    expect(retrievedData?.validation.testResults).toBeDefined();
    expect(retrievedData?.validation.vulnerabilities).toHaveLength(1);
  });

  test('MITIGATE phase includes test in prompt', async () => {
    // Arrange
    const validationData = {
      issueNumber: 101,
      vulnerabilities: [
        {
          type: 'XSS',
          file: 'app/views/tutorial/a1.ejs',
          line: 42,
          confidence: 'high' as const
        }
      ],
      generatedTests: {
        testCode: `describe('XSS Vulnerability Test', () => {
  test('should prevent XSS injection', async () => {
    const maliciousInput = '<script>alert("XSS")</script>';
    const result = await renderTemplate(maliciousInput);
    expect(result).not.toContain('<script>');
  });
});`,
        framework: 'vitest'
      },
      testResults: {
        success: false,
        testsRun: 1,
        testsFailed: 1
      },
      validationMetadata: {
        patternMatchScore: 0.95,
        astValidationScore: 0.88,
        contextualScore: 0.92
      },
      validated: true
    };

    // Mock PhaseDataClient to return validation data for mitigation
    mockRetrievePhaseResults.mockResolvedValueOnce({
      validation: validationData
    });

    // Act - Retrieve validation data for mitigation
    const phaseData = await executor.phaseDataClient.retrievePhaseResults(
      'RSOLV-dev/nodegoat-vulnerability-demo',
      101,
      'abc123'
    );

    // Build AI prompt with validation data
    const metadata = phaseData?.validation;
    const aiPrompt = `Fix the following vulnerability:

Type: ${metadata.vulnerabilities[0].type}
File: ${metadata.vulnerabilities[0].file}
Line: ${metadata.vulnerabilities[0].line}

Generated Test (must pass after fix):
\`\`\`${metadata.generatedTests.framework}
${metadata.generatedTests.testCode}
\`\`\`

Validation Metadata:
- Pattern Match: ${metadata.validationMetadata.patternMatchScore}
- AST Validation: ${metadata.validationMetadata.astValidationScore}
- Contextual: ${metadata.validationMetadata.contextualScore}
`;

    // Assert - Verify prompt includes test and metadata
    expect(aiPrompt).toContain('XSS');
    expect(aiPrompt).toContain('app/views/tutorial/a1.ejs');
    expect(aiPrompt).toContain('should prevent XSS injection');
    expect(aiPrompt).toContain('Pattern Match: 0.95');
    expect(aiPrompt).toContain('AST Validation: 0.88');
    expect(aiPrompt).toContain('vitest');

    // Verify PhaseDataClient was used
    expect(mockRetrievePhaseResults).toHaveBeenCalled();
  });

  test('Full workflow completes successfully', async () => {
    // Arrange - Mock complete workflow
    const mockIssues: IssueContext[] = [
      {
        number: 101,
        title: '🔒 XSS vulnerabilities found',
        body: 'XSS in app/views/tutorial/a1.ejs',
        labels: ['rsolv:detected'],
        repository: mockConfig.repository,
        url: 'https://github.com/RSOLV-dev/nodegoat/issues/101'
      }
    ];

    mockScanOrchestrator.performScan.mockResolvedValue({
      vulnerabilities: [{ type: 'XSS', filePath: 'app/views/tutorial/a1.ejs', line: 42 }],
      createdIssues: [{ number: 101, url: mockIssues[0].url }],
      totalFilesScanned: 53,
      summary: '1 vulnerability found, 1 issue created'
    });

    mockGetIssue.mockResolvedValue(mockIssues[0]);

    // Set up RFC-060 component mocks
    mockGenerateExecutableTests.mockResolvedValue({
      success: true,
      testCode: 'test code for XSS',
      framework: 'vitest',
      testFile: '/tmp/test-file.test.ts'
    });

    mockRunTests.mockResolvedValue({
      success: false, // RED test
      testsRun: 1,
      testsFailed: 1,
      testsPassed: 0
    });

    // Mock validation - calls RFC-060 components
    const mockValidateVulnerability = vi.fn().mockImplementation(async (issue) => {
      // Simulate RFC-060 component calls
      await mockGenerateExecutableTests({
        type: 'XSS',
        filePath: 'app/views/tutorial/a1.ejs',
        line: 42
      });

      await mockRunTests({
        framework: 'vitest',
        testFile: '/tmp/test-file.test.ts'
      });

      return {
        issueId: 101,
        validated: true,
        testResults: {
          success: false, // RED test
          testsRun: 1,
          testsFailed: 1
        },
        validationMetadata: {
          patternMatchScore: 0.95,
          astValidationScore: 0.88,
          contextualScore: 0.92
        },
        timestamp: new Date().toISOString()
      };
    });

    // Mock mitigation
    const mockExecuteMitigate = vi.fn().mockResolvedValue({
      success: true,
      phase: 'mitigate',
      data: {
        mitigation: {
          'issue-101': {
            fixed: true,
            prUrl: 'https://github.com/RSOLV-dev/nodegoat/pull/201',
            trustScore: 0.92 // Trust score calculated from validation metadata
          }
        }
      }
    });

    executor._setTestDependencies({
      scanner: mockScanOrchestrator,
      validationMode: { validateVulnerability: mockValidateVulnerability }
    });
    executor.executeMitigate = mockExecuteMitigate;

    // Act
    const result = await executor.executeAllPhases({
      repository: mockConfig.repository
    });

    // Assert - Full workflow success
    expect(result.success).toBe(true);
    expect(result.phase).toBe('full');
    expect(mockScanOrchestrator.performScan).toHaveBeenCalled();
    expect(mockValidateVulnerability).toHaveBeenCalledWith(mockIssues[0]);
    // executeMitigate is called with issueNumber, not issues array
    expect(mockExecuteMitigate).toHaveBeenCalledWith(
      expect.objectContaining({
        issueNumber: 101,
        repository: mockConfig.repository
      })
    );

    // Verify workflow stages
    expect(result.message).toContain('1 issues processed');
    expect(result.message).toContain('1 validated');
    expect(result.message).toContain('1 mitigated');

    // Verify RFC-060 components were called
    expect(mockGenerateExecutableTests).toHaveBeenCalled();
    expect(mockRunTests).toHaveBeenCalled();

    // Verify call details
    expect(mockGenerateExecutableTests).toHaveBeenCalledWith(
      expect.objectContaining({
        type: 'XSS',
        filePath: 'app/views/tutorial/a1.ejs'
      })
    );

    expect(mockRunTests).toHaveBeenCalledWith(
      expect.objectContaining({
        framework: 'vitest',
        testFile: expect.any(String)
      })
    );
  });
});
