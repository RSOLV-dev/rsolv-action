import { describe, it, expect, beforeEach, vi } from 'vitest';
import { RepositoryScanner } from '../../src/scanner/repository-scanner.js';
import type { ScanConfig } from '../../src/scanner/types.js';
import type { Vulnerability } from '../../src/security/types.js';
import { VulnerabilityType } from '../../src/security/types.js';

// Mock all external dependencies
vi.mock('../../src/github/api.js');
vi.mock('../../src/security/safe-detector.js');
vi.mock('../../src/scanner/ast-validator.js');
vi.mock('../../src/vendor/vendor-detector.js');

describe('RepositoryScanner with AST Validation', () => {
  let scanner: RepositoryScanner;
  let mockValidator: ReturnType<typeof vi.fn>;
  let ASTValidatorMock: any;

  // Test data factory
  const createVulnerability = (overrides?: Partial<Vulnerability>): Vulnerability => ({
    type: VulnerabilityType.COMMAND_INJECTION,
    severity: 'critical',
    description: 'Eval injection detected',
    message: 'Using eval() with user input can lead to code injection',
    line: 10,
    column: 5,
    filePath: 'test.js',
    snippet: 'eval(x);',
    confidence: 90,
    cweId: 'CWE-95',
    owaspCategory: 'A03:2021',
    remediation: 'Do not use eval with user input',
    ...overrides
  });

  const createConfig = (overrides?: Partial<ScanConfig>): ScanConfig => ({
    repository: { owner: 'test', name: 'repo', defaultBranch: 'main' },
    enableASTValidation: true,
    rsolvApiKey: 'test-api-key',
    createIssues: false,
    issueLabel: 'security',
    ...overrides
  });

  const setupGitHubMock = (files: Array<{ path: string; content: string }>) => {
    const mockGitHub = (scanner as any).github;
    mockGitHub.git.getTree.mockResolvedValue({
      data: {
        tree: files.map(f => ({ type: 'blob', path: f.path, sha: 'abc123', size: f.content.length }))
      }
    });
    mockGitHub.git.getBlob.mockImplementation(({ file_sha }: { file_sha: string }) => {
      const file = files[0]; // Simplified for tests
      return Promise.resolve({
        data: { content: Buffer.from(file.content).toString('base64'), encoding: 'base64' }
      });
    });
  };

  beforeEach(async () => {
    vi.clearAllMocks();

    const { getGitHubClient } = await import('../../src/github/api.js');
    const { SafeDetector } = await import('../../src/security/safe-detector.js');
    const ASTValidatorModule = await import('../../src/scanner/ast-validator.js');
    ASTValidatorMock = ASTValidatorModule.ASTValidator;
    const { VendorDetector } = await import('../../src/vendor/vendor-detector.js');

    // Setup mocks with minimal required interface
    vi.mocked(getGitHubClient).mockReturnValue({
      git: {
        getTree: vi.fn().mockResolvedValue({ data: { tree: [] } }),
        getBlob: vi.fn().mockResolvedValue({ data: { content: '', encoding: 'base64' } })
      }
    } as any);

    vi.mocked(SafeDetector).mockImplementation(() => ({
      detect: vi.fn().mockResolvedValue([]),
      cleanup: vi.fn()
    } as any));

    vi.mocked(VendorDetector).mockImplementation(() => ({
      isVendorFile: vi.fn().mockResolvedValue(false)
    } as any));

    mockValidator = vi.fn().mockImplementation((vulns) => Promise.resolve(vulns));
    vi.mocked(ASTValidatorMock).mockImplementation(() => ({
      validateVulnerabilities: mockValidator
    } as any));

    scanner = new RepositoryScanner();
  });

  it('should use AST validation when enabled with API key', async () => {
    const vuln = createVulnerability();
    const config = createConfig();

    (scanner as any).detector.detect.mockResolvedValue([vuln]);
    setupGitHubMock([{ path: 'test.js', content: 'eval(x);' }]);
    mockValidator.mockResolvedValue([]); // AST filters out the vulnerability

    const result = await scanner.scan(config);

    expect(ASTValidatorMock).toHaveBeenCalledWith('test-api-key');
    expect(mockValidator).toHaveBeenCalledWith([vuln], expect.any(Map));
    expect(result.vulnerabilities).toHaveLength(0);
  });

  it('should skip AST validation when disabled', async () => {
    const vuln = createVulnerability();
    const config = createConfig({ enableASTValidation: false });

    (scanner as any).detector.detect.mockResolvedValue([vuln]);
    setupGitHubMock([{ path: 'test.js', content: 'eval(x);' }]);

    const result = await scanner.scan(config);

    expect(mockValidator).not.toHaveBeenCalled();
    expect(result.vulnerabilities).toHaveLength(1);
  });

  it('should skip AST validation when no API key provided', async () => {
    const vuln = createVulnerability();
    const config = createConfig({ rsolvApiKey: undefined });

    (scanner as any).detector.detect.mockResolvedValue([vuln]);
    setupGitHubMock([{ path: 'test.js', content: 'eval(x);' }]);

    const result = await scanner.scan(config);

    expect(ASTValidatorMock).not.toHaveBeenCalled();
    expect(result.vulnerabilities).toHaveLength(1);
  });

  it('should provide file contents to AST validator', async () => {
    const fileContent = 'const x = eval(userInput); // dangerous';
    const vuln = createVulnerability({ filePath: 'app.js', line: 1, column: 11 });
    const config = createConfig();

    (scanner as any).detector.detect.mockResolvedValue([vuln]);
    setupGitHubMock([{ path: 'app.js', content: fileContent }]);
    mockValidator.mockResolvedValue([vuln]);

    await scanner.scan(config);

    expect(mockValidator).toHaveBeenCalledWith(
      [vuln],
      new Map([['app.js', fileContent]])
    );
  });
});
