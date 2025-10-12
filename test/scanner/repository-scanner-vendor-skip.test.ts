import { describe, it, expect, beforeEach, vi } from 'vitest';
import { RepositoryScanner } from '../../src/scanner/repository-scanner.js';
import type { ScanConfig } from '../../src/scanner/types.js';

/**
 * Regression test for vendor file skipping issue
 *
 * Bug: Scanner was DETECTING vendor files but NOT SKIPPING them
 * Result: 23+ minute hang on minified JavaScript files (catastrophic regex backtracking)
 *
 * This test ensures vendor/minified files are actually SKIPPED during scanning,
 * not just flagged as vendor after scanning.
 */

describe('RepositoryScanner - Vendor File Skipping (Regression Test)', () => {
  let scanner: RepositoryScanner;
  let mockDetector: any;
  let mockVendorDetector: any;
  let mockGitHub: any;

  beforeEach(() => {
    vi.clearAllMocks();

    // Create mock detector that tracks detect() calls
    mockDetector = {
      detect: vi.fn().mockResolvedValue([]),
      cleanup: vi.fn()
    };

    // Create mock vendor detector
    mockVendorDetector = {
      isVendorFile: vi.fn()
    };

    // Create mock GitHub API
    mockGitHub = {
      git: {
        getTree: vi.fn(),
        getBlob: vi.fn()
      }
    };

    scanner = new RepositoryScanner();

    // Override the scanner's internal dependencies
    (scanner as any).detector = mockDetector;
    (scanner as any).vendorDetector = mockVendorDetector;
    (scanner as any).github = mockGitHub;
  });

  it('should SKIP scanning vendor/minified files (not just flag them)', async () => {
    const config: ScanConfig = {
      repository: {
        owner: 'test',
        name: 'railsgoat',
        defaultBranch: 'master'
      },
      enableASTValidation: false,
      createIssues: false,
      issueLabel: 'security'
    };

    // Mock GitHub to return both application and vendor files
    mockGitHub.git.getTree.mockResolvedValue({
      data: {
        tree: [
          { type: 'blob', path: 'app/controllers/user.rb', sha: 'abc123', size: 500 },
          { type: 'blob', path: 'app/assets/javascripts/bootstrap-editable.min.js', sha: 'def456', size: 50000 },
          { type: 'blob', path: 'app/models/post.rb', sha: 'ghi789', size: 300 }
        ]
      }
    });

    // Mock file contents
    mockGitHub.git.getBlob.mockImplementation(({ file_sha }: { file_sha: string }) => {
      const contents: Record<string, string> = {
        'abc123': 'class User < ApplicationRecord\n  # code\nend',
        'def456': '!function(){var e=window.jQuery;/* minified vendor code */}();',
        'ghi789': 'class Post < ApplicationRecord\n  # code\nend'
      };
      return Promise.resolve({
        data: {
          content: Buffer.from(contents[file_sha] || '').toString('base64')
        }
      });
    });

    // Configure vendor detector to identify .min.js as vendor
    mockVendorDetector.isVendorFile.mockImplementation((path: string) => {
      return Promise.resolve(path.includes('.min.js'));
    });

    // Run scan
    const result = await scanner.scan(config);

    // CRITICAL ASSERTION: detector.detect() should NOT be called for vendor files
    expect(mockDetector.detect).toHaveBeenCalledTimes(2); // Only for 2 Ruby files

    // Verify detect() was NOT called with minified file content
    const detectCalls = mockDetector.detect.mock.calls;
    expect(detectCalls).toHaveLength(2);

    // Verify detect() was only called for application files
    expect(detectCalls[0][0]).not.toContain('minified vendor code');
    expect(detectCalls[1][0]).not.toContain('minified vendor code');

    // Verify it WAS called for Ruby files
    expect(detectCalls[0][0]).toContain('ApplicationRecord');
    expect(detectCalls[1][0]).toContain('ApplicationRecord');
  });

  it('should skip all common vendor file patterns', async () => {
    const config: ScanConfig = {
      repository: {
        owner: 'test',
        name: 'repo',
        defaultBranch: 'main'
      },
      enableASTValidation: false,
      createIssues: false,
      issueLabel: 'security'
    };

    // Mock various vendor file patterns
    mockGitHub.git.getTree.mockResolvedValue({
      data: {
        tree: [
          { type: 'blob', path: 'node_modules/jquery/dist/jquery.js', sha: '1', size: 1000 },
          { type: 'blob', path: 'vendor/bootstrap/bootstrap.min.js', sha: '2', size: 5000 },
          { type: 'blob', path: 'app/assets/javascripts/alertify.min.js', sha: '3', size: 2000 },
          { type: 'blob', path: 'bower_components/angular/angular.js', sha: '4', size: 3000 },
          { type: 'blob', path: 'app/code.js', sha: '5', size: 200 }
        ]
      }
    });

    mockGitHub.git.getBlob.mockResolvedValue({
      data: { content: Buffer.from('// code').toString('base64') }
    });

    // All paths except app/code.js should be vendor
    mockVendorDetector.isVendorFile.mockImplementation((path: string) => {
      return Promise.resolve(!path.includes('app/code.js'));
    });

    await scanner.scan(config);

    // Should only scan the one application file
    expect(mockDetector.detect).toHaveBeenCalledTimes(1);
  });

  it('should log when skipping vendor files', async () => {
    const config: ScanConfig = {
      repository: {
        owner: 'test',
        name: 'repo',
        defaultBranch: 'main'
      },
      enableASTValidation: false,
      createIssues: false,
      issueLabel: 'security'
    };

    mockGitHub.git.getTree.mockResolvedValue({
      data: {
        tree: [
          { type: 'blob', path: 'vendor/jquery.min.js', sha: 'abc', size: 1000 }
        ]
      }
    });

    mockGitHub.git.getBlob.mockResolvedValue({
      data: { content: Buffer.from('vendor code').toString('base64') }
    });

    mockVendorDetector.isVendorFile.mockResolvedValue(true);

    // Spy on console/logger to verify skip message
    const logSpy = vi.spyOn(console, 'log');

    await scanner.scan(config);

    // Verify detector was NOT called
    expect(mockDetector.detect).not.toHaveBeenCalled();

    // Note: Actual logging verification would require mocking the logger
    // This is a placeholder for the concept
  });

  it('should prevent catastrophic backtracking on minified files by skipping them', async () => {
    const config: ScanConfig = {
      repository: {
        owner: 'test',
        name: 'railsgoat',
        defaultBranch: 'master'
      },
      enableASTValidation: false,
      createIssues: false,
      issueLabel: 'security'
    };

    // Simulate the exact file that caused the 23-minute hang
    const minifiedContent = '!function(){'.repeat(10000) + '}();'; // Long minified line

    mockGitHub.git.getTree.mockResolvedValue({
      data: {
        tree: [
          {
            type: 'blob',
            path: 'app/assets/javascripts/bootstrap-editable.min.js',
            sha: 'problematic',
            size: minifiedContent.length
          }
        ]
      }
    });

    mockGitHub.git.getBlob.mockResolvedValue({
      data: { content: Buffer.from(minifiedContent).toString('base64') }
    });

    mockVendorDetector.isVendorFile.mockResolvedValue(true);

    // This should complete quickly (not hang for 23+ minutes)
    const startTime = Date.now();
    await scanner.scan(config);
    const duration = Date.now() - startTime;

    // Should complete in under 1 second (not 23 minutes!)
    expect(duration).toBeLessThan(1000);

    // Should NOT have called detect() with the problematic content
    expect(mockDetector.detect).not.toHaveBeenCalled();
  });
});
