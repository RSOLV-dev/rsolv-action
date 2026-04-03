import { describe, it, expect, vi, beforeEach } from 'vitest';
import { RepositoryScanner } from '../repository-scanner.js';

// Mock dependencies
vi.mock('../../github/api.js', () => ({
  getGitHubClient: vi.fn(() => ({
    git: { getTree: vi.fn() },
    repos: { getContent: vi.fn() },
  }))
}));

vi.mock('../../utils/logger.js', () => ({
  logger: {
    info: vi.fn(),
    warn: vi.fn(),
    error: vi.fn(),
    debug: vi.fn(),
  }
}));

vi.mock('../../vendor/vendor-detector.js', () => ({
  VendorDetector: vi.fn().mockImplementation(() => ({
    isVendorFile: vi.fn().mockResolvedValue(false),
  }))
}));

describe('Config File Filtering', () => {
  it('should identify config directory paths', () => {
    // Access static method
    const isConfigFile = (RepositoryScanner as Record<string, unknown>)['isConfigFile'] as (path: string) => boolean;

    expect(isConfigFile('config/env/development.js')).toBe(true);
    expect(isConfigFile('config/database.yml')).toBe(true);
    expect(isConfigFile('.config/settings.js')).toBe(true);
    expect(isConfigFile('configs/app.json')).toBe(true);
    expect(isConfigFile('src/app.js')).toBe(false);
    expect(isConfigFile('lib/handler.ts')).toBe(false);
  });

  it('should identify config file patterns', () => {
    const isConfigFile = (RepositoryScanner as Record<string, unknown>)['isConfigFile'] as (path: string) => boolean;

    expect(isConfigFile('webpack.config.js')).toBe(true);
    expect(isConfigFile('tsconfig.json')).toBe(true);
    expect(isConfigFile('.env.production')).toBe(true);
    expect(isConfigFile('src/utils.js')).toBe(false);
  });

  it('should apply 0.5x confidence multiplier to config file vulnerabilities', () => {
    const applyConfigMultiplier = (RepositoryScanner as Record<string, unknown>)['applyConfigConfidenceMultiplier'] as
      (vulns: Array<{filePath?: string; confidence: number}>) => Array<{filePath?: string; confidence: number}>;

    const vulns = [
      { filePath: 'config/env/development.js', confidence: 80 },
      { filePath: 'src/app.js', confidence: 80 },
    ];

    const result = applyConfigMultiplier(vulns);

    // Config file vuln should have halved confidence
    expect(result[0].confidence).toBe(40);
    // Non-config vuln should be unchanged
    expect(result[1].confidence).toBe(80);
  });

  it('should still detect hardcoded secrets in config files (just lower confidence)', () => {
    const applyConfigMultiplier = (RepositoryScanner as Record<string, unknown>)['applyConfigConfidenceMultiplier'] as
      (vulns: Array<{type?: string; filePath?: string; confidence: number}>) => Array<{type?: string; filePath?: string; confidence: number}>;

    const vulns = [
      { type: 'hardcoded_secrets', filePath: 'config/database.yml', confidence: 90 },
    ];

    const result = applyConfigMultiplier(vulns);

    // Should still be present, just with reduced confidence
    expect(result).toHaveLength(1);
    expect(result[0].confidence).toBe(45);
  });

  it('should cause XSS with document.write in config to drop below typical threshold', () => {
    const applyConfigMultiplier = (RepositoryScanner as Record<string, unknown>)['applyConfigConfidenceMultiplier'] as
      (vulns: Array<{type?: string; filePath?: string; confidence: number}>) => Array<{type?: string; filePath?: string; confidence: number}>;

    // XSS typically has ~60-80 confidence, halved puts it at 30-40
    const vulns = [
      { type: 'xss', filePath: 'config/env/development.js', confidence: 60 },
    ];

    const result = applyConfigMultiplier(vulns);
    // 30% confidence is below most actionable thresholds
    expect(result[0].confidence).toBe(30);
    expect(result[0].confidence).toBeLessThan(50);
  });
});
