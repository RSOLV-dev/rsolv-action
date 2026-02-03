/**
 * RFC-101: Tests for project shape consumption in VALIDATE phase
 * Verifies that validation-mode correctly:
 *   1. Retrieves project_shape from phase data
 *   2. Applies env vars from project shape to process.env and setup commands
 *   3. Executes setup commands with merged environment
 *   4. Passes ai_context to the LLM prompt
 */

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import type { ActionConfig, IssueContext } from '../../types/index.js';

// Create mocks using vi.hoisted to ensure proper hoisting
const {
  mockAnalyzeIssue,
  mockTestIntegrationClientAnalyze,
  mockRetrievePhaseResults,
  mockStorePhaseResults,
  mockAddLabels,
  mockCreateLabel,
  mockExecSync
} = vi.hoisted(() => ({
  mockAnalyzeIssue: vi.fn(),
  mockTestIntegrationClientAnalyze: vi.fn(),
  mockRetrievePhaseResults: vi.fn(),
  mockStorePhaseResults: vi.fn(),
  mockAddLabels: vi.fn(),
  mockCreateLabel: vi.fn(),
  mockExecSync: vi.fn()
}));

vi.mock('../../ai/analyzer.js', () => ({
  analyzeIssue: mockAnalyzeIssue
}));

vi.mock('../test-integration-client.js', () => ({
  TestIntegrationClient: vi.fn().mockImplementation(() => ({
    analyze: mockTestIntegrationClientAnalyze
  }))
}));

vi.mock('../../modes/phase-data-client/index.js', () => ({
  PhaseDataClient: vi.fn().mockImplementation(() => ({
    retrievePhaseResults: mockRetrievePhaseResults,
    storePhaseResults: mockStorePhaseResults
  }))
}));

vi.mock('@octokit/rest', () => ({
  Octokit: vi.fn().mockImplementation(() => ({
    issues: { addLabels: mockAddLabels, createLabel: mockCreateLabel }
  }))
}));

vi.mock('../../github/api.js', () => ({
  getGitHubClient: vi.fn().mockReturnValue({
    issues: { addLabels: mockAddLabels, createLabel: mockCreateLabel }
  })
}));

vi.mock('../vendor-utils.js', () => ({
  vendorFilterUtils: {
    checkForVendorFiles: vi.fn().mockResolvedValue({ isVendor: false, files: [] })
  }
}));

vi.mock('../../ai/client.js', () => ({
  getAiClient: vi.fn().mockResolvedValue({
    complete: vi.fn().mockResolvedValue('```javascript\ntest("vuln", () => { expect(true).toBe(true); });\n```')
  })
}));

vi.mock('child_process', () => ({
  execSync: mockExecSync
}));

vi.mock('fs', () => ({
  default: {
    existsSync: vi.fn().mockReturnValue(false),
    readFileSync: vi.fn().mockReturnValue(''),
    writeFileSync: vi.fn(),
    mkdirSync: vi.fn(),
    readdirSync: vi.fn().mockReturnValue([])
  },
  existsSync: vi.fn().mockReturnValue(false),
  readFileSync: vi.fn().mockReturnValue(''),
  writeFileSync: vi.fn(),
  mkdirSync: vi.fn(),
  readdirSync: vi.fn().mockReturnValue([])
}));

import { ValidationMode } from '../validation-mode.js';
import { logger } from '../../utils/logger.js';

vi.mock('../../utils/logger.js', () => ({
  logger: {
    info: vi.fn(),
    warn: vi.fn(),
    error: vi.fn(),
    debug: vi.fn()
  }
}));

function makeConfig(): ActionConfig {
  return {
    apiKey: 'test-api-key',
    configPath: '/test/config',
    issueLabel: 'rsolv:vulnerability',
    repoToken: 'test-token',
    rsolvApiKey: 'test-rsolv-key',
    rsolvApiUrl: 'https://api.rsolv.dev',
    aiProvider: {
      provider: 'anthropic',
      apiKey: 'test-ai-key',
      model: 'claude-sonnet-4-5-20250929',
      maxTokens: 4000,
      useVendedCredentials: false
    },
    containerConfig: { enabled: false },
    securitySettings: { scanDependencies: true }
  } as ActionConfig;
}

function makeIssue(): IssueContext {
  return {
    id: '1',
    number: 123,
    title: 'SQL Injection in user authentication',
    body: 'Vulnerability details...',
    labels: ['rsolv:vulnerability'],
    assignees: [],
    repository: {
      owner: 'test-org',
      name: 'test-repo',
      fullName: 'test-org/test-repo',
      defaultBranch: 'main'
    },
    source: 'github',
    createdAt: '2024-01-01T00:00:00Z',
    updatedAt: '2024-01-01T00:00:00Z'
  } as IssueContext;
}

describe('RFC-101: Project Shape Consumption in VALIDATE', () => {
  let validationMode: ValidationMode;
  let mockIssue: IssueContext;
  const originalEnv = { ...process.env };

  beforeEach(() => {
    process.env = { ...originalEnv };
    process.env.GITHUB_TOKEN = 'test-token';
    process.env.GITHUB_REPOSITORY = 'test-org/test-repo';

    vi.clearAllMocks();

    // Reset hoisted mocks
    mockAnalyzeIssue.mockReset();
    mockTestIntegrationClientAnalyze.mockReset();
    mockRetrievePhaseResults.mockReset();
    mockStorePhaseResults.mockReset();
    mockAddLabels.mockReset();
    mockCreateLabel.mockReset();
    mockExecSync.mockReset();

    // Default mock behaviors
    mockExecSync.mockReturnValue('test-commit-hash');
    mockStorePhaseResults.mockResolvedValue({ success: true });
    mockAddLabels.mockResolvedValue({});
    mockCreateLabel.mockResolvedValue({});

    mockAnalyzeIssue.mockResolvedValue({
      canBeFixed: true,
      filesToModify: ['src/auth.js'],
      issueType: 'security',
      estimatedComplexity: 'medium',
      requiredContext: [],
      suggestedApproach: 'Fix SQL injection'
    });

    mockTestIntegrationClientAnalyze.mockResolvedValue({
      recommendations: [{ path: 'test/auth.test.js', score: 0.9, reason: 'Best match' }],
      fallback: { path: 'test/auth.test.js', reason: 'Only candidate' }
    });

    mockIssue = makeIssue();

    validationMode = new ValidationMode(makeConfig(), '/tmp/test-repo');

    // Spy on private methods to control the pipeline up to the RFC-101 block
    vi.spyOn(validationMode as any, 'ensureCleanGitState').mockImplementation(() => {});
    vi.spyOn(validationMode as any, 'loadFalsePositiveCache').mockImplementation(() => {});
    vi.spyOn(validationMode as any, 'detectFrameworkFromFile').mockReturnValue('jest');
    vi.spyOn(validationMode as any, 'scanTestFiles').mockResolvedValue(['test/auth.test.js']);
    vi.spyOn(validationMode as any, 'addGitHubLabel').mockResolvedValue(undefined);
  });

  afterEach(() => {
    process.env = { ...originalEnv };
  });

  describe('env map consumption', () => {
    it('should apply env vars from project shape to process.env', async () => {
      mockRetrievePhaseResults.mockResolvedValue({
        project_shape: {
          ecosystem: 'python',
          runtime_services: [{ kind: 'sql_database', package: 'django', resolution: 'in_process_fallback' }],
          setup_commands: [],
          env: { DJANGO_SETTINGS_MODULE: 'myproject.settings', PYTHONDONTWRITEBYTECODE: '1' },
          ai_context: 'Fallback sqlite3 configured.'
        }
      });

      // Let it run through the pipeline — it will fail at generateTestWithRetry but
      // RFC-101 block runs before that
      try {
        await validationMode.validateVulnerability(mockIssue);
      } catch {
        // Expected: fails after RFC-101 block
      }

      // Verify env vars were applied to process.env
      expect(process.env.DJANGO_SETTINGS_MODULE).toBe('myproject.settings');
      expect(process.env.PYTHONDONTWRITEBYTECODE).toBe('1');

      // Verify log message
      expect(logger.info).toHaveBeenCalledWith(
        expect.stringContaining('Applied 2 env var(s) from project shape')
      );
    });

    it('should merge env vars into setup command execution environment', async () => {
      mockRetrievePhaseResults.mockResolvedValue({
        project_shape: {
          ecosystem: 'ruby',
          runtime_services: [{ kind: 'sql_database', package: 'rails', resolution: 'in_process_native' }],
          setup_commands: ['bundle exec rake db:create', 'bundle exec rake db:schema:load'],
          env: { RAILS_ENV: 'test' },
          ai_context: 'SQLite configured.'
        }
      });

      try {
        await validationMode.validateVulnerability(mockIssue);
      } catch {
        // Expected
      }

      // Find the setup command calls (filter out git rev-parse etc.)
      const setupCalls = mockExecSync.mock.calls.filter(
        (call: unknown[]) => typeof call[0] === 'string' && (call[0] as string).includes('bundle exec')
      );
      expect(setupCalls.length).toBe(2);
      expect(setupCalls[0][0]).toBe('bundle exec rake db:create');
      expect(setupCalls[1][0]).toBe('bundle exec rake db:schema:load');

      // Verify RAILS_ENV=test was in the env for both commands
      for (const call of setupCalls) {
        const opts = call[1] as { env?: Record<string, string> };
        expect(opts.env).toBeDefined();
        expect(opts.env?.RAILS_ENV).toBe('test');
      }
    });

    it('should handle project shape with empty env map', async () => {
      mockRetrievePhaseResults.mockResolvedValue({
        project_shape: {
          ecosystem: 'javascript',
          runtime_services: [],
          setup_commands: [],
          env: {},
          ai_context: 'No runtime service dependencies.'
        }
      });

      try {
        await validationMode.validateVulnerability(mockIssue);
      } catch {
        // Expected
      }

      // Should NOT log env application message when empty
      expect(logger.info).not.toHaveBeenCalledWith(
        expect.stringContaining('Applied')
      );

      // Should still log project shape detection
      expect(logger.info).toHaveBeenCalledWith(
        expect.stringContaining('javascript')
      );
    });

    it('should handle project shape without env property (backward compat)', async () => {
      // Older phase data may not have env field
      mockRetrievePhaseResults.mockResolvedValue({
        project_shape: {
          ecosystem: 'ruby',
          runtime_services: [],
          setup_commands: ['echo hello'],
          ai_context: 'Test context'
          // no env property
        }
      });

      try {
        await validationMode.validateVulnerability(mockIssue);
      } catch {
        // Expected
      }

      // Should still execute setup commands without error
      const echoCalls = mockExecSync.mock.calls.filter(
        (call: unknown[]) => call[0] === 'echo hello'
      );
      expect(echoCalls.length).toBe(1);
    });
  });

  describe('ai_context consumption', () => {
    it('should store ai_context from project shape for LLM prompt', async () => {
      mockRetrievePhaseResults.mockResolvedValue({
        project_shape: {
          ecosystem: 'python',
          runtime_services: [{ kind: 'sql_database', package: 'django', resolution: 'in_process_fallback' }],
          setup_commands: [],
          env: {},
          ai_context: 'Fallback sqlite3 (stdlib) configured. Behavior may differ from postgresql.'
        }
      });

      try {
        await validationMode.validateVulnerability(mockIssue);
      } catch {
        // Expected
      }

      // Verify ai_context was logged (confirming it was stored)
      expect(logger.info).toHaveBeenCalledWith(
        expect.stringContaining('1 ecosystem(s): python')
      );

      // Verify the projectAiContext property was set
      expect((validationMode as any).projectAiContext).toBe(
        'Fallback sqlite3 (stdlib) configured. Behavior may differ from postgresql.'
      );
    });
  });

  describe('setup command execution', () => {
    it('should execute setup commands in order with correct cwd', async () => {
      mockRetrievePhaseResults.mockResolvedValue({
        project_shape: {
          ecosystem: 'python',
          runtime_services: [{ kind: 'sql_database', package: 'django', resolution: 'in_process_fallback' }],
          setup_commands: ['python manage.py migrate', 'python manage.py collectstatic --noinput'],
          env: { DJANGO_SETTINGS_MODULE: 'myproject.settings' },
          ai_context: 'Test context'
        }
      });

      try {
        await validationMode.validateVulnerability(mockIssue);
      } catch {
        // Expected
      }

      const migrateCalls = mockExecSync.mock.calls.filter(
        (call: unknown[]) => typeof call[0] === 'string' && (call[0] as string).includes('manage.py')
      );
      expect(migrateCalls.length).toBe(2);
      expect(migrateCalls[0][0]).toBe('python manage.py migrate');
      expect(migrateCalls[1][0]).toBe('python manage.py collectstatic --noinput');

      // Both should use the repo path as cwd
      for (const call of migrateCalls) {
        const opts = call[1] as { cwd?: string };
        expect(opts.cwd).toBe('/tmp/test-repo');
      }
    });

    it('should continue execution if a setup command fails', async () => {
      // Make the first rake command fail, but allow others
      mockExecSync.mockImplementation((cmd: string) => {
        if (typeof cmd === 'string' && cmd.includes('db:create')) {
          throw new Error('rake aborted: database already exists');
        }
        return 'test-commit-hash';
      });

      mockRetrievePhaseResults.mockResolvedValue({
        project_shape: {
          ecosystem: 'ruby',
          runtime_services: [],
          setup_commands: ['bundle exec rake db:create', 'bundle exec rake db:schema:load'],
          env: { RAILS_ENV: 'test' },
          ai_context: 'Test'
        }
      });

      try {
        await validationMode.validateVulnerability(mockIssue);
      } catch {
        // Expected
      }

      // Both commands should have been attempted even though first failed
      const rakeCalls = mockExecSync.mock.calls.filter(
        (call: unknown[]) => typeof call[0] === 'string' && (call[0] as string).includes('bundle exec')
      );
      expect(rakeCalls.length).toBe(2);

      // Warning logged for failure
      expect(logger.warn).toHaveBeenCalledWith(
        expect.stringContaining('Setup command warning: bundle exec rake db:create')
      );

      // Second command still executed
      expect(logger.info).toHaveBeenCalledWith(
        expect.stringContaining('Setup command succeeded: bundle exec rake db:schema:load')
      );
    });
  });

  describe('no phase data graceful degradation', () => {
    it('should continue without project shape when phase data returns null', async () => {
      mockRetrievePhaseResults.mockResolvedValue(null);

      try {
        await validationMode.validateVulnerability(mockIssue);
      } catch {
        // Expected — fails later, not at RFC-101
      }

      // No RFC-101 log messages about project shape
      expect(logger.info).not.toHaveBeenCalledWith(
        expect.stringContaining('Project shape detected')
      );
    });

    it('should continue without project shape when phase data has no project_shape', async () => {
      mockRetrievePhaseResults.mockResolvedValue({
        some_other_field: 'data'
      });

      try {
        await validationMode.validateVulnerability(mockIssue);
      } catch {
        // Expected
      }

      expect(logger.info).not.toHaveBeenCalledWith(
        expect.stringContaining('Project shape detected')
      );
    });

    it('should handle retrievePhaseResults throwing an error', async () => {
      mockRetrievePhaseResults.mockRejectedValue(new Error('Network error'));

      try {
        await validationMode.validateVulnerability(mockIssue);
      } catch {
        // Expected
      }

      // Should log warning but continue
      expect(logger.warn).toHaveBeenCalledWith(
        expect.stringContaining('Project shape retrieval warning')
      );
    });
  });

  describe('multi-ecosystem project_shapes array', () => {
    it('should merge ai_context from multiple shapes', async () => {
      mockRetrievePhaseResults.mockResolvedValue({
        project_shapes: [
          {
            ecosystem: 'php',
            runtime_services: [{ kind: 'sql_database', package: 'laravel/framework', resolution: 'in_process_fallback' }],
            setup_commands: ['php artisan migrate'],
            env: {},
            ai_context: 'PHP: Fallback PDO SQLite configured.'
          },
          {
            ecosystem: 'javascript',
            runtime_services: [{ kind: 'document_store', package: 'mongoose', resolution: 'unavailable' }],
            setup_commands: ['npm install'],
            env: {},
            ai_context: 'JS: No MongoDB service running. Write STANDALONE tests.'
          }
        ],
        project_shape: {
          ecosystem: 'php',
          runtime_services: [{ kind: 'sql_database', package: 'laravel/framework', resolution: 'in_process_fallback' }],
          setup_commands: ['php artisan migrate'],
          env: {},
          ai_context: 'PHP: Fallback PDO SQLite configured.'
        }
      });

      try {
        await validationMode.validateVulnerability(mockIssue);
      } catch {
        // Expected
      }

      // ai_context should contain context from BOTH ecosystems
      const aiContext = (validationMode as any).projectAiContext as string;
      expect(aiContext).toContain('PHP: Fallback PDO SQLite configured.');
      expect(aiContext).toContain('JS: No MongoDB service running.');
    });

    it('should collect and execute setup commands from all shapes', async () => {
      mockRetrievePhaseResults.mockResolvedValue({
        project_shapes: [
          {
            ecosystem: 'ruby',
            runtime_services: [],
            setup_commands: ['bundle exec rake db:create'],
            env: { RAILS_ENV: 'test' },
            ai_context: 'Ruby context'
          },
          {
            ecosystem: 'javascript',
            runtime_services: [],
            setup_commands: ['npm install', 'npx prisma migrate deploy'],
            env: { NODE_ENV: 'test' },
            ai_context: 'JS context'
          }
        ],
        project_shape: {
          ecosystem: 'ruby',
          runtime_services: [],
          setup_commands: ['bundle exec rake db:create'],
          env: { RAILS_ENV: 'test' },
          ai_context: 'Ruby context'
        }
      });

      try {
        await validationMode.validateVulnerability(mockIssue);
      } catch {
        // Expected
      }

      // All 3 setup commands should have been attempted
      const setupCalls = mockExecSync.mock.calls.filter(
        (call: unknown[]) => typeof call[0] === 'string' && (
          (call[0] as string).includes('bundle exec') ||
          (call[0] as string).includes('npm install') ||
          (call[0] as string).includes('npx prisma')
        )
      );
      expect(setupCalls.length).toBe(3);
    });

    it('should merge env vars from all shapes', async () => {
      mockRetrievePhaseResults.mockResolvedValue({
        project_shapes: [
          {
            ecosystem: 'ruby',
            runtime_services: [],
            setup_commands: [],
            env: { RAILS_ENV: 'test', BUNDLE_WITHOUT: 'production' },
            ai_context: ''
          },
          {
            ecosystem: 'javascript',
            runtime_services: [],
            setup_commands: [],
            env: { NODE_ENV: 'test' },
            ai_context: ''
          }
        ],
        project_shape: {
          ecosystem: 'ruby',
          runtime_services: [],
          setup_commands: [],
          env: { RAILS_ENV: 'test', BUNDLE_WITHOUT: 'production' },
          ai_context: ''
        }
      });

      try {
        await validationMode.validateVulnerability(mockIssue);
      } catch {
        // Expected
      }

      // All env vars from all shapes should be applied
      expect(process.env.RAILS_ENV).toBe('test');
      expect(process.env.BUNDLE_WITHOUT).toBe('production');
      expect(process.env.NODE_ENV).toBe('test');
    });

    it('should log all detected ecosystems', async () => {
      mockRetrievePhaseResults.mockResolvedValue({
        project_shapes: [
          {
            ecosystem: 'php',
            runtime_services: [{ kind: 'sql_database' }],
            setup_commands: [],
            env: {},
            ai_context: 'PHP context'
          },
          {
            ecosystem: 'javascript',
            runtime_services: [],
            setup_commands: [],
            env: {},
            ai_context: 'JS context'
          }
        ],
        project_shape: {
          ecosystem: 'php',
          runtime_services: [{ kind: 'sql_database' }],
          setup_commands: [],
          env: {},
          ai_context: 'PHP context'
        }
      });

      try {
        await validationMode.validateVulnerability(mockIssue);
      } catch {
        // Expected
      }

      // Should log multi-ecosystem detection with all ecosystems
      expect(logger.info).toHaveBeenCalledWith(
        expect.stringContaining('2 ecosystem(s)')
      );
      expect(logger.info).toHaveBeenCalledWith(
        expect.stringContaining('php')
      );
      expect(logger.info).toHaveBeenCalledWith(
        expect.stringContaining('javascript')
      );
    });

    it('should fall back to single project_shape when project_shapes is absent', async () => {
      // Backward compat: old phase data only has project_shape (single)
      mockRetrievePhaseResults.mockResolvedValue({
        project_shape: {
          ecosystem: 'ruby',
          runtime_services: [{ kind: 'sql_database', package: 'rails', resolution: 'in_process_native' }],
          setup_commands: ['bundle exec rake db:create'],
          env: { RAILS_ENV: 'test' },
          ai_context: 'SQLite configured.'
        }
        // no project_shapes field
      });

      try {
        await validationMode.validateVulnerability(mockIssue);
      } catch {
        // Expected
      }

      // Should still work with single shape
      expect((validationMode as any).projectAiContext).toBe('SQLite configured.');
      expect(process.env.RAILS_ENV).toBe('test');

      const rakeCalls = mockExecSync.mock.calls.filter(
        (call: unknown[]) => typeof call[0] === 'string' && (call[0] as string).includes('bundle exec')
      );
      expect(rakeCalls.length).toBe(1);
    });
  });
});
