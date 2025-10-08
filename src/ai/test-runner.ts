/**
 * TestRunner - Executes framework-specific test commands
 */

import { exec } from 'child_process';
import { promisify } from 'util';

const execAsync = promisify(exec);

/**
 * Supported test frameworks
 */
export type TestFramework =
  // JavaScript/TypeScript
  | 'jest'
  | 'vitest'
  | 'mocha'
  // Ruby
  | 'rspec'
  | 'minitest'
  // Python
  | 'pytest'
  // PHP
  | 'phpunit'
  // Java
  | 'junit'
  // Go
  | 'testing'
  // Elixir
  | 'exunit';

/**
 * Command pattern for framework
 */
interface CommandPattern {
  /** Base command to run */
  base: string;
  /** Flag for specifying test name */
  testNameFlag: string;
}

/**
 * Test run configuration
 */
export interface TestRunConfig {
  /** Test framework to use */
  framework: TestFramework;
  /** Path to test file */
  testFile: string;
  /** Name/pattern of specific test to run */
  testName?: string;
  /** Working directory for test execution */
  workingDir: string;
  /** Timeout in milliseconds (default: 30000) */
  timeout?: number;
}

/**
 * Test execution result
 */
export interface TestRunResult {
  /** Whether test passed */
  passed: boolean;
  /** Combined stdout output */
  output: string;
  /** stderr output */
  stderr: string;
  /** Whether execution timed out */
  timedOut: boolean;
  /** Exit code from process */
  exitCode?: number;
  /** Error information if execution failed */
  error?: string;
}

/**
 * TestRunner executes framework-specific test commands with timeout handling
 */
export class TestRunner {
  private readonly DEFAULT_TIMEOUT = 30000; // 30 seconds

  /**
   * Run tests using specified framework
   */
  async runTests(config: TestRunConfig): Promise<TestRunResult> {
    const timeout = config.timeout ?? this.DEFAULT_TIMEOUT;
    const command = this.buildCommand(config);

    try {
      const { stdout, stderr } = await execAsync(command, {
        cwd: config.workingDir,
        timeout,
        encoding: 'utf8'
      });

      // Test passed (exit code 0)
      return this.createResult(true, stdout, stderr, false, 0);
    } catch (error: any) {
      // Check if timeout
      if (error.killed || error.signal === 'SIGTERM') {
        return this.createResult(
          false,
          error.stdout || '',
          error.stderr || '',
          true,
          error.code,
          'Test execution timed out'
        );
      }

      // Test failed (non-zero exit code) or execution error
      return this.createResult(
        false,
        error.stdout || '',
        error.stderr || '',
        false,
        error.code,
        error.message
      );
    }
  }

  /**
   * Build framework-specific command
   */
  private buildCommand(config: TestRunConfig): string {
    const { framework, testFile, testName } = config;
    const pattern = this.getCommandPattern(framework);
    return this.buildCommandFromPattern(pattern, testFile, testName);
  }

  /**
   * Get command pattern for framework
   */
  private getCommandPattern(framework: TestFramework): CommandPattern {
    const patterns: Record<TestFramework, CommandPattern> = {
      // JavaScript/TypeScript
      jest: { base: 'npx jest', testNameFlag: '-t' },
      vitest: { base: 'npx vitest run', testNameFlag: '-t' },
      mocha: { base: 'npx mocha', testNameFlag: '--grep' },
      // Ruby
      rspec: { base: 'bundle exec rspec', testNameFlag: '-e' },
      minitest: { base: 'ruby', testNameFlag: '-n' },
      // Python
      pytest: { base: 'pytest', testNameFlag: '-k' },
      // PHP
      phpunit: { base: 'vendor/bin/phpunit', testNameFlag: '--filter' },
      // Java
      junit: { base: 'mvn test', testNameFlag: '-Dtest' },
      // Go
      testing: { base: 'go test', testNameFlag: '-run' },
      // Elixir
      exunit: { base: 'mix test', testNameFlag: '--only' }
    };

    const pattern = patterns[framework];
    if (!pattern) {
      throw new Error(`Unsupported test framework: ${framework}`);
    }
    return pattern;
  }

  /**
   * Build command from pattern
   */
  private buildCommandFromPattern(
    pattern: CommandPattern,
    testFile: string,
    testName?: string
  ): string {
    let cmd = `${pattern.base} "${testFile}"`;
    if (testName) {
      cmd += ` ${pattern.testNameFlag} "${testName}"`;
    }
    return cmd;
  }

  /**
   * Create result object from execution output
   */
  private createResult(
    passed: boolean,
    output: string,
    stderr: string,
    timedOut: boolean,
    exitCode?: number,
    error?: string
  ): TestRunResult {
    return {
      passed,
      output,
      stderr,
      timedOut,
      exitCode,
      error
    };
  }
}
