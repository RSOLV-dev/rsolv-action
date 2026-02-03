/**
 * TestRunner - Executes framework-specific test commands
 */

import { exec } from 'child_process';
import { promisify } from 'util';
import * as fs from 'fs/promises';
import * as path from 'path';

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
  | 'junit5'  // JUnit 5 (also maps to java runtime)
  | 'junit4'  // JUnit 4 (also maps to java runtime)
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
 * Map from test framework to the runtime binary name needed
 */
const FRAMEWORK_RUNTIME_MAP: Record<TestFramework, string> = {
  jest: 'node',
  vitest: 'node',
  mocha: 'node',
  rspec: 'ruby',
  minitest: 'ruby',
  pytest: 'python',
  phpunit: 'php',
  junit: 'java',
  junit5: 'java',   // JUnit 5 uses Java runtime
  junit4: 'java',   // JUnit 4 uses Java runtime
  testing: 'go',
  exunit: 'elixir',
};

/**
 * Version files that mise can read to determine runtime version
 */
const VERSION_FILES: Record<string, string[]> = {
  ruby: ['.ruby-version', '.tool-versions'],
  python: ['.python-version', '.tool-versions'],
  node: ['.node-version', '.nvmrc', '.tool-versions'],
  java: ['.java-version', '.tool-versions'],
  go: ['.go-version', '.tool-versions'],
  elixir: ['.tool-versions'],
  php: ['.php-version', '.tool-versions'],
};

/**
 * TestRunner executes framework-specific test commands with timeout handling
 */
export class TestRunner {
  private readonly DEFAULT_TIMEOUT = 30000; // 30 seconds
  private readonly RUNTIME_INSTALL_TIMEOUT = 600000; // 10 minutes for runtime install (Ruby compiles from source)
  private readonly DEP_INSTALL_TIMEOUT = 180000; // 3 minutes for dependency install

  /**
   * Run tests using specified framework
   */
  async runTests(config: TestRunConfig): Promise<TestRunResult> {
    const timeout = config.timeout ?? this.DEFAULT_TIMEOUT;

    // Ensure the required runtime is available (e.g., ruby for rspec)
    try {
      await this.ensureRuntime(config.framework, config.workingDir);
    } catch (error: unknown) {
      const message = error instanceof Error ? error.message : String(error);
      return this.createResult(
        false, '', '', false, undefined,
        `Failed to install runtime for ${config.framework}: ${message}`
      );
    }

    // Install project dependencies before running tests
    try {
      await this.ensureDependencies(config.framework, config.workingDir);
    } catch (error: unknown) {
      const message = error instanceof Error ? error.message : String(error);
      return this.createResult(
        false, '', '', false, undefined,
        `Failed to install dependencies for ${config.framework}: ${message}`
      );
    }

    const command = this.buildCommand(config);

    try {
      const { stdout, stderr } = await execAsync(command, {
        cwd: config.workingDir,
        timeout,
        encoding: 'utf8'
      });

      // Test passed (exit code 0)
      return this.createResult(true, stdout, stderr, false, 0);
    } catch (error: unknown) {
      const execError = error as { killed?: boolean; signal?: string; stdout?: string; stderr?: string; code?: number; message?: string };
      // Check if timeout
      if (execError.killed || execError.signal === 'SIGTERM') {
        return this.createResult(
          false,
          execError.stdout || '',
          execError.stderr || '',
          true,
          execError.code,
          'Test execution timed out'
        );
      }

      // Test failed (non-zero exit code) or execution error
      return this.createResult(
        false,
        execError.stdout || '',
        execError.stderr || '',
        false,
        execError.code,
        execError.message
      );
    }
  }

  /**
   * Ensure the runtime for a given framework is available.
   * Uses mise to install on-demand if not already present.
   */
  async ensureRuntime(framework: TestFramework, workingDir: string): Promise<void> {
    const runtime = FRAMEWORK_RUNTIME_MAP[framework];

    // Node is always available in our Docker image
    if (runtime === 'node') return;

    // Check if runtime is already available
    try {
      await execAsync(`which ${runtime}`, { encoding: 'utf8' });
      return; // Runtime already present
    } catch {
      // Not found, need to install
    }

    // Handle Elixir's dependency on Erlang - must install Erlang first
    if (runtime === 'elixir') {
      console.log(`[TestRunner] Elixir requires Erlang - installing Erlang first`);
      try {
        await execAsync(`which erl`, { encoding: 'utf8' });
        console.log(`[TestRunner] Erlang already available`);
      } catch {
        // Install Erlang via mise
        console.log(`[TestRunner] Installing Erlang via mise`);
        try {
          await execAsync(
            `mise install erlang@latest && mise use --global erlang@latest`,
            { cwd: workingDir, timeout: this.RUNTIME_INSTALL_TIMEOUT, encoding: 'utf8' }
          );
          console.log(`[TestRunner] Erlang installed successfully`);
        } catch (erlErr) {
          console.warn(`[TestRunner] Erlang install failed: ${(erlErr as Error).message}`);
          // Continue anyway, maybe Elixir has a bundled Erlang or will work
        }
      }
    }

    // Determine version from project files
    const version = await this.detectRuntimeVersion(runtime, workingDir);
    const runtimeSpec = version ? `${runtime}@${version}` : `${runtime}@latest`;

    console.log(`[TestRunner] Installing runtime: ${runtimeSpec} via mise`);

    try {
      const { stdout, stderr } = await execAsync(
        `mise install ${runtimeSpec} && mise use --global ${runtimeSpec}`,
        { cwd: workingDir, timeout: this.RUNTIME_INSTALL_TIMEOUT, encoding: 'utf8' }
      );
      console.log(`[TestRunner] Runtime installed: ${stdout}`);
      if (stderr) console.log(`[TestRunner] Runtime install stderr: ${stderr}`);

      // Ensure mise shims and install paths are on the current process PATH
      // so subsequent execSync calls (syntax check, test run) can find the binary
      const homedir = process.env.HOME || '/root';
      const miseShims = `${homedir}/.local/share/mise/shims`;
      const miseBin = `${homedir}/.local/bin`;
      const currentPath = process.env.PATH || '';
      if (!currentPath.includes(miseShims)) {
        process.env.PATH = `${miseShims}:${miseBin}:${currentPath}`;
        console.log(`[TestRunner] Updated PATH to include mise shims: ${miseShims}`);
      }
    } catch (error: unknown) {
      const execError = error as { stderr?: string; message?: string };
      throw new Error(
        `mise install ${runtimeSpec} failed: ${execError.stderr || execError.message}`
      );
    }
  }

  /**
   * Detect the runtime version from project version files.
   * Returns the version string or undefined if no version file found.
   */
  private async detectRuntimeVersion(runtime: string, workingDir: string): Promise<string | undefined> {
    const versionFiles = VERSION_FILES[runtime] || [];

    for (const versionFile of versionFiles) {
      try {
        const filePath = path.join(workingDir, versionFile);
        const content = (await fs.readFile(filePath, 'utf8')).trim();

        if (versionFile === '.tool-versions') {
          // .tool-versions format: "ruby 3.2.2\npython 3.11.0"
          const match = content.match(new RegExp(`^${runtime}\\s+(.+)$`, 'm'));
          if (match) return match[1].trim();
        } else {
          // Simple version files contain just the version
          return content;
        }
      } catch {
        // File doesn't exist, try next
      }
    }
    return undefined;
  }

  /**
   * Install project dependencies for the given framework.
   * Runs the appropriate package manager command from the repo root.
   */
  async ensureDependencies(framework: TestFramework, workingDir: string): Promise<void> {
    const depCommand = await this.getDependencyCommand(framework, workingDir);
    if (!depCommand) return; // No dependency install needed

    console.log(`[TestRunner] Installing dependencies: ${depCommand}`);

    try {
      const { stdout, stderr } = await execAsync(depCommand, {
        cwd: workingDir,
        timeout: this.DEP_INSTALL_TIMEOUT,
        encoding: 'utf8',
      });
      console.log(`[TestRunner] Dependencies installed: ${stdout.slice(0, 500)}`);
      if (stderr) console.log(`[TestRunner] Dep install stderr: ${stderr.slice(0, 500)}`);
    } catch (error: unknown) {
      const execError = error as { stderr?: string; message?: string };
      // Log but don't fail — dependency install failures may be recoverable
      console.warn(
        `[TestRunner] Dependency install warning: ${execError.stderr || execError.message}`
      );
    }
  }

  /**
   * Get the dependency install command for a given framework.
   * Returns null if no install is needed or deps are already present.
   */
  private async getDependencyCommand(framework: TestFramework, workingDir: string): Promise<string | null> {
    switch (framework) {
    case 'rspec':
    case 'minitest': {
      // Ruby: bundle install (if Gemfile exists)
      // Always run bundle install even if vendor/bundle exists — the gems may have been
      // compiled for a different Ruby version (e.g., host runner's Ruby vs mise-installed Ruby).
      // Bundler handles idempotency and will recompile native extensions if needed.
      if (await this.fileExists(path.join(workingDir, 'Gemfile'))) {
        return 'bundle install';
      }
      return null;
    }
    case 'pytest': {
      // Python: pip install
      if (await this.fileExists(path.join(workingDir, 'requirements.txt'))) {
        return 'pip install -r requirements.txt';
      }
      if (await this.fileExists(path.join(workingDir, 'pyproject.toml'))) {
        return 'pip install -e .';
      }
      if (await this.fileExists(path.join(workingDir, 'setup.py'))) {
        return 'pip install -e .';
      }
      return null;
    }
    case 'phpunit': {
      if (await this.fileExists(path.join(workingDir, 'composer.json'))) {
        if (await this.fileExists(path.join(workingDir, 'vendor', 'autoload.php'))) return null;
        return 'composer install --no-dev';
      }
      return null;
    }
    case 'junit': {
      // Maven handles deps during test execution
      return null;
    }
    case 'exunit': {
      if (await this.fileExists(path.join(workingDir, 'mix.exs'))) {
        return 'mix deps.get && mix deps.compile';
      }
      return null;
    }
    case 'testing': {
      if (await this.fileExists(path.join(workingDir, 'go.mod'))) {
        return 'go mod download';
      }
      return null;
    }
    case 'jest':
    case 'vitest':
    case 'mocha': {
      // Node: check for lock files
      if (await this.fileExists(path.join(workingDir, 'node_modules'))) return null;
      if (await this.fileExists(path.join(workingDir, 'bun.lockb'))) return 'bun install';
      if (await this.fileExists(path.join(workingDir, 'package-lock.json'))) return 'npm ci';
      if (await this.fileExists(path.join(workingDir, 'yarn.lock'))) return 'yarn install --frozen-lockfile';
      if (await this.fileExists(path.join(workingDir, 'package.json'))) return 'npm install';
      return null;
    }
    default:
      return null;
    }
  }

  /**
   * Check if a file or directory exists
   */
  private async fileExists(filePath: string): Promise<boolean> {
    try {
      await fs.access(filePath);
      return true;
    } catch {
      return false;
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
      junit5: { base: 'mvn test', testNameFlag: '-Dtest' },
      junit4: { base: 'mvn test', testNameFlag: '-Dtest' },
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
