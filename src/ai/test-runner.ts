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
  private readonly MISE_QUICK_TIMEOUT = 300000; // 5 minutes for mise install before fallback (RFC-101 M2)
  // Note: For faster builds, configure GitHub Actions cache for ~/.local/share/mise
  // Or configure mise to use prebuilt binaries: mise settings set ruby_binary_url ...
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

          // CRITICAL: Update PATH immediately after Erlang installation
          // so that Elixir's installation can find 'erl' for its version check
          const homedir = process.env.HOME || '/root';
          const miseShims = `${homedir}/.local/share/mise/shims`;
          const miseBin = `${homedir}/.local/bin`;
          const currentPath = process.env.PATH || '';
          if (!currentPath.includes(miseShims)) {
            process.env.PATH = `${miseShims}:${miseBin}:${currentPath}`;
            console.log(`[TestRunner] Updated PATH after Erlang install: ${miseShims}`);
          }
        } catch (erlErr) {
          console.warn(`[TestRunner] Erlang install failed: ${(erlErr as Error).message}`);
          // Continue anyway, maybe Elixir has a bundled Erlang or will work
        }
      }
    }

    // For PHP and Java, try apt-get first since mise requires build dependencies
    // that may not be available in the Docker image.
    // Note: We run as root in the Docker container, so no sudo needed.
    // Exception: If a specific PHP version is required (from composer.json), use mise.
    if (runtime === 'php') {
      const requiredVersion = await this.detectPhpVersionFromComposer(workingDir);
      if (requiredVersion) {
        // Specific version required - skip apt-get, use mise for version matching
        console.log(`[TestRunner] PHP ${requiredVersion} required by composer.json - using mise for version matching`);
      } else {
        // No specific version - apt-get is faster
        console.log(`[TestRunner] Trying apt-get for PHP + Composer (faster than building from source)`);
        try {
          const { stdout, stderr } = await execAsync(
            `apt-get update && apt-get install -y php php-cli php-xml php-mbstring php-curl php-zip unzip composer`,
            { cwd: workingDir, timeout: 120000, encoding: 'utf8' }
          );
          console.log(`[TestRunner] apt-get output: ${stdout}`);
          if (stderr) console.log(`[TestRunner] apt-get stderr: ${stderr}`);
          // Verify installation
          await execAsync(`which php`, { encoding: 'utf8' });
          console.log(`[TestRunner] PHP installed via apt-get`);
          return; // Success, no need for mise
        } catch (aptErr) {
          const err = aptErr as { stderr?: string; message?: string };
          console.log(`[TestRunner] apt-get PHP failed: ${err.stderr || err.message}`);
          console.log(`[TestRunner] Will try mise as fallback`);
        }
      }
    }

    if (runtime === 'java') {
      console.log(`[TestRunner] Trying apt-get for Java + Maven (faster than building from source)`);
      try {
        const { stdout, stderr } = await execAsync(
          `apt-get update && apt-get install -y default-jdk maven`,
          { cwd: workingDir, timeout: 180000, encoding: 'utf8' }
        );
        console.log(`[TestRunner] apt-get output: ${stdout}`);
        if (stderr) console.log(`[TestRunner] apt-get stderr: ${stderr}`);
        // Verify installation
        await execAsync(`which javac && which mvn`, { encoding: 'utf8' });
        console.log(`[TestRunner] Java + Maven installed via apt-get`);
        return; // Success, no need for mise
      } catch (aptErr) {
        const err = aptErr as { stderr?: string; message?: string };
        console.log(`[TestRunner] apt-get Java failed: ${err.stderr || err.message}`);
        console.log(`[TestRunner] Will try mise as fallback`);
      }
    }

    // Determine version from project files
    const version = await this.detectRuntimeVersion(runtime, workingDir);
    const runtimeSpec = version ? `${runtime}@${version}` : `${runtime}@latest`;

    console.log(`[TestRunner] Installing runtime: ${runtimeSpec} via mise`);

    try {
      // For Elixir, prepend the mise shims PATH to the command so that 'erl' is found
      // during Elixir's installation verification step (which spawns its own subprocess)
      let installCmd = `mise install ${runtimeSpec} && mise use --global ${runtimeSpec}`;
      if (runtime === 'elixir') {
        const homedir = process.env.HOME || '/root';
        const miseShims = `${homedir}/.local/share/mise/shims`;
        installCmd = `PATH="${miseShims}:$PATH" ${installCmd}`;
        console.log(`[TestRunner] Using PATH prefix for Elixir install: ${miseShims}`);
      }

      // RFC-101 Iteration 15 M2: Use shorter timeout for mise, fall back to apt-get on timeout
      // This prevents hanging on slow builds (e.g., PHP 7.1 from source)
      const miseTimeout = version ? this.MISE_QUICK_TIMEOUT : this.RUNTIME_INSTALL_TIMEOUT;

      const { stdout, stderr } = await execAsync(
        installCmd,
        { cwd: workingDir, timeout: miseTimeout, encoding: 'utf8' }
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

      // For PHP installed via mise, also install Composer
      if (runtime === 'php') {
        console.log(`[TestRunner] Installing Composer for mise PHP`);
        try {
          // Install Composer via official installer
          await execAsync(
            `curl -sS https://getcomposer.org/installer | php -- --install-dir=/usr/local/bin --filename=composer`,
            { cwd: workingDir, timeout: 60000, encoding: 'utf8' }
          );
          console.log(`[TestRunner] Composer installed successfully`);
        } catch (composerErr) {
          console.warn(`[TestRunner] Composer install warning: ${(composerErr as Error).message}`);
        }
      }
    } catch (error: unknown) {
      const execError = error as { stderr?: string; message?: string; killed?: boolean };
      const isTimeout = execError.killed || (execError.message && execError.message.includes('TIMEOUT'));
      const errorMsg = execError.stderr || execError.message || String(error);
      console.warn(`[TestRunner] mise install failed: ${errorMsg.slice(0, 200)}`);

      // RFC-101 v3.8.68: Fall back to apt-get for ANY mise failure (not just timeout)
      // Common failures: no prebuilt binary, build fails, missing deps, timeout
      // This ensures runtimes are available even when mise can't provide them
      if (runtime === 'php' || runtime === 'ruby' || runtime === 'python') {
        const reason = isTimeout ? `timed out after ${this.MISE_QUICK_TIMEOUT}ms` : 'failed';
        console.warn(`[TestRunner] mise install ${reason} - falling back to apt-get`);
        console.warn(`[TestRunner] Note: System version may differ from project's required ${runtimeSpec}`);

        const aptPackages: Record<string, string> = {
          php: 'php php-cli php-xml php-mbstring php-curl php-zip unzip composer',
          ruby: 'ruby ruby-dev bundler',
          python: 'python3 python3-pip python3-venv'
        };

        try {
          const { stdout, stderr } = await execAsync(
            `apt-get update && apt-get install -y ${aptPackages[runtime]}`,
            { cwd: workingDir, timeout: 120000, encoding: 'utf8' }
          );
          console.log(`[TestRunner] apt-get fallback output: ${stdout}`);
          if (stderr) console.log(`[TestRunner] apt-get fallback stderr: ${stderr}`);
          // Verify installation
          await execAsync(`which ${runtime === 'python' ? 'python3' : runtime}`, { encoding: 'utf8' });
          console.log(`[TestRunner] ${runtime} installed via apt-get fallback (may differ from project version)`);
          return; // Success via fallback
        } catch (aptErr) {
          const aptError = aptErr as { stderr?: string; message?: string };
          // Both mise and apt-get failed
          throw new Error(
            `mise install ${runtimeSpec} timed out and apt-get fallback failed: ${aptError.stderr || aptError.message}`
          );
        }
      }

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

    // For PHP, also check composer.json for version requirements
    if (runtime === 'php') {
      const phpVersion = await this.detectPhpVersionFromComposer(workingDir);
      if (phpVersion) return phpVersion;
    }

    return undefined;
  }

  /**
   * Detect PHP version from composer.json require.php constraint.
   * Converts constraints like "^7.1.3" or ">=7.2" to a mise-compatible version.
   */
  private async detectPhpVersionFromComposer(workingDir: string): Promise<string | undefined> {
    try {
      const composerPath = path.join(workingDir, 'composer.json');
      const content = await fs.readFile(composerPath, 'utf8');
      const composer = JSON.parse(content);
      const phpConstraint = composer?.require?.php;

      if (!phpConstraint) return undefined;

      // Extract major.minor version from constraint
      // "^7.1.3" -> "7.1", ">=7.2" -> "7.2", "~8.0" -> "8.0"
      const match = phpConstraint.match(/(\d+)\.(\d+)/);
      if (match) {
        const major = match[1];
        const minor = match[2];
        // Return latest patch for this major.minor
        console.log(`[TestRunner] Detected PHP ${major}.${minor} requirement from composer.json`);
        return `${major}.${minor}`;
      }
    } catch {
      // composer.json doesn't exist or isn't valid JSON
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
      // RFC-101 v3.8.67: Set BUNDLE_IGNORE_RUBY_VERSION=1 to handle apt-get fallback Ruby
      // version mismatch (e.g., Gemfile says ruby "3.4.1" but system has 3.2.x)
      if (await this.fileExists(path.join(workingDir, 'Gemfile'))) {
        return 'BUNDLE_IGNORE_RUBY_VERSION=1 bundle install';
      }
      return null;
    }
    case 'pytest': {
      // Python: pip install
      // RFC-101 v3.8.68: Install system libs commonly needed by Python packages (Pillow, etc.)
      // before pip install to prevent build failures. Also ensure pytest is installed.
      const sysDeps = 'apt-get update && apt-get install -y --no-install-recommends libjpeg-dev libpng-dev libfreetype-dev 2>/dev/null || true';
      const ensurePytest = 'pip install pytest';
      if (await this.fileExists(path.join(workingDir, 'requirements.txt'))) {
        // Install deps first (may fail on some packages), then ensure pytest is available
        return `${sysDeps} && (pip install -r requirements.txt || echo "Some deps failed, continuing...") && ${ensurePytest}`;
      }
      if (await this.fileExists(path.join(workingDir, 'pyproject.toml'))) {
        return `${sysDeps} && (pip install -e . || echo "Install failed, continuing...") && ${ensurePytest}`;
      }
      if (await this.fileExists(path.join(workingDir, 'setup.py'))) {
        return `${sysDeps} && (pip install -e . || echo "Install failed, continuing...") && ${ensurePytest}`;
      }
      // No manifest - just install pytest
      return ensurePytest;
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
      // Ruby (BUNDLE_IGNORE_RUBY_VERSION=1 handles apt-get fallback version mismatch)
      rspec: { base: 'BUNDLE_IGNORE_RUBY_VERSION=1 bundle exec rspec', testNameFlag: '-e' },
      minitest: { base: 'BUNDLE_IGNORE_RUBY_VERSION=1 ruby', testNameFlag: '-n' },
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
   * RFC-101 v3.8.68: Special handling for Maven/JUnit - use -Dtest=ClassName format
   */
  private buildCommandFromPattern(
    pattern: CommandPattern,
    testFile: string,
    testName?: string
  ): string {
    // Special handling for Maven-based frameworks (JUnit)
    // Maven expects: mvn test -Dtest=ClassName, not mvn test /path/to/Test.java
    if (pattern.base.startsWith('mvn ')) {
      // Extract class name from file path
      // e.g., src/test/java/org/example/MyTest.java -> MyTest
      // e.g., src/it/java/org/owasp/webgoat/integration/ChallengeIntegrationTest.java -> ChallengeIntegrationTest
      const fileName = testFile.split('/').pop() || testFile;
      const className = fileName.replace(/\.java$/, '');
      let cmd = `${pattern.base} ${pattern.testNameFlag}="${className}"`;
      if (testName) {
        // For specific test method: -Dtest=ClassName#methodName
        cmd = `${pattern.base} ${pattern.testNameFlag}="${className}#${testName}"`;
      }
      return cmd;
    }

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
