import { SafeDetector } from '../security/safe-detector.js';
import { getGitHubClient } from '../github/api.js';
import { logger } from '../utils/logger.js';
import type { FileToScan, ScanConfig, ScanResult, VulnerabilityGroup } from './types.js';
import type { Vulnerability } from '../security/types.js';
import { createPatternSource } from '../security/pattern-source.js';
import { ASTValidator } from './ast-validator.js';
import { VendorDetector } from '../vendor/vendor-detector.js';
import { SEVERITY_PRIORITY } from '../security/severity.js';

export class RepositoryScanner {
  private detector: SafeDetector;
  private github: ReturnType<typeof getGitHubClient>;
  private vendorDetector: VendorDetector;

  /**
   * Directories that contain non-production code (tests, artifacts, build scripts).
   * Vulnerabilities in these files are not actionable for production security.
   */
  private static readonly NON_PRODUCTION_DIRS = [
    'test/',
    'tests/',
    '__tests__/',
    '__test__/',
    'spec/',
    'specs/',
    'artifacts/',
    'fixtures/',
    'test-fixtures/',
    '__fixtures__/',
    '__mocks__/',
    'mocks/',
  ];

  /**
   * Directories that typically contain configuration files.
   * Vulnerabilities in these files get a 0.5x confidence multiplier
   * (aligned with backend file_path_classifier.ex).
   */
  private static readonly CONFIG_DIRS = [
    'config/',
    '.config/',
    'configs/',
  ];

  /**
   * File name patterns for configuration files.
   * Matched against the filename (basename) portion of the path.
   */
  private static readonly CONFIG_FILE_PATTERNS = [
    /\.config\.\w+$/,
    /\.env\.\w+$/,
    /^tsconfig.*\.json$/,
  ];

  /**
   * RFC-101: Manifest and config files to capture for project shape detection.
   * Contents are included in phase data so the platform can classify the project
   * ecosystem and determine runtime service dependencies.
   */
  private static readonly MANIFEST_FILES = [
    'Gemfile', 'config/database.yml',                        // Ruby
    'package.json',                                          // JavaScript/TypeScript
    'requirements.txt', 'pyproject.toml', 'setup.py',       // Python
    'setup.cfg',                                             // Python
    'mix.exs', 'config/dev.exs', 'config/test.exs',        // Elixir
    'pom.xml', 'build.gradle',                              // Java
    'composer.json',                                         // PHP
  ];

  /**
   * File name patterns for non-production files (test files, build configs, scripts).
   */
  private static readonly NON_PRODUCTION_FILE_PATTERNS = [
    /\.test\.\w+$/,
    /\.spec\.\w+$/,
    /\.tests\.\w+$/,
    /\.specs\.\w+$/,
    /_test\.\w+$/,
    /_spec\.\w+$/,
    /^Gruntfile\.\w+$/,
    /^Gulpfile\.\w+$/,
    /^Rakefile$/,
    /^Jakefile\.\w+$/,
  ];

  constructor() {
    // Use SafeDetector instead of SecurityDetectorV2 to prevent hangs
    this.detector = new SafeDetector(createPatternSource());
    this.github = getGitHubClient();
    this.vendorDetector = new VendorDetector();
  }

  async scan(config: ScanConfig): Promise<ScanResult> {
    logger.info(`Starting vulnerability scan for ${config.repository.owner}/${config.repository.name}`);
    
    const startTime = Date.now();
    const files = await this.getRepositoryFiles(config);
    let vulnerabilities: Vulnerability[] = [];
    
    logger.info(`Found ${files.length} files to scan`);
    
    // Scan each file with progress logging
    logger.info(`Starting vulnerability detection on ${files.length} files...`);
    
    for (let i = 0; i < files.length; i++) {
      const file = files[i];
      
      // Log progress every 10 files or on first/last file
      if (i === 0 || i === files.length - 1 || (i + 1) % 10 === 0) {
        logger.info(`Scanning progress: ${i + 1}/${files.length} files (${file.path})`);
      }
      
      if (file.language && this.isSupportedLanguage(file.language)) {
        try {
          // Check if this is a vendor file
          const isVendorFile = await this.vendorDetector.isVendorFile(file.path, file.content);

          if (isVendorFile) {
            logger.info(`Skipping vendor/minified file: ${file.path}`);
            continue;
          }

          // Check if this is a non-production file (tests, artifacts, build configs)
          if (RepositoryScanner.isNonProductionFile(file.path)) {
            logger.info(`Skipping non-production file: ${file.path}`);
            continue;
          }

          // SafeDetector handles timeout protection internally using worker threads
          const fileVulnerabilities = await this.detector.detect(file.content, file.language, file.path);

          // Add file path to each vulnerability
          fileVulnerabilities.forEach(vuln => {
            vuln.filePath = file.path;
            vuln.isVendor = false; // We already filtered out vendor files above
          });

          vulnerabilities.push(...fileVulnerabilities);

          if (fileVulnerabilities.length > 0) {
            logger.info(`Found ${fileVulnerabilities.length} vulnerabilities in ${file.path}`);
          }
        } catch (error) {
          logger.error(`Error scanning file ${file.path}:`, error);
        }
      }
    }
    
    logger.info(`Scanning complete. Total vulnerabilities found: ${vulnerabilities.length}`);

    // Apply confidence reduction for config file vulnerabilities
    RepositoryScanner.applyConfigConfidenceMultiplier(vulnerabilities);

    // Apply AST validation if enabled (default is true)
    if (config.enableASTValidation !== false && config.rsolvApiKey && typeof config.rsolvApiKey === 'string' && config.rsolvApiKey.length > 0) {
      logger.info('Performing AST validation on detected vulnerabilities (enabled by default)...');
      const validator = new ASTValidator(config.rsolvApiKey);
      
      // Create file contents map
      const fileContents = new Map<string, string>();
      files.forEach(f => fileContents.set(f.path, f.content));
      
      const preValidationCount = vulnerabilities.length;
      vulnerabilities = await validator.validateVulnerabilities(vulnerabilities, fileContents);
      const filtered = preValidationCount - vulnerabilities.length;
      
      logger.info(`AST validation complete: ${filtered} false positives filtered out`);
    } else if (config.enableASTValidation !== false) {
      logger.warn('AST validation is enabled but skipped - missing RSOLV API key');
    }
    
    // Log that we only scanned production application code
    logger.info('Scanned production code only (vendor/minified and non-production files excluded)');

    // RFC-101: Capture manifest files for project shape detection
    const manifestFiles = await this.captureManifestFiles(config, files);

    // Group vulnerabilities by type
    const groupedVulnerabilities = this.groupVulnerabilities(vulnerabilities);

    const scanTime = Date.now() - startTime;
    logger.info(`Scan completed in ${scanTime}ms. Found ${vulnerabilities.length} vulnerabilities`);

    // Clean up any remaining worker threads
    this.detector.cleanup();

    return {
      repository: `${config.repository.owner}/${config.repository.name}`,
      branch: config.repository.defaultBranch,
      scanDate: new Date().toISOString(),
      totalFiles: files.length,
      scannedFiles: files.filter(f => f.language && this.isSupportedLanguage(f.language)).length,
      vulnerabilities,
      groupedVulnerabilities,
      createdIssues: [], // Will be populated if issues are created
      manifestFiles: Object.keys(manifestFiles).length > 0 ? manifestFiles : undefined
    };
  }

  private async getRepositoryFiles(config: ScanConfig): Promise<FileToScan[]> {
    const files: FileToScan[] = [];
    
    try {
      // Get repository tree
      const { data: tree } = await this.github.git.getTree({
        owner: config.repository.owner,
        repo: config.repository.name,
        tree_sha: config.repository.defaultBranch,
        recursive: '1'
      });
      
      // Filter for code files only
      const codeFiles = tree.tree.filter(item => 
        item.type === 'blob' && 
        item.path && 
        this.isCodeFile(item.path) &&
        item.size && item.size < 1000000 // Skip files larger than 1MB
      );
      
      // Fetch content for each file with progress logging
      logger.info(`Fetching content for ${codeFiles.length} code files...`);
      
      for (let i = 0; i < codeFiles.length; i++) {
        const file = codeFiles[i];
        if (!file.path || !file.sha) continue;
        
        // Log progress every 10 files or on first/last file
        if (i === 0 || i === codeFiles.length - 1 || (i + 1) % 10 === 0) {
          logger.info(`Progress: ${i + 1}/${codeFiles.length} files fetched (${file.path})`);
        }
        
        try {
          const { data: blob } = await this.github.git.getBlob({
            owner: config.repository.owner,
            repo: config.repository.name,
            file_sha: file.sha
          });
          
          // Decode base64 content
          const content = Buffer.from(blob.content, 'base64').toString('utf-8');
          const language = this.detectLanguage(file.path);
          
          if (language) {
            files.push({
              path: file.path,
              content,
              language
            });
          }
        } catch (error) {
          logger.error(`Error fetching content for ${file.path}:`, error);
        }
      }
      
      logger.info(`Completed fetching ${files.length} files with supported languages`);
    } catch (error) {
      logger.error('Error getting repository files:', error);
      throw error;
    }
    
    return files;
  }

  private isCodeFile(path: string): boolean {
    const codeExtensions = [
      '.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs',
      '.py', '.pyw',
      '.rb', '.rake',
      '.java',
      '.php', '.phtml',
      '.ex', '.exs'
    ];
    
    return codeExtensions.some(ext => path.endsWith(ext));
  }

  private detectLanguage(path: string): string | null {
    const extensionMap: Record<string, string> = {
      '.js': 'javascript',
      '.jsx': 'javascript',
      '.ts': 'typescript',
      '.tsx': 'typescript',
      '.mjs': 'javascript',
      '.cjs': 'javascript',
      '.py': 'python',
      '.pyw': 'python',
      '.rb': 'ruby',
      '.rake': 'ruby',
      '.java': 'java',
      '.php': 'php',
      '.phtml': 'php',
      '.ex': 'elixir',
      '.exs': 'elixir'
    };
    
    const extension = path.substring(path.lastIndexOf('.'));
    return extensionMap[extension] || null;
  }

  /**
   * Check if a file path is a non-production file (tests, artifacts, build configs).
   * These files should be skipped during vulnerability scanning because findings
   * in them are not actionable for production security.
   */
  static isNonProductionFile(filePath: string): boolean {
    const normalizedPath = filePath.replace(/\\/g, '/');

    // Check if path contains a non-production directory
    for (const dir of RepositoryScanner.NON_PRODUCTION_DIRS) {
      if (normalizedPath.includes(`/${dir}`) || normalizedPath.startsWith(dir)) {
        return true;
      }
    }

    // Check if filename matches non-production patterns
    const filename = normalizedPath.split('/').pop() || '';
    for (const pattern of RepositoryScanner.NON_PRODUCTION_FILE_PATTERNS) {
      if (pattern.test(filename)) {
        return true;
      }
    }

    return false;
  }

  /**
   * Check if a file path is in a configuration directory or matches config file patterns.
   */
  static isConfigFile(filePath: string): boolean {
    const normalizedPath = filePath.replace(/\\/g, '/');

    // Check if path starts with or contains a config directory
    for (const dir of RepositoryScanner.CONFIG_DIRS) {
      if (normalizedPath.startsWith(dir) || normalizedPath.includes(`/${dir}`)) {
        return true;
      }
    }

    // Check if filename matches config file patterns
    const filename = normalizedPath.split('/').pop() || '';
    for (const pattern of RepositoryScanner.CONFIG_FILE_PATTERNS) {
      if (pattern.test(filename)) {
        return true;
      }
    }

    return false;
  }

  /**
   * Apply 0.5x confidence multiplier to vulnerabilities found in config files.
   * Aligned with backend file_path_classifier.ex confidence reduction.
   */
  static applyConfigConfidenceMultiplier(vulnerabilities: Vulnerability[]): Vulnerability[] {
    for (const vuln of vulnerabilities) {
      if (vuln.filePath && RepositoryScanner.isConfigFile(vuln.filePath)) {
        vuln.confidence = Math.round(vuln.confidence * 0.5);
      }
    }
    return vulnerabilities;
  }

  /**
   * RFC-101: Capture manifest/config file contents for project shape detection.
   * Checks already-fetched files first, then fetches remaining manifest files from GitHub.
   * Files larger than 10KB are skipped to keep phase data payload reasonable.
   */
  private async captureManifestFiles(
    config: ScanConfig,
    alreadyFetched: FileToScan[]
  ): Promise<Record<string, string>> {
    const manifestFiles: Record<string, string> = {};
    const MAX_FILE_SIZE = 10 * 1024; // 10KB cap per file

    // Build a map of already-fetched file contents
    const fetchedMap = new Map<string, string>();
    for (const f of alreadyFetched) {
      fetchedMap.set(f.path, f.content);
    }

    for (const manifestPath of RepositoryScanner.MANIFEST_FILES) {
      // Check if we already have this file from the scan
      const existing = fetchedMap.get(manifestPath);
      if (existing) {
        if (existing.length <= MAX_FILE_SIZE) {
          manifestFiles[manifestPath] = existing;
        }
        continue;
      }

      // Try to fetch from GitHub
      try {
        const { data } = await this.github.repos.getContent({
          owner: config.repository.owner,
          repo: config.repository.name,
          path: manifestPath,
          ref: config.repository.defaultBranch
        });

        if ('content' in data && data.content && data.encoding === 'base64') {
          const content = Buffer.from(data.content, 'base64').toString('utf-8');
          if (content.length <= MAX_FILE_SIZE) {
            manifestFiles[manifestPath] = content;
          }
        }
      } catch {
        // File doesn't exist in repo — silently skip
      }
    }

    if (Object.keys(manifestFiles).length > 0) {
      logger.info(`RFC-101: Captured ${Object.keys(manifestFiles).length} manifest files: ${Object.keys(manifestFiles).join(', ')}`);
    }

    return manifestFiles;
  }

  private isSupportedLanguage(language: string): boolean {
    const supported = ['javascript', 'typescript', 'python', 'ruby', 'java', 'php', 'elixir'];
    return supported.includes(language.toLowerCase());
  }

  private groupVulnerabilities(vulnerabilities: Vulnerability[]): VulnerabilityGroup[] {
    const groups = new Map<string, VulnerabilityGroup>();

    for (const vuln of vulnerabilities) {
      // Group by type and severity (no vendor grouping since we skip vendor files)
      const key = `${vuln.type}-${vuln.severity}`;

      if (!groups.has(key)) {
        groups.set(key, {
          type: vuln.type,
          severity: vuln.severity,
          count: 0,
          files: [],
          vulnerabilities: [],
          isVendor: false // All vulnerabilities are in application code
        });
      }

      const group = groups.get(key)!;
      group.count++;
      group.vulnerabilities.push(vuln);

      if (vuln.filePath && !group.files.includes(vuln.filePath)) {
        group.files.push(vuln.filePath);
      }
    }

    // Sort groups by severity (highest priority first) and count
    return Array.from(groups.values()).sort((a, b) => {
      const severityDiff = SEVERITY_PRIORITY[a.severity] - SEVERITY_PRIORITY[b.severity];
      return severityDiff !== 0 ? severityDiff : b.count - a.count;
    });
  }
}