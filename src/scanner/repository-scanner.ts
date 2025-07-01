import { SecurityDetectorV2 } from '../security/detector-v2.js';
import { getGitHubClient } from '../github/api.js';
import { logger } from '../utils/logger.js';
import type { FileToScan, ScanConfig, ScanResult, VulnerabilityGroup } from './types.js';
import type { Vulnerability } from '../security/types.js';
import { createPatternSource } from '../security/pattern-source.js';
import { ASTValidator } from './ast-validator.js';

export class RepositoryScanner {
  private detector: SecurityDetectorV2;
  private github: ReturnType<typeof getGitHubClient>;

  constructor() {
    this.detector = new SecurityDetectorV2(createPatternSource());
    this.github = getGitHubClient();
  }

  async scan(config: ScanConfig): Promise<ScanResult> {
    logger.info(`Starting vulnerability scan for ${config.repository.owner}/${config.repository.name}`);
    
    const startTime = Date.now();
    const files = await this.getRepositoryFiles(config);
    let vulnerabilities: Vulnerability[] = [];
    
    logger.info(`Found ${files.length} files to scan`);
    
    // Scan each file
    for (const file of files) {
      if (file.language && this.isSupportedLanguage(file.language)) {
        try {
          const fileVulnerabilities = await this.detector.detect(file.content, file.language);
          
          // Add file path to each vulnerability
          fileVulnerabilities.forEach(vuln => {
            vuln.filePath = file.path;
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
    
    // Group vulnerabilities by type
    const groupedVulnerabilities = this.groupVulnerabilities(vulnerabilities);
    
    const scanTime = Date.now() - startTime;
    logger.info(`Scan completed in ${scanTime}ms. Found ${vulnerabilities.length} vulnerabilities`);
    
    return {
      repository: `${config.repository.owner}/${config.repository.name}`,
      branch: config.repository.defaultBranch,
      scanDate: new Date().toISOString(),
      totalFiles: files.length,
      scannedFiles: files.filter(f => f.language && this.isSupportedLanguage(f.language)).length,
      vulnerabilities,
      groupedVulnerabilities,
      createdIssues: [] // Will be populated if issues are created
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
      
      // Fetch content for each file
      for (const file of codeFiles) {
        if (!file.path || !file.sha) continue;
        
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

  private isSupportedLanguage(language: string): boolean {
    const supported = ['javascript', 'typescript', 'python', 'ruby', 'java', 'php', 'elixir'];
    return supported.includes(language.toLowerCase());
  }

  private groupVulnerabilities(vulnerabilities: Vulnerability[]): VulnerabilityGroup[] {
    const groups = new Map<string, VulnerabilityGroup>();
    
    for (const vuln of vulnerabilities) {
      const key = `${vuln.type}-${vuln.severity}`;
      
      if (!groups.has(key)) {
        groups.set(key, {
          type: vuln.type,
          severity: vuln.severity,
          count: 0,
          files: [],
          vulnerabilities: []
        });
      }
      
      const group = groups.get(key)!;
      group.count++;
      group.vulnerabilities.push(vuln);
      
      if (vuln.filePath && !group.files.includes(vuln.filePath)) {
        group.files.push(vuln.filePath);
      }
    }
    
    // Sort groups by severity and count
    return Array.from(groups.values()).sort((a, b) => {
      const severityOrder = { high: 0, medium: 1, low: 2 };
      const severityDiff = severityOrder[a.severity as keyof typeof severityOrder] - 
                           severityOrder[b.severity as keyof typeof severityOrder];
      
      return severityDiff !== 0 ? severityDiff : b.count - a.count;
    });
  }
}