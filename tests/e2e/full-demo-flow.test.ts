import { describe, test, expect, beforeAll } from 'bun:test';
import { getGitHubClient } from '../../src/github/api.js';
import { loadConfig } from '../../src/config/index.js';
import { SecurityAwareAnalyzer } from '../../src/ai/security-analyzer.js';
import { generateSolution } from '../../src/ai/solution.js';
import { createPullRequest } from '../../src/github/pr.js';
import { RSOLVCredentialManager } from '../../src/credentials/manager.js';
import { RsolvApiClient } from '../../src/external/api-client.js';

describe('Full Demo E2E Flow', () => {
  // Force real AI for E2E tests
  process.env.FORCE_REAL_AI = 'true';
  let config: any;
  let issueContext: any;
  let githubClient: any;
  
  beforeAll(async () => {
    // Ensure required env vars
    expect(process.env.GITHUB_TOKEN).toBeDefined();
    expect(process.env.RSOLV_API_KEY).toBeDefined();
    expect(process.env.RSOLV_API_URL).toMatch(/https:\/\/api\.rsolv\.(dev|ai)/);
  });

  test('should fetch issue from GitHub', async () => {
    githubClient = getGitHubClient({ token: process.env.GITHUB_TOKEN! });
    
    const { data: issue } = await githubClient.issues.get({
      owner: 'RSOLV-dev',
      repo: 'demo-ecommerce-security',
      issue_number: 8
    });
    
    expect(issue.number).toBe(8);
    expect(issue.title).toContain('Security audit');
    expect(issue.labels.map((l: any) => l.name)).toContain('rsolv:automate');
    
    // Create issue context
    issueContext = {
      id: issue.id.toString(),
      number: issue.number,
      title: issue.title,
      body: issue.body || '',
      labels: issue.labels.map((l: any) => l.name),
      assignees: issue.assignees.map((a: any) => a.login),
      repository: {
        owner: 'RSOLV-dev',
        name: 'demo-ecommerce-security',
        fullName: 'RSOLV-dev/demo-ecommerce-security',
        defaultBranch: 'main',
        language: 'JavaScript'
      },
      source: 'github' as const,
      url: issue.html_url,
      createdAt: issue.created_at,
      updatedAt: issue.updated_at
    };
  });

  test('should load config with credential vending enabled', async () => {
    config = await loadConfig();
    
    expect(config.apiKey).toBe('rsolv_prod_demo_key');
    expect(config.aiProvider.provider).toBe('claude-code');
    expect(config.aiProvider.useVendedCredentials).toBe(true);
    expect(config.enableSecurityAnalysis).toBe(true);
  });

  test('should successfully exchange credentials', async () => {
    const credManager = new RSOLVCredentialManager();
    
    await credManager.initialize(config.apiKey);
    
    // Should be able to get Anthropic credentials
    const anthropicKey = credManager.getCredential('anthropic');
    expect(anthropicKey).toStartWith('sk-ant-');
    expect(anthropicKey.length).toBeGreaterThan(20);
  }, 10000); // 10s timeout for API call

  test('should perform security analysis and find vulnerabilities', async () => {
    // Get vulnerable code
    const { data: fileContent } = await githubClient.repos.getContent({
      owner: 'RSOLV-dev',
      repo: 'demo-ecommerce-security',
      path: 'src/auth/login.js'
    });
    
    const decodedContent = Buffer.from(fileContent.content, 'base64').toString();
    expect(decodedContent).toContain('SELECT * FROM users WHERE username =');
    
    const codebaseFiles = new Map([['src/auth/login.js', decodedContent]]);
    
    const securityAnalyzer = new SecurityAwareAnalyzer();
    const analysis = await securityAnalyzer.analyzeWithSecurity(
      issueContext,
      config,
      codebaseFiles
    );
    
    // Check security analysis results
    expect(analysis.securityAnalysis).toBeDefined();
    expect(analysis.securityAnalysis!.hasSecurityIssues).toBe(true);
    expect(analysis.securityAnalysis!.vulnerabilities.length).toBeGreaterThanOrEqual(2);
    
    // Should find SQL injection vulnerabilities
    const sqlInjections = analysis.securityAnalysis!.vulnerabilities.filter(
      v => v.type === 'sql_injection'
    );
    expect(sqlInjections.length).toBeGreaterThanOrEqual(2);
    
    // Check summary
    expect(analysis.securityAnalysis!.summary.total).toBeGreaterThanOrEqual(2);
    expect(analysis.securityAnalysis!.summary.bySeverity['high']).toBeGreaterThanOrEqual(2);
    expect(analysis.securityAnalysis!.riskLevel).toBeOneOf(['high', 'critical']);
  }, 30000); // 30s timeout

  test('should generate solution using Claude Code', async () => {
    // This test needs all previous tests to run for setup
    if (!githubClient || !config || !issueContext) {
      console.log('Skipping - requires previous tests to run first');
      return;
    }
    // Get the security analysis again
    const { data: fileContent } = await githubClient.repos.getContent({
      owner: 'RSOLV-dev',
      repo: 'demo-ecommerce-security',
      path: 'src/auth/login.js'
    });
    
    const decodedContent = Buffer.from(fileContent.content, 'base64').toString();
    const codebaseFiles = new Map([['src/auth/login.js', decodedContent]]);
    
    const securityAnalyzer = new SecurityAwareAnalyzer();
    const analysisWithSecurity = await securityAnalyzer.analyzeWithSecurity(
      issueContext,
      config,
      codebaseFiles
    );
    
    // Create a file getter that returns the vulnerable code
    const fileGetter = async (filePath: string) => {
      if (filePath === 'src/auth/login.js') {
        return decodedContent;
      }
      return '';
    };
    
    // Generate solution with Claude Code
    const solution = await generateSolution(
      issueContext,
      analysisWithSecurity,
      config,
      undefined,
      fileGetter,
      analysisWithSecurity.securityAnalysis
    );
    
    expect(solution.success).toBe(true);
    expect(solution.changes).toBeDefined();
    expect(Object.keys(solution.changes!).length).toBeGreaterThan(0);
    
    // Should have fix for login.js
    expect(solution.changes!['src/auth/login.js']).toBeDefined();
    
    // Fix should use parameterized queries
    const loginFix = solution.changes!['src/auth/login.js'];
    expect(loginFix).toContain('?'); // Parameterized query placeholder
    expect(loginFix).not.toContain("' + username + '"); // No string concatenation
  }, 120000); // 2 minute timeout for Claude Code

  test('should track fix attempt via API', async () => {
    const apiClient = new RsolvApiClient(config.apiKey);
    
    // Create a mock fix attempt
    const fixAttempt = await apiClient.createFixAttempt({
      github_issue_url: issueContext.url,
      github_pr_url: 'https://github.com/RSOLV-dev/demo-ecommerce-security/pull/999',
      repository_full_name: issueContext.repository.fullName,
      issue_number: issueContext.number,
      issue_title: issueContext.title,
      ai_provider: config.aiProvider.provider,
      ai_model: config.aiProvider.model,
      security_vulnerabilities_found: 4,
      estimated_time_saved_hours: 2.5
    });
    
    expect(fixAttempt.success).toBe(true);
    expect(fixAttempt.data).toBeDefined();
    expect(fixAttempt.data.id).toBeDefined();
  }, 10000);

  test('should handle the complete workflow end-to-end', async () => {
    // This test verifies the entire flow works together
    const startTime = Date.now();
    
    // 1. Issue exists and has correct labels
    expect(issueContext.labels).toContain('rsolv:automate');
    
    // 2. Config loads with vending enabled
    expect(config.aiProvider.useVendedCredentials).toBe(true);
    
    // 3. Credentials can be vended
    const credManager = new RSOLVCredentialManager();
    await credManager.initialize(config.apiKey);
    const hasValidCreds = () => {
      try {
        credManager.getCredential('anthropic');
        return true;
      } catch {
        return false;
      }
    };
    expect(hasValidCreds()).toBe(true);
    
    // 4. Security analysis finds issues
    const { data: fileContent } = await githubClient.repos.getContent({
      owner: 'RSOLV-dev',
      repo: 'demo-ecommerce-security',
      path: 'src/auth/login.js'
    });
    const decodedContent = Buffer.from(fileContent.content, 'base64').toString();
    const codebaseFiles = new Map([['src/auth/login.js', decodedContent]]);
    
    const securityAnalyzer = new SecurityAwareAnalyzer();
    const analysis = await securityAnalyzer.analyzeWithSecurity(
      issueContext,
      config,
      codebaseFiles
    );
    
    expect(analysis.securityAnalysis!.summary.total).toBeGreaterThan(0);
    
    // 5. Solution can be generated
    const solution = await generateSolution(
      issueContext,
      analysis,
      config,
      undefined,
      undefined,
      analysis.securityAnalysis
    );
    
    expect(solution.success).toBe(true);
    
    // 6. Timing is reasonable
    const duration = Date.now() - startTime;
    expect(duration).toBeLessThan(180000); // Should complete in under 3 minutes
    
    console.log(`Full workflow completed in ${(duration / 1000).toFixed(1)}s`);
  }, 180000); // 3 minute timeout for full test
});