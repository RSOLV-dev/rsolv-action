import { generateSolution } from './src/ai/solution.js';

const mockIssue = {
  id: '123',
  number: 123,
  source: 'github',
  title: 'Critical SQL Injection Vulnerability in User Authentication',
  body: 'The authenticateUser function uses direct string concatenation for SQL queries, making it vulnerable to SQL injection attacks.',
  labels: ['security', 'rsolv:automate'],
  assignees: [],
  repository: {
    owner: 'demo-owner',
    name: 'demo-repo',
    fullName: 'demo-owner/demo-repo',
    defaultBranch: 'main',
    language: 'JavaScript'
  },
  url: 'https://github.com/demo-owner/demo-repo/issues/123',
  createdAt: new Date().toISOString(),
  updatedAt: new Date().toISOString()
};

const mockAnalysis = {
  complexity: 'medium',
  estimatedTime: 45,
  issueType: 'security',
  filesToModify: ['src/auth/login.js'],
  relatedFiles: ['src/auth/login.js'],
  suggestedApproach: 'Replace string concatenation with parameterized queries',
  riskLevel: 'high',
  estimatedComplexity: 'medium',
  requiredContext: [],
  canBeFixed: true,
  confidenceScore: 0.8
};

const mockConfig = {
  configPath: '.github/rsolv.yml',
  issueLabel: 'rsolv:automate',
  rsolvApiKey: 'test-key',
  aiProvider: {
    provider: 'claude-code',
    model: 'claude-sonnet-4-20250514',
    temperature: 0.2,
    maxTokens: 4000,
    contextLimit: 100000,
    timeout: 60000,
    useVendedCredentials: true
  },
  enableSecurityAnalysis: true,
  containerConfig: {
    enabled: false,
    image: 'rsolv/code-analysis:latest',
    memoryLimit: '2g',
    cpuLimit: '1',
    timeout: 300,
    securityProfile: 'default'
  }
};

const solution = await generateSolution(mockIssue, mockAnalysis, mockConfig);
console.log('=== CLAUDE CODE GENERATED SOLUTION ===');
console.log('Success:', solution.success);
console.log('Message:', solution.message);
console.log('Changes:');
console.log(JSON.stringify(solution.changes, null, 2));
EOF < /dev/null