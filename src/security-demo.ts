import { SecurityDetector } from './security/detector.js';
import { SecurityAwareAnalyzer } from './ai/security-analyzer.js';
import { ComplianceGenerator } from './security/compliance.js';
import { ThreeTierExplanationFramework } from './security/explanation-framework.js';
import { CveCorrelator } from './security/cve-correlator.js';
import { VulnerabilityType } from './security/types.js';

export interface DemoExample {
  id: string;
  title: string;
  description: string;
  category: 'sql_injection' | 'xss' | 'access_control' | 'mixed';
  vulnerableCode: string;
  language: string;
  expectedVulnerabilities: Array<{
    type: VulnerabilityType;
    severity: string;
    line: number;
  }>;
  metadata: {
    difficulty: 'beginner' | 'intermediate' | 'advanced';
    realWorld: boolean;
    scenario: string;
  };
}

export interface SecurityAnalysisResult {
  vulnerabilities: any[];
  securityAnalysis: any;
  threeTierExplanation: any;
  recommendations: string[];
}

export interface SecurityReportResult {
  summary: {
    totalVulnerabilities: number;
    riskLevel: string;
    complianceStatus: string;
  };
  vulnerabilityBreakdown: Record<string, number>;
  complianceStatus: any;
  riskAssessment: any;
  recommendations: string[];
  cveIntelligence: any;
}

export interface AnalysisStep {
  id: string;
  title: string;
  description: string;
  action: string;
}

export interface PromptEnhancementDemo {
  originalPrompt: string;
  securityEnhancedPrompt: string;
  improvements: string[];
}

export interface VulnerabilityFixDemo {
  vulnerableCode: string;
  secureCode: string;
  explanation: {
    lineLevel: string;
    conceptLevel: string;
    businessLevel: string;
  };
}

export interface PerformanceMetrics {
  analysisTime: number;
  vulnerabilitiesDetected: number;
  cveCorrelations: number;
  complianceChecks: number;
  averageRiskScore: number;
}

export interface BenchmarkResult {
  totalTime: number;
  averageTimePerVulnerability: number;
  vulnerabilitiesProcessed: number;
  throughput: number;
}

export interface DemoConfig {
  includeRealistic?: boolean;
  includeSynthetic?: boolean;
  focusAreas?: string[];
  complexityLevel?: 'beginner' | 'intermediate' | 'advanced';
}

export interface EducationalMode {
  detailedExplanations: boolean;
  stepByStepGuidance: boolean;
  interactiveExercises: Array<{
    id: string;
    title: string;
    description: string;
    code: string;
    expectedAnswer: string;
  }>;
}

export class SecurityDemoEnvironment {
  private detector: SecurityDetector;
  private analyzer: SecurityAwareAnalyzer;
  private complianceGenerator: ComplianceGenerator;
  private explanationFramework: ThreeTierExplanationFramework;
  private cveCorrelator: CveCorrelator;
  private performanceMetrics: PerformanceMetrics;

  constructor() {
    this.detector = new SecurityDetector();
    this.analyzer = new SecurityAwareAnalyzer();
    this.complianceGenerator = new ComplianceGenerator();
    this.explanationFramework = new ThreeTierExplanationFramework();
    this.cveCorrelator = new CveCorrelator();
    this.performanceMetrics = {
      analysisTime: 0,
      vulnerabilitiesDetected: 0,
      cveCorrelations: 0,
      complianceChecks: 0,
      averageRiskScore: 0
    };
  }

  async getDemoExamples(config?: DemoConfig): Promise<DemoExample[]> {
    const allExamples: DemoExample[] = [
      {
        id: 'sql-injection-basic',
        title: 'SQL Injection in User Authentication',
        description: 'A classic SQL injection vulnerability in a login system',
        category: 'sql_injection',
        vulnerableCode: `
function authenticateUser(username, password) {
  const query = "SELECT * FROM users WHERE username = '" + username + "' AND password = '" + password + "'";
  return database.query(query);
}`,
        language: 'javascript',
        expectedVulnerabilities: [
          { type: VulnerabilityType.SQL_INJECTION, severity: 'high', line: 2 }
        ],
        metadata: {
          difficulty: 'beginner',
          realWorld: true,
          scenario: 'User authentication bypass'
        }
      },
      {
        id: 'xss-stored',
        title: 'Stored XSS in Comment System',
        description: 'A stored XSS vulnerability in user-generated content',
        category: 'xss',
        vulnerableCode: `
function displayComments(comments) {
  const container = document.getElementById('comments');
  comments.forEach(comment => {
    const div = document.createElement('div');
    div.innerHTML = comment.content;
    container.appendChild(div);
  });
}`,
        language: 'javascript',
        expectedVulnerabilities: [
          { type: VulnerabilityType.XSS, severity: 'high', line: 5 }
        ],
        metadata: {
          difficulty: 'intermediate',
          realWorld: true,
          scenario: 'User comment system'
        }
      },
      {
        id: 'access-control-broken',
        title: 'Broken Access Control in Admin Panel',
        description: 'Missing authentication checks on administrative endpoints',
        category: 'access_control',
        vulnerableCode: `
app.get('/admin/users', (req, res) => {
  const users = database.getAllUsers();
  res.json(users);
});

app.delete('/admin/users/:id', (req, res) => {
  database.deleteUser(req.params.id);
  res.send('User deleted');
});`,
        language: 'javascript',
        expectedVulnerabilities: [
          { type: VulnerabilityType.BROKEN_ACCESS_CONTROL, severity: 'high', line: 1 },
          { type: VulnerabilityType.BROKEN_ACCESS_CONTROL, severity: 'high', line: 6 }
        ],
        metadata: {
          difficulty: 'intermediate',
          realWorld: true,
          scenario: 'Administrative panel'
        }
      },
      {
        id: 'mixed-vulnerabilities',
        title: 'E-commerce Application with Multiple Issues',
        description: 'A realistic e-commerce scenario with multiple vulnerability types',
        category: 'mixed',
        vulnerableCode: `
// Product search with SQL injection
function searchProducts(query) {
  const sql = "SELECT * FROM products WHERE name LIKE '%" + query + "%'";
  return db.query(sql);
}

// User review display with XSS
function displayReviews(reviews) {
  reviews.forEach(review => {
    document.getElementById('reviews').innerHTML += '<div>' + review.text + '</div>';
  });
}

// Admin functions without proper access control
app.get('/admin/orders', (req, res) => {
  res.json(getAllOrders());
});

// Sensitive data logging
function processPayment(cardNumber, cvv) {
  console.log('Processing payment for card:', cardNumber, 'CVV:', cvv);
  return processTransaction(cardNumber, cvv);
}`,
        language: 'javascript',
        expectedVulnerabilities: [
          { type: VulnerabilityType.SQL_INJECTION, severity: 'high', line: 3 },
          { type: VulnerabilityType.XSS, severity: 'high', line: 9 },
          { type: VulnerabilityType.BROKEN_ACCESS_CONTROL, severity: 'high', line: 14 },
          { type: VulnerabilityType.SENSITIVE_DATA_EXPOSURE, severity: 'high', line: 19 }
        ],
        metadata: {
          difficulty: 'advanced',
          realWorld: true,
          scenario: 'E-commerce application'
        }
      }
    ];

    if (!config) return allExamples;

    let filteredExamples = allExamples;

    if (config.focusAreas) {
      filteredExamples = filteredExamples.filter(example => 
        config.focusAreas!.includes(example.category) || 
        config.focusAreas!.some(area => example.category.includes(area))
      );
    }

    if (config.complexityLevel) {
      filteredExamples = filteredExamples.filter(example => 
        example.metadata.difficulty === config.complexityLevel
      );
    }

    if (config.includeRealistic === false) {
      filteredExamples = filteredExamples.filter(example => 
        !example.metadata.realWorld
      );
    }

    return filteredExamples;
  }

  async demonstrateVulnerabilityDetection(example: DemoExample): Promise<{
    detectedVulnerabilities: any[];
    analysisReport: any;
    complianceReport: any;
    cveCorrelations: any;
  }> {
    const startTime = Date.now();
    
    // Step 1: Detect vulnerabilities
    const detectedVulnerabilities = this.detector.detect(example.vulnerableCode, example.language);
    
    // Step 2: Generate analysis report
    const codebaseMap = new Map([[`${example.id}.${example.language}`, example.vulnerableCode]]);
    const mockIssue = {
      id: example.id,
      title: example.title,
      body: example.description,
      number: 1,
      labels: ['security'],
      assignees: [],
      repository: {
        owner: 'demo',
        name: 'security-demo',
        fullName: 'demo/security-demo',
        language: example.language
      }
    };
    
    const analysisReport = await this.analyzer.analyzeWithSecurity(mockIssue, {}, codebaseMap);
    
    // Step 3: Generate compliance report
    const complianceReport = this.complianceGenerator.generateOwaspComplianceReport(detectedVulnerabilities);
    
    // Step 4: Get CVE correlations
    const cveCorrelations = await this.cveCorrelator.correlateWithCve(detectedVulnerabilities);
    
    // Update performance metrics
    this.performanceMetrics.analysisTime = Date.now() - startTime;
    this.performanceMetrics.vulnerabilitiesDetected += detectedVulnerabilities.length;
    this.performanceMetrics.cveCorrelations += cveCorrelations.totalCves;
    this.performanceMetrics.complianceChecks += 1;

    return {
      detectedVulnerabilities,
      analysisReport,
      complianceReport,
      cveCorrelations
    };
  }

  async analyzeCustomCode(code: string, language: string): Promise<SecurityAnalysisResult> {
    const vulnerabilities = this.detector.detect(code, language);
    
    const codebaseMap = new Map([['custom.js', code]]);
    const mockIssue = {
      id: 'custom',
      title: 'Custom Code Analysis',
      body: 'User-provided code for security analysis',
      number: 1,
      labels: ['security'],
      assignees: [],
      repository: {
        owner: 'demo',
        name: 'custom-analysis',
        fullName: 'demo/custom-analysis',
        language: language
      }
    };
    
    const securityAnalysis = await this.analyzer.analyzeWithSecurity(mockIssue, {}, codebaseMap);
    
    const threeTierExplanation = this.explanationFramework.generateCompleteExplanation(
      vulnerabilities,
      { 'custom.js': code }
    );
    
    const recommendations = this.generateRecommendations(vulnerabilities);

    return {
      vulnerabilities,
      securityAnalysis,
      threeTierExplanation,
      recommendations
    };
  }

  async generateSecurityReport(example: DemoExample): Promise<SecurityReportResult> {
    const detectionResult = await this.demonstrateVulnerabilityDetection(example);
    
    const vulnerabilityBreakdown: Record<string, number> = {};
    for (const vuln of detectionResult.detectedVulnerabilities) {
      vulnerabilityBreakdown[vuln.type] = (vulnerabilityBreakdown[vuln.type] || 0) + 1;
    }

    return {
      summary: {
        totalVulnerabilities: detectionResult.detectedVulnerabilities.length,
        riskLevel: detectionResult.complianceReport.summary.compliance.status,
        complianceStatus: detectionResult.complianceReport.summary.compliance.status
      },
      vulnerabilityBreakdown,
      complianceStatus: detectionResult.complianceReport,
      riskAssessment: detectionResult.cveCorrelations.riskAssessment,
      recommendations: this.generateRecommendations(detectionResult.detectedVulnerabilities),
      cveIntelligence: detectionResult.cveCorrelations
    };
  }

  async exportSecurityReport(example: DemoExample, formats: string[]): Promise<Record<string, string>> {
    const report = await this.generateSecurityReport(example);
    const detectionResult = await this.demonstrateVulnerabilityDetection(example);
    const results: Record<string, string> = {};

    if (formats.includes('markdown')) {
      results.markdown = this.generateMarkdownReport(report, example);
    }

    if (formats.includes('json')) {
      // Add vulnerabilities field to the report for JSON export
      const exportReport = {
        ...report,
        vulnerabilities: detectionResult.detectedVulnerabilities
      };
      results.json = JSON.stringify(exportReport, null, 2);
    }

    return results;
  }

  async getAnalysisSteps(): Promise<AnalysisStep[]> {
    return [
      {
        id: 'code-scanning',
        title: 'Code Vulnerability Scanning',
        description: 'Scan code for known security vulnerability patterns',
        action: 'Run security detector on codebase'
      },
      {
        id: 'ai-analysis',
        title: 'AI-Enhanced Security Analysis',
        description: 'Use AI to analyze context and identify complex security issues',
        action: 'Perform AI-powered security analysis'
      },
      {
        id: 'compliance-check',
        title: 'Compliance Assessment',
        description: 'Check compliance against security standards (OWASP, SOC2)',
        action: 'Generate compliance reports'
      },
      {
        id: 'cve-correlation',
        title: 'CVE Intelligence Correlation',
        description: 'Correlate findings with known CVE database entries',
        action: 'Match vulnerabilities with CVE database'
      },
      {
        id: 'risk-assessment',
        title: 'Risk Level Assessment',
        description: 'Calculate overall risk score and prioritize fixes',
        action: 'Compute risk metrics and recommendations'
      },
      {
        id: 'explanation-generation',
        title: 'Three-Tier Explanation',
        description: 'Generate technical, conceptual, and business explanations',
        action: 'Create comprehensive explanations'
      }
    ];
  }

  async demonstratePromptEnhancement(vulnerableCode: string): Promise<PromptEnhancementDemo> {
    const originalPrompt = `Fix the following code:\n\n${vulnerableCode}`;
    
    const vulnerabilities = this.detector.detect(vulnerableCode, 'javascript');
    const securityEnhancedPrompt = `Fix the following security-vulnerable code:

SECURITY ANALYSIS:
${vulnerabilities.map(v => `- ${v.type}: ${v.message} (${v.severity})`).join('\n')}

VULNERABLE CODE:
${vulnerableCode}

REQUIREMENTS:
1. Address ALL identified security vulnerabilities
2. Follow security best practices
3. Implement proper input validation
4. Use secure coding patterns
5. Add security tests

Please provide a secure implementation with explanations.`;

    const improvements = [
      'Added specific security vulnerability identification',
      'Included risk assessment information',
      'Specified security-focused requirements',
      'Requested security testing guidance',
      'Enhanced with vulnerability-specific context'
    ];

    return {
      originalPrompt,
      securityEnhancedPrompt,
      improvements
    };
  }

  async demonstrateVulnerabilityFix(vulnerableCode: string, vulnerabilityType: string): Promise<VulnerabilityFixDemo> {
    const secureCode = this.generateSecureCode(vulnerableCode, vulnerabilityType);
    const vulnerabilities = this.detector.detect(vulnerableCode, 'javascript');
    
    const explanation = this.explanationFramework.generateLineLevelExplanation(
      vulnerabilities[0],
      vulnerableCode
    );

    return {
      vulnerableCode,
      secureCode,
      explanation: {
        lineLevel: explanation.content,
        conceptLevel: 'This vulnerability allows attackers to exploit the application by manipulating input data.',
        businessLevel: 'This security risk could lead to data breaches, compliance violations, and reputational damage.'
      }
    };
  }

  async getPerformanceMetrics(): Promise<PerformanceMetrics> {
    return { ...this.performanceMetrics };
  }

  async runPerformanceBenchmark(): Promise<BenchmarkResult> {
    const startTime = Date.now();
    const examples = await this.getDemoExamples();
    let totalVulnerabilities = 0;

    for (const example of examples) {
      const result = await this.demonstrateVulnerabilityDetection(example);
      totalVulnerabilities += result.detectedVulnerabilities.length;
    }

    const totalTime = Date.now() - startTime;
    const averageTimePerVulnerability = totalVulnerabilities > 0 ? totalTime / totalVulnerabilities : 0;
    const throughput = totalVulnerabilities / (totalTime / 1000); // vulnerabilities per second

    return {
      totalTime,
      averageTimePerVulnerability,
      vulnerabilitiesProcessed: totalVulnerabilities,
      throughput
    };
  }

  async enableEducationalMode(): Promise<EducationalMode> {
    return {
      detailedExplanations: true,
      stepByStepGuidance: true,
      interactiveExercises: [
        {
          id: 'sql-injection-exercise',
          title: 'Identify SQL Injection',
          description: 'Find the SQL injection vulnerability in this code',
          code: 'const query = "SELECT * FROM users WHERE id = " + userId;',
          expectedAnswer: 'String concatenation creates SQL injection vulnerability'
        },
        {
          id: 'xss-exercise',
          title: 'Spot XSS Vulnerability',
          description: 'Identify the cross-site scripting issue',
          code: 'element.innerHTML = userInput;',
          expectedAnswer: 'Direct assignment to innerHTML without sanitization'
        },
        {
          id: 'access-control-exercise',
          title: 'Find Access Control Issue',
          description: 'What is wrong with this endpoint?',
          code: 'app.get("/admin/users", (req, res) => { res.json(users); });',
          expectedAnswer: 'Missing authentication and authorization checks'
        }
      ]
    };
  }

  private generateRecommendations(vulnerabilities: any[]): string[] {
    const recommendations: string[] = [];
    
    const sqlInjectionVulns = vulnerabilities.filter(v => v.type === 'sql_injection');
    if (sqlInjectionVulns.length > 0) {
      recommendations.push('Implement parameterized queries to prevent SQL injection');
    }

    const xssVulns = vulnerabilities.filter(v => v.type === 'xss');
    if (xssVulns.length > 0) {
      recommendations.push('Use output encoding and Content Security Policy for XSS prevention');
    }

    const accessControlVulns = vulnerabilities.filter(v => v.type === 'broken_access_control');
    if (accessControlVulns.length > 0) {
      recommendations.push('Add proper authentication and authorization checks');
    }

    return recommendations;
  }

  private generateSecureCode(vulnerableCode: string, vulnerabilityType: string): string {
    switch (vulnerabilityType) {
      case 'sql_injection':
        return vulnerableCode.replace(
          /["'`].*?["'`]\s*\+\s*\w+/g,
          '"SELECT * FROM users WHERE id = ?"; db.query(query, [userId])'
        );
      case 'xss':
        return vulnerableCode.replace(
          /\.innerHTML\s*=\s*[^;]+/g,
          '.textContent = userInput; // or use DOMPurify.sanitize(userInput)'
        );
      default:
        return vulnerableCode + ' // Add security measures';
    }
  }

  private generateMarkdownReport(report: SecurityReportResult, example: DemoExample): string {
    return `# Security Analysis Report

## Summary
- **Total Vulnerabilities**: ${report.summary.totalVulnerabilities}
- **Risk Level**: ${report.summary.riskLevel}
- **Compliance Status**: ${report.summary.complianceStatus}

## Vulnerability Breakdown
${Object.entries(report.vulnerabilityBreakdown)
  .map(([type, count]) => `- **${type}**: ${count}`)
  .join('\n')}

## Recommendations
${report.recommendations.map(rec => `- ${rec}`).join('\n')}

## CVE Intelligence
- **Total Related CVEs**: ${report.cveIntelligence.totalCves}
- **High Severity CVEs**: ${report.cveIntelligence.highSeverityCves}

---
*Generated by RSOLV Security Demo Environment*
`;
  }
}