/**
 * Mock Handler Helpers
 * Shared utilities for generating mock API responses
 */

/**
 * Generate mock security pattern
 */
export function generateMockPattern(id: string, type: string, lang: string) {
  return {
    id: `${lang}-${id}`,
    name: `Mock ${type.toUpperCase()} Detection`,
    type,
    description: `Mock pattern for ${type} detection in ${lang}`,
    severity: 'high' as const,
    regex: [`(${type}|mock).*pattern`],
    languages: [lang],
    recommendation: `Avoid ${type} vulnerabilities`,
    cwe_id: 'CWE-89',
    owasp_category: 'A03:2021'
  };
}

/**
 * Generate mock patterns for a specific language
 */
export function generateMockPatternsByLanguage(language: string): any[] {
  const patternsByLanguage: Record<string, any[]> = {
    javascript: [
      ...Array.from({ length: 10 }, (_, i) => generateMockPattern(`xss-${i}`, 'xss', 'javascript')),
      ...Array.from({ length: 10 }, (_, i) => generateMockPattern(`sql-${i}`, 'sql_injection', 'javascript')),
      ...Array.from({ length: 5 }, (_, i) => generateMockPattern(`cmd-${i}`, 'command_injection', 'javascript')),
      ...Array.from({ length: 5 }, (_, i) => generateMockPattern(`path-${i}`, 'path_traversal', 'javascript'))
    ],
    typescript: [
      ...Array.from({ length: 10 }, (_, i) => generateMockPattern(`xss-${i}`, 'xss', 'typescript')),
      ...Array.from({ length: 10 }, (_, i) => generateMockPattern(`sql-${i}`, 'sql_injection', 'typescript')),
      ...Array.from({ length: 5 }, (_, i) => generateMockPattern(`cmd-${i}`, 'command_injection', 'typescript')),
      ...Array.from({ length: 5 }, (_, i) => generateMockPattern(`path-${i}`, 'path_traversal', 'typescript'))
    ],
    python: [
      ...Array.from({ length: 5 }, (_, i) => generateMockPattern(`sql-${i}`, 'sql_injection', 'python')),
      ...Array.from({ length: 5 }, (_, i) => generateMockPattern(`cmd-${i}`, 'command_injection', 'python')),
      ...Array.from({ length: 3 }, (_, i) => generateMockPattern(`path-${i}`, 'path_traversal', 'python')),
      ...Array.from({ length: 2 }, (_, i) => generateMockPattern(`deser-${i}`, 'insecure_deserialization', 'python'))
    ],
    ruby: [
      ...Array.from({ length: 8 }, (_, i) => generateMockPattern(`sql-${i}`, 'sql_injection', 'ruby')),
      ...Array.from({ length: 5 }, (_, i) => generateMockPattern(`cmd-${i}`, 'command_injection', 'ruby')),
      ...Array.from({ length: 3 }, (_, i) => generateMockPattern(`xss-${i}`, 'xss', 'ruby'))
    ],
    php: [
      ...Array.from({ length: 8 }, (_, i) => generateMockPattern(`xss-${i}`, 'xss', 'php')),
      ...Array.from({ length: 8 }, (_, i) => generateMockPattern(`sql-${i}`, 'sql_injection', 'php')),
      ...Array.from({ length: 5 }, (_, i) => generateMockPattern(`upload-${i}`, 'file_upload', 'php'))
    ],
    java: [
      ...Array.from({ length: 8 }, (_, i) => generateMockPattern(`sql-${i}`, 'sql_injection', 'java')),
      ...Array.from({ length: 5 }, (_, i) => generateMockPattern(`xxe-${i}`, 'xxe', 'java')),
      ...Array.from({ length: 4 }, (_, i) => generateMockPattern(`deser-${i}`, 'deserialization', 'java'))
    ],
    elixir: [
      ...Array.from({ length: 3 }, (_, i) => generateMockPattern(`sql-${i}`, 'sql_injection', 'elixir')),
      ...Array.from({ length: 2 }, (_, i) => generateMockPattern(`xss-${i}`, 'xss', 'elixir')),
      ...Array.from({ length: 2 }, (_, i) => generateMockPattern(`csrf-${i}`, 'csrf', 'elixir'))
    ]
  };

  return patternsByLanguage[language] || patternsByLanguage.javascript;
}

/**
 * Format test code based on framework and language
 */
export function formatTestCode(testName: string, testCode: string, framework: string, language: string): string {
  if (framework === 'rspec' || language === 'ruby') {
    return `  it '${testName}' do\n    ${testCode}\n  end`;
  }

  if (framework === 'vitest' || framework === 'jest' || language === 'javascript' || language === 'typescript') {
    return `  it('${testName}', () => {\n    ${testCode}\n  });`;
  }

  if (framework === 'pytest' || language === 'python') {
    return `def ${testName}():\n    ${testCode}`;
  }

  return testCode;
}

/**
 * Generate mock test integration analyze response
 */
export function createMockAnalyzeResponse(body: Record<string, any>) {
  const candidateFiles = body?.candidateTestFiles || [];

  const recommendations = candidateFiles.map((file: string, index: number) => ({
    path: file,
    score: 0.8 - (index * 0.1),
    reason: 'File path similarity and test framework match'
  }));

  return {
    recommendations,
    fallback: {
      path: `spec/security/${body?.vulnerableFile?.split('/').pop()?.replace('.rb', '')}_security_spec.rb`,
      reason: 'No existing test found - suggest creating new security test file'
    }
  };
}

/**
 * Generate mock test integration generate response
 */
export function createMockGenerateResponse(body: Record<string, any>) {
  const targetContent = body?.targetFileContent || '';
  const redTests = body?.testSuite?.redTests || [];
  const framework = body?.framework || 'rspec';
  const language = body?.language || 'ruby';

  const securityTests = redTests
    .map((test: any) => formatTestCode(test.testName, test.testCode, framework, language))
    .join('\n\n');

  const integratedContent = targetContent + '\n\n' + securityTests;

  return {
    integratedContent,
    method: 'ast' as const,
    insertionPoint: {
      line: targetContent.split('\n').length,
      strategy: 'append_to_describe_block'
    }
  };
}

/**
 * Create mock credentials response
 */
export function createMockCredentials(prefix = '') {
  const suffix = prefix ? `_${prefix}_` : '_';

  return {
    success: true,
    credentials: {
      anthropic: {
        api_key: `temp_ant${suffix}` + Math.random().toString(36).substr(2, 9),
        expires_at: new Date(Date.now() + 3600000).toISOString()
      },
      openai: {
        api_key: `temp_oai${suffix}` + Math.random().toString(36).substr(2, 9),
        expires_at: new Date(Date.now() + 3600000).toISOString()
      },
      openrouter: {
        api_key: `temp_or${suffix}` + Math.random().toString(36).substr(2, 9),
        expires_at: new Date(Date.now() + 3600000).toISOString()
      }
    },
    usage: {
      remaining_fixes: 999999,
      reset_at: new Date(Date.now() + 86400000).toISOString()
    }
  };
}
