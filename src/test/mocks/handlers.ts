/**
 * MSW Request Handlers
 * Define API mocks for all external services
 */

import { http, HttpResponse } from 'msw';

// Default test data
const mockIssue = {
  id: 1,
  number: 123,
  title: 'Test Issue',
  body: 'Test issue body',
  state: 'open',
  labels: [{ name: 'rsolv:automate' }],
  user: { login: 'testuser' },
  created_at: new Date().toISOString(),
  updated_at: new Date().toISOString()
};

const mockPR = {
  number: 456,
  html_url: 'https://github.com/test/repo/pull/456',
  state: 'open',
  title: 'Fix: Test Issue',
  body: 'This PR fixes the test issue'
};

export const handlers = [
  
  // GitHub API handlers
  http.get('https://api.github.com/repos/:owner/:repo/issues/:number', ({ params }) => {
    return HttpResponse.json({
      ...mockIssue,
      number: parseInt(params.number as string),
      repository_url: `https://api.github.com/repos/${params.owner}/${params.repo}`
    });
  }),

  http.post('https://api.github.com/repos/:owner/:repo/pulls', async ({ request }) => {
    const body = await request.json() as Record<string, any>;
    return HttpResponse.json({
      ...mockPR,
      title: body?.title || mockPR.title,
      body: body?.body || mockPR.body
    }, { status: 201 });
  }),

  http.get('https://api.github.com/repos/:owner/:repo/labels', () => {
    return HttpResponse.json([
      { name: 'rsolv:automate', color: 'ff0000' },
      { name: 'bug', color: '00ff00' },
      { name: 'enhancement', color: '0000ff' }
    ]);
  }),

  http.post('https://api.github.com/repos/:owner/:repo/labels', async ({ request }) => {
    const body = await request.json() as Record<string, any>;
    return HttpResponse.json({
      name: body?.name || 'label',
      color: body?.color || 'cccccc'
    }, { status: 201 });
  }),

  // RSOLV API handlers
  http.post('https://api.rsolv.ai/v1/validate', async ({ request }) => {
    const body = await request.json() as Record<string, any>;
    return HttpResponse.json({
      success: true,
      vulnerabilities: body?.vulnerabilities || [],
      validated: true,
      confidence: 0.95
    });
  }),

  http.post('https://api.rsolv.ai/v1/ast/analyze', async ({ request }) => {
    const body = await request.json() as Record<string, any>;
    return HttpResponse.json({
      success: true,
      findings: [],
      patterns_checked: body?.patterns?.length || 0,
      files_analyzed: 1
    });
  }),

  http.post('https://api.rsolv.ai/v1/credentials/vend', () => {
    return HttpResponse.json({
      success: true,
      credentials: {
        anthropic: {
          apiKey: 'test-vended-key',
          expiresAt: new Date(Date.now() + 3600000).toISOString()
        }
      }
    });
  }),

  // RSOLV Credential Exchange endpoint
  http.post('https://api.rsolv.ai/api/v1/credentials/exchange', () => {
    return HttpResponse.json({
      success: true,
      credentials: {
        anthropic: {
          api_key: 'temp_ant_' + Math.random().toString(36).substr(2, 9),
          expires_at: new Date(Date.now() + 3600000).toISOString()
        },
        openai: {
          api_key: 'temp_oai_' + Math.random().toString(36).substr(2, 9),
          expires_at: new Date(Date.now() + 3600000).toISOString()
        },
        openrouter: {
          api_key: 'temp_or_' + Math.random().toString(36).substr(2, 9),
          expires_at: new Date(Date.now() + 3600000).toISOString()
        }
      },
      usage: {
        remaining_fixes: 999999,
        reset_at: new Date(Date.now() + 86400000).toISOString()
      }
    });
  }),

  // RSOLV Patterns endpoint
  http.get('https://api.rsolv.ai/api/v1/patterns', ({ request }) => {
    // Accept any API key in tests (no auth check needed for mocks)
    const url = new URL(request.url);
    const language = url.searchParams.get('language') || 'javascript';
    const format = url.searchParams.get('format') || 'standard';

    // Helper to generate mock patterns
    const generatePattern = (id: string, type: string, lang: string) => ({
      id: `${lang}-${id}`,
      name: `Mock ${type.toUpperCase()} Detection`,
      type,
      description: `Mock pattern for ${type} detection in ${lang}`,
      severity: 'high',
      regex: [`(${type}|mock).*pattern`],
      languages: [lang],
      recommendation: `Avoid ${type} vulnerabilities`,
      cwe_id: 'CWE-89',
      owasp_category: 'A03:2021'
    });

    // Generate patterns based on language requirements from test
    const patternsByLanguage: Record<string, any[]> = {
      javascript: [
        ...Array.from({ length: 10 }, (_, i) => generatePattern(`xss-${i}`, 'xss', 'javascript')),
        ...Array.from({ length: 10 }, (_, i) => generatePattern(`sql-${i}`, 'sql_injection', 'javascript')),
        ...Array.from({ length: 5 }, (_, i) => generatePattern(`cmd-${i}`, 'command_injection', 'javascript')),
        ...Array.from({ length: 5 }, (_, i) => generatePattern(`path-${i}`, 'path_traversal', 'javascript'))
      ],
      typescript: [
        ...Array.from({ length: 10 }, (_, i) => generatePattern(`xss-${i}`, 'xss', 'typescript')),
        ...Array.from({ length: 10 }, (_, i) => generatePattern(`sql-${i}`, 'sql_injection', 'typescript')),
        ...Array.from({ length: 5 }, (_, i) => generatePattern(`cmd-${i}`, 'command_injection', 'typescript')),
        ...Array.from({ length: 5 }, (_, i) => generatePattern(`path-${i}`, 'path_traversal', 'typescript'))
      ],
      python: [
        ...Array.from({ length: 5 }, (_, i) => generatePattern(`sql-${i}`, 'sql_injection', 'python')),
        ...Array.from({ length: 5 }, (_, i) => generatePattern(`cmd-${i}`, 'command_injection', 'python')),
        ...Array.from({ length: 3 }, (_, i) => generatePattern(`path-${i}`, 'path_traversal', 'python')),
        ...Array.from({ length: 2 }, (_, i) => generatePattern(`deser-${i}`, 'insecure_deserialization', 'python'))
      ],
      ruby: [
        ...Array.from({ length: 8 }, (_, i) => generatePattern(`sql-${i}`, 'sql_injection', 'ruby')),
        ...Array.from({ length: 5 }, (_, i) => generatePattern(`cmd-${i}`, 'command_injection', 'ruby')),
        ...Array.from({ length: 3 }, (_, i) => generatePattern(`xss-${i}`, 'xss', 'ruby'))
      ],
      php: [
        ...Array.from({ length: 8 }, (_, i) => generatePattern(`xss-${i}`, 'xss', 'php')),
        ...Array.from({ length: 8 }, (_, i) => generatePattern(`sql-${i}`, 'sql_injection', 'php')),
        ...Array.from({ length: 5 }, (_, i) => generatePattern(`upload-${i}`, 'file_upload', 'php'))
      ],
      java: [
        ...Array.from({ length: 8 }, (_, i) => generatePattern(`sql-${i}`, 'sql_injection', 'java')),
        ...Array.from({ length: 5 }, (_, i) => generatePattern(`xxe-${i}`, 'xxe', 'java')),
        ...Array.from({ length: 4 }, (_, i) => generatePattern(`deser-${i}`, 'deserialization', 'java'))
      ],
      elixir: [
        ...Array.from({ length: 3 }, (_, i) => generatePattern(`sql-${i}`, 'sql_injection', 'elixir')),
        ...Array.from({ length: 2 }, (_, i) => generatePattern(`xss-${i}`, 'xss', 'elixir')),
        ...Array.from({ length: 2 }, (_, i) => generatePattern(`csrf-${i}`, 'csrf', 'elixir'))
      ]
    };

    const patterns = patternsByLanguage[language] || patternsByLanguage.javascript;

    return HttpResponse.json({
      patterns,
      metadata: {
        count: patterns.length,
        language,
        format,
        access_level: 'full'
      }
    });
  }),

  // RSOLV.dev API handlers (production default URL)
  // Test Integration - Analyze endpoint
  http.post('https://api.rsolv.dev/api/v1/test-integration/analyze', async ({ request }) => {
    const body = await request.json() as Record<string, any>;
    const candidateFiles = body?.candidateTestFiles || [];

    // Generate scored recommendations based on file paths
    const recommendations = candidateFiles.map((file: string, index: number) => ({
      path: file,
      score: 0.8 - (index * 0.1), // Descending scores
      reason: `File path similarity and test framework match`
    }));

    return HttpResponse.json({
      recommendations,
      fallback: {
        path: `spec/security/${body?.vulnerableFile?.split('/').pop()?.replace('.rb', '')}_security_spec.rb`,
        reason: 'No existing test found - suggest creating new security test file'
      }
    });
  }),

  // Test Integration - Generate endpoint
  http.post('https://api.rsolv.dev/api/v1/test-integration/generate', async ({ request }) => {
    const body = await request.json() as Record<string, any>;
    const targetContent = body?.targetFileContent || '';
    const redTests = body?.testSuite?.redTests || [];

    // Generate integrated content by appending security tests
    const securityTests = redTests.map((test: any) => {
      const framework = body?.framework || 'rspec';
      const language = body?.language || 'ruby';

      // Format test based on framework/language
      if (framework === 'rspec' || language === 'ruby') {
        return `  it '${test.testName}' do\n    ${test.testCode}\n  end`;
      } else if (framework === 'vitest' || framework === 'jest' || language === 'javascript' || language === 'typescript') {
        return `  it('${test.testName}', () => {\n    ${test.testCode}\n  });`;
      } else if (framework === 'pytest' || language === 'python') {
        return `def ${test.testName}():\n    ${test.testCode}`;
      }
      return test.testCode;
    }).join('\n\n');

    const integratedContent = targetContent + '\n\n' + securityTests;

    return HttpResponse.json({
      integratedContent,
      method: 'ast',
      insertionPoint: {
        line: targetContent.split('\n').length,
        strategy: 'append_to_describe_block'
      }
    });
  }),

  http.get('https://api.rsolv.dev/api/v1/patterns', ({ request }) => {
    const url = new URL(request.url);
    const language = url.searchParams.get('language') || 'javascript';
    const format = url.searchParams.get('format') || 'standard';

    // Helper to generate mock patterns
    const generatePattern = (id: string, type: string, lang: string) => ({
      id: `${lang}-${id}`,
      name: `Mock ${type.toUpperCase()} Detection`,
      type,
      description: `Mock pattern for ${type} detection in ${lang}`,
      severity: 'high',
      regex: [`(${type}|mock).*pattern`],
      languages: [lang],
      recommendation: `Avoid ${type} vulnerabilities`,
      cwe_id: 'CWE-89',
      owasp_category: 'A03:2021'
    });

    // Generate patterns based on language requirements from test
    const patternsByLanguage: Record<string, any[]> = {
      javascript: [
        ...Array.from({ length: 10 }, (_, i) => generatePattern(`xss-${i}`, 'xss', 'javascript')),
        ...Array.from({ length: 10 }, (_, i) => generatePattern(`sql-${i}`, 'sql_injection', 'javascript')),
        ...Array.from({ length: 5 }, (_, i) => generatePattern(`cmd-${i}`, 'command_injection', 'javascript')),
        ...Array.from({ length: 5 }, (_, i) => generatePattern(`path-${i}`, 'path_traversal', 'javascript'))
      ],
      typescript: [
        ...Array.from({ length: 10 }, (_, i) => generatePattern(`xss-${i}`, 'xss', 'typescript')),
        ...Array.from({ length: 10 }, (_, i) => generatePattern(`sql-${i}`, 'sql_injection', 'typescript')),
        ...Array.from({ length: 5 }, (_, i) => generatePattern(`cmd-${i}`, 'command_injection', 'typescript')),
        ...Array.from({ length: 5 }, (_, i) => generatePattern(`path-${i}`, 'path_traversal', 'typescript'))
      ],
      python: [
        ...Array.from({ length: 5 }, (_, i) => generatePattern(`sql-${i}`, 'sql_injection', 'python')),
        ...Array.from({ length: 5 }, (_, i) => generatePattern(`cmd-${i}`, 'command_injection', 'python')),
        ...Array.from({ length: 3 }, (_, i) => generatePattern(`path-${i}`, 'path_traversal', 'python')),
        ...Array.from({ length: 2 }, (_, i) => generatePattern(`deser-${i}`, 'insecure_deserialization', 'python'))
      ],
      ruby: [
        ...Array.from({ length: 8 }, (_, i) => generatePattern(`sql-${i}`, 'sql_injection', 'ruby')),
        ...Array.from({ length: 5 }, (_, i) => generatePattern(`cmd-${i}`, 'command_injection', 'ruby')),
        ...Array.from({ length: 3 }, (_, i) => generatePattern(`xss-${i}`, 'xss', 'ruby'))
      ],
      php: [
        ...Array.from({ length: 8 }, (_, i) => generatePattern(`xss-${i}`, 'xss', 'php')),
        ...Array.from({ length: 8 }, (_, i) => generatePattern(`sql-${i}`, 'sql_injection', 'php')),
        ...Array.from({ length: 5 }, (_, i) => generatePattern(`upload-${i}`, 'file_upload', 'php'))
      ],
      java: [
        ...Array.from({ length: 8 }, (_, i) => generatePattern(`sql-${i}`, 'sql_injection', 'java')),
        ...Array.from({ length: 5 }, (_, i) => generatePattern(`xxe-${i}`, 'xxe', 'java')),
        ...Array.from({ length: 4 }, (_, i) => generatePattern(`deser-${i}`, 'deserialization', 'java'))
      ],
      elixir: [
        ...Array.from({ length: 3 }, (_, i) => generatePattern(`sql-${i}`, 'sql_injection', 'elixir')),
        ...Array.from({ length: 2 }, (_, i) => generatePattern(`xss-${i}`, 'xss', 'elixir')),
        ...Array.from({ length: 2 }, (_, i) => generatePattern(`csrf-${i}`, 'csrf', 'elixir'))
      ]
    };

    const patterns = patternsByLanguage[language] || patternsByLanguage.javascript;

    return HttpResponse.json({
      patterns,
      metadata: {
        count: patterns.length,
        language,
        format,
        access_level: 'full'
      }
    });
  }),

  // RSOLV Staging API handlers
  http.post('https://api.rsolv-staging.com/api/v1/credentials/exchange', () => {
    return HttpResponse.json({
      success: true,
      credentials: {
        anthropic: {
          api_key: 'temp_ant_staging_' + Math.random().toString(36).substr(2, 9),
          expires_at: new Date(Date.now() + 3600000).toISOString()
        },
        openai: {
          api_key: 'temp_oai_staging_' + Math.random().toString(36).substr(2, 9),
          expires_at: new Date(Date.now() + 3600000).toISOString()
        },
        openrouter: {
          api_key: 'temp_or_staging_' + Math.random().toString(36).substr(2, 9),
          expires_at: new Date(Date.now() + 3600000).toISOString()
        }
      },
      usage: {
        remaining_fixes: 999999,
        reset_at: new Date(Date.now() + 86400000).toISOString()
      }
    });
  }),

  // RSOLV Staging Test Integration - Analyze endpoint
  http.post('https://api.rsolv-staging.com/api/v1/test-integration/analyze', async ({ request }) => {
    const body = await request.json() as Record<string, any>;
    const candidateFiles = body?.candidateTestFiles || [];

    // Generate scored recommendations based on file paths
    const recommendations = candidateFiles.map((file: string, index: number) => ({
      path: file,
      score: 0.8 - (index * 0.1), // Descending scores
      reason: `File path similarity and test framework match`
    }));

    return HttpResponse.json({
      recommendations,
      fallback: {
        path: `spec/security/${body?.vulnerableFile?.split('/').pop()?.replace('.rb', '')}_security_spec.rb`,
        reason: 'No existing test found - suggest creating new security test file'
      }
    });
  }),

  // RSOLV Staging Test Integration - Generate endpoint
  http.post('https://api.rsolv-staging.com/api/v1/test-integration/generate', async ({ request }) => {
    const body = await request.json() as Record<string, any>;
    const targetContent = body?.targetFileContent || '';
    const redTests = body?.testSuite?.redTests || [];

    // Generate integrated content by appending security tests
    const securityTests = redTests.map((test: any) => {
      const framework = body?.framework || 'rspec';
      const language = body?.language || 'ruby';

      // Format test based on framework/language
      if (framework === 'rspec' || language === 'ruby') {
        return `  it '${test.testName}' do\n    ${test.testCode}\n  end`;
      } else if (framework === 'vitest' || framework === 'jest' || language === 'javascript' || language === 'typescript') {
        return `  it('${test.testName}', () => {\n    ${test.testCode}\n  });`;
      } else if (framework === 'pytest' || language === 'python') {
        return `def ${test.testName}():\n    ${test.testCode}`;
      }
      return test.testCode;
    }).join('\n\n');

    const integratedContent = targetContent + '\n\n' + securityTests;

    return HttpResponse.json({
      integratedContent,
      method: 'ast',
      insertionPoint: {
        line: targetContent.split('\n').length,
        strategy: 'append_to_describe_block'
      }
    });
  }),

  http.get('https://api.rsolv-staging.com/api/v1/patterns', ({ request }) => {
    const url = new URL(request.url);
    const language = url.searchParams.get('language') || 'javascript';
    const format = url.searchParams.get('format') || 'standard';

    // Helper to generate mock patterns
    const generatePattern = (id: string, type: string, lang: string) => ({
      id: `${lang}-${id}`,
      name: `Mock ${type.toUpperCase()} Detection`,
      type,
      description: `Mock pattern for ${type} detection in ${lang}`,
      severity: 'high',
      regex: [`(${type}|mock).*pattern`],
      languages: [lang],
      recommendation: `Avoid ${type} vulnerabilities`,
      cwe_id: 'CWE-89',
      owasp_category: 'A03:2021'
    });

    // Generate patterns based on language requirements from test
    const patternsByLanguage: Record<string, any[]> = {
      javascript: [
        ...Array.from({ length: 10 }, (_, i) => generatePattern(`xss-${i}`, 'xss', 'javascript')),
        ...Array.from({ length: 10 }, (_, i) => generatePattern(`sql-${i}`, 'sql_injection', 'javascript')),
        ...Array.from({ length: 5 }, (_, i) => generatePattern(`cmd-${i}`, 'command_injection', 'javascript')),
        ...Array.from({ length: 5 }, (_, i) => generatePattern(`path-${i}`, 'path_traversal', 'javascript'))
      ],
      typescript: [
        ...Array.from({ length: 10 }, (_, i) => generatePattern(`xss-${i}`, 'xss', 'typescript')),
        ...Array.from({ length: 10 }, (_, i) => generatePattern(`sql-${i}`, 'sql_injection', 'typescript')),
        ...Array.from({ length: 5 }, (_, i) => generatePattern(`cmd-${i}`, 'command_injection', 'typescript')),
        ...Array.from({ length: 5 }, (_, i) => generatePattern(`path-${i}`, 'path_traversal', 'typescript'))
      ],
      python: [
        ...Array.from({ length: 5 }, (_, i) => generatePattern(`sql-${i}`, 'sql_injection', 'python')),
        ...Array.from({ length: 5 }, (_, i) => generatePattern(`cmd-${i}`, 'command_injection', 'python')),
        ...Array.from({ length: 3 }, (_, i) => generatePattern(`path-${i}`, 'path_traversal', 'python')),
        ...Array.from({ length: 2 }, (_, i) => generatePattern(`deser-${i}`, 'insecure_deserialization', 'python'))
      ],
      ruby: [
        ...Array.from({ length: 8 }, (_, i) => generatePattern(`sql-${i}`, 'sql_injection', 'ruby')),
        ...Array.from({ length: 5 }, (_, i) => generatePattern(`cmd-${i}`, 'command_injection', 'ruby')),
        ...Array.from({ length: 3 }, (_, i) => generatePattern(`xss-${i}`, 'xss', 'ruby'))
      ],
      php: [
        ...Array.from({ length: 8 }, (_, i) => generatePattern(`xss-${i}`, 'xss', 'php')),
        ...Array.from({ length: 8 }, (_, i) => generatePattern(`sql-${i}`, 'sql_injection', 'php')),
        ...Array.from({ length: 5 }, (_, i) => generatePattern(`upload-${i}`, 'file_upload', 'php'))
      ],
      java: [
        ...Array.from({ length: 8 }, (_, i) => generatePattern(`sql-${i}`, 'sql_injection', 'java')),
        ...Array.from({ length: 5 }, (_, i) => generatePattern(`xxe-${i}`, 'xxe', 'java')),
        ...Array.from({ length: 4 }, (_, i) => generatePattern(`deser-${i}`, 'deserialization', 'java'))
      ],
      elixir: [
        ...Array.from({ length: 3 }, (_, i) => generatePattern(`sql-${i}`, 'sql_injection', 'elixir')),
        ...Array.from({ length: 2 }, (_, i) => generatePattern(`xss-${i}`, 'xss', 'elixir')),
        ...Array.from({ length: 2 }, (_, i) => generatePattern(`csrf-${i}`, 'csrf', 'elixir'))
      ]
    };

    const patterns = patternsByLanguage[language] || patternsByLanguage.javascript;

    return HttpResponse.json({
      patterns,
      metadata: {
        count: patterns.length,
        language,
        format,
        access_level: 'full'
      }
    });
  }),

  // Anthropic API handlers
  http.post('https://api.anthropic.com/v1/messages', async ({ request }) => {
    const body = await request.json() as Record<string, any>;
    return HttpResponse.json({
      id: 'msg_test',
      type: 'message',
      role: 'assistant',
      content: [{
        type: 'text',
        text: 'I have fixed the issue by updating the code.'
      }],
      model: body?.model || 'claude-3-sonnet-20240229',
      usage: {
        input_tokens: 100,
        output_tokens: 50
      }
    });
  }),

  // OpenRouter API handlers
  http.post('https://openrouter.ai/api/v1/chat/completions', async ({ request }) => {
    const body = await request.json() as Record<string, any>;
    return HttpResponse.json({
      id: 'chatcmpl-test',
      object: 'chat.completion',
      created: Date.now(),
      model: body?.model || 'anthropic/claude-3-sonnet',
      choices: [{
        index: 0,
        message: {
          role: 'assistant',
          content: 'I have analyzed the issue and generated a fix.'
        },
        finish_reason: 'stop'
      }],
      usage: {
        prompt_tokens: 100,
        completion_tokens: 50,
        total_tokens: 150
      }
    });
  }),

  // Postmark API handlers
  http.post('https://api.postmarkapp.com/email', async ({ request }) => {
    const body = await request.json() as Record<string, any>;
    return HttpResponse.json({
      To: body?.To || '',
      SubmittedAt: new Date().toISOString(),
      MessageID: 'test-message-id',
      ErrorCode: 0,
      Message: 'OK'
    });
  }),

  // Slack Webhook handlers
  http.post('https://hooks.slack.com/services/*', () => {
    return HttpResponse.text('ok', { status: 200 });
  }),

  // Generic fallback for unhandled requests
  http.get('*', ({ request }) => {
    console.warn(`Unhandled GET request: ${request.url}`);
    return HttpResponse.json({ error: 'Not found' }, { status: 404 });
  }),

  http.post('*', ({ request }) => {
    console.warn(`Unhandled POST request: ${request.url}`);
    return HttpResponse.json({ error: 'Not found' }, { status: 404 });
  })
];