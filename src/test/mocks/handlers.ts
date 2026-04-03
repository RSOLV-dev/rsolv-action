/**
 * MSW Request Handlers
 * Define API mocks for all external services
 */

import { http, HttpResponse } from 'msw';
import { createMockCredentials } from './helpers.js';
import { createTestIntegrationHandlers } from './test-integration-handlers.js';
import { createPatternHandler } from './pattern-handlers.js';

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

  // RSOLV API handlers (api.rsolv.ai - legacy)
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

  http.post('https://api.rsolv.ai/api/v1/credentials/exchange', () => {
    return HttpResponse.json(createMockCredentials());
  }),

  createPatternHandler('https://api.rsolv.ai'),

  // RSOLV.dev API handlers (production default URL)
  ...createTestIntegrationHandlers('https://api.rsolv.dev'),
  createPatternHandler('https://api.rsolv.dev'),

  // RSOLV Staging API handlers
  http.post('https://api.rsolv-staging.com/api/v1/credentials/exchange', () => {
    return HttpResponse.json(createMockCredentials('staging'));
  }),

  ...createTestIntegrationHandlers('https://api.rsolv-staging.com'),
  createPatternHandler('https://api.rsolv-staging.com'),

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
      model: body?.model || 'claude-sonnet-4-5-20250929',
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
      model: body?.model || 'anthropic/claude-sonnet-4-5-20250929',
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
