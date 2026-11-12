import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest';
import { getAiClient } from '../../src/ai/client.js';
import { AiProviderConfig } from '../../src/types/index.js';

// Mock the logger
vi.mock('../../src/utils/logger.js', () => ({
  Logger: class {
    info = vi.fn();
    warn = vi.fn();
    error = vi.fn();
    debug = vi.fn();
  },
  logger: {
    info: vi.fn(),
    warn: vi.fn(),
    error: vi.fn(),
    debug: vi.fn()
  }
}));

const providerError = (status: number, message: string): Response =>
  new Response(JSON.stringify({ error: { message } }), {
    status,
    headers: { 'Content-Type': 'application/json' }
  });

const errorFrom = async (promise: Promise<unknown>): Promise<Error> => {
  const error = await promise.then(
    () => { throw new Error('expected the call to reject'); },
    (e: unknown) => e
  );
  expect(error).toBeInstanceOf(Error);
  return error as Error;
};

describe('Error Message Sanitization', () => {
  const fetchMock = vi.fn<typeof fetch>();

  const anthropicConfig: AiProviderConfig = {
    provider: 'anthropic',
    apiKey: 'test-key',
    model: 'claude-3'
  };

  const openaiConfig: AiProviderConfig = {
    provider: 'openai',
    apiKey: 'test-key',
    model: 'gpt-4'
  };

  const completeWith = async (config: AiProviderConfig): Promise<Error> => {
    const client = await getAiClient(config);
    return errorFrom(client.complete('Analyze this issue'));
  };

  beforeEach(() => {
    fetchMock.mockReset();
    vi.stubGlobal('fetch', fetchMock);
    // Without this the clients return canned text under NODE_ENV=test
    vi.stubEnv('FORCE_REAL_AI', 'true');
  });

  afterEach(() => {
    vi.unstubAllGlobals();
    vi.unstubAllEnvs();
  });

  test('should sanitize Anthropic-specific errors', async () => {
    fetchMock.mockResolvedValueOnce(
      providerError(400, 'Failed to connect to Anthropic API: model claude-3 is not available')
    );

    const { message } = await completeWith(anthropicConfig);

    expect(message).toMatch(/^AI provider error/);
    // Should not contain provider-specific information
    expect(message).not.toContain('Anthropic');
    expect(message).not.toContain('anthropic');
    expect(message).not.toContain('Claude');
    expect(message).not.toContain('claude');
  });

  test('should sanitize OpenAI-specific errors', async () => {
    fetchMock.mockResolvedValueOnce(
      providerError(400, 'OpenAI API error: the model gpt-4 does not exist (GPT)')
    );

    const { message } = await completeWith(openaiConfig);

    expect(message).toMatch(/^AI provider error/);
    // Should not contain provider-specific information
    expect(message).not.toContain('OpenAI');
    expect(message).not.toContain('openai');
    expect(message).not.toContain('GPT');
    expect(message).not.toContain('gpt');
  });

  test('should handle API key errors generically', async () => {
    const { message } = await errorFrom(getAiClient({ ...anthropicConfig, apiKey: '' }));

    // Should be a generic error message
    expect(message).toBe('AI provider API key is required');
    expect(message).not.toContain('Anthropic');
    expect(message).not.toContain('Claude');
  });

  test('should handle unsupported provider errors without exposing internal details', async () => {
    const { message } = await errorFrom(getAiClient({
      ...anthropicConfig,
      provider: 'secret-internal-provider'
    }));

    // This error can include the provider name since it's user input
    expect(message).toBe('Unsupported AI provider: secret-internal-provider');
  });

  test.each([
    { name: 'Anthropic', config: anthropicConfig, url: 'https://api.anthropic.com/v1/messages' },
    { name: 'OpenAI', config: openaiConfig, url: 'https://api.openai.com/v1/chat/completions' }
  ])('should sanitize network errors ($name)', async ({ config, url }) => {
    fetchMock.mockRejectedValueOnce(new TypeError(`Network error: Failed to fetch from ${url}`));

    const { message } = await completeWith(config);

    expect(message).toMatch(/^AI provider error/);
    // Should not contain API URLs or provider names
    expect(message).not.toContain('api.anthropic.com');
    expect(message).not.toContain('api.openai.com');
    expect(message).not.toContain('/v1/messages');
    expect(message).not.toContain('/chat/completions');
  });

  test('should provide helpful error messages without exposing implementation details', async () => {
    fetchMock.mockResolvedValueOnce(
      providerError(400, 'Failed to connect to Anthropic API: model claude-3 is not available')
    );

    const { message } = await completeWith(anthropicConfig);

    // Error message should be helpful but generic
    expect(message).toBeTruthy();
    expect(message.length).toBeGreaterThan(0);

    // Should contain generic error language
    expect(message).toMatch(/error|failed|unable|problem/i);
  });
});
