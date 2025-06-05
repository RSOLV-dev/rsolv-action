/**
 * Simple mock helpers that work with Bun's constraints
 */
import { mock } from 'bun:test';

export interface MockResponse {
  ok?: boolean;
  status?: number;
  statusText?: string;
  headers?: Record<string, string>;
  json?: any;
  text?: string;
  data?: any;
  url?: string;
}

/**
 * Create a properly typed Response object
 */
export function createMockResponse(options: MockResponse = {}): Response {
  const headers = new Headers(options.headers || {});
  const jsonData = options.json || options.data || {};
  
  return {
    ok: options.ok ?? true,
    status: options.status ?? 200,
    statusText: options.statusText || 'OK',
    headers,
    redirected: false,
    type: 'basic' as ResponseType,
    url: options.url || '',
    clone: function() { return this; },
    json: async () => jsonData,
    text: async () => options.text || JSON.stringify(jsonData),
    arrayBuffer: async () => new ArrayBuffer(0),
    blob: async () => new Blob([JSON.stringify(jsonData)]),
    formData: async () => new FormData(),
    body: null,
    bodyUsed: false
  } as Response;
}

/**
 * Create mock for AI responses
 */
export function mockAIResponse(content: string = 'AI response') {
  return {
    content: [{
      text: content
    }]
  };
}

/**
 * Setup fetch mock with queue system
 */
export function setupFetchMock() {
  let responseQueue: Array<() => Promise<Response>> = [];
  
  const fetchMock = mock((input: RequestInfo | URL, init?: RequestInit) => {
    if (responseQueue.length > 0) {
      const nextResponse = responseQueue.shift()!;
      return nextResponse();
    }
    
    console.warn(`[TEST] Unmocked fetch call to: ${input}`);
    return Promise.resolve(createMockResponse());
  });
  
  // Replace global fetch
  global.fetch = fetchMock as any;
  
  return {
    mock: fetchMock,
    mockResponseOnce: (response: MockResponse | Response) => {
      const res = response instanceof Response ? response : createMockResponse(response);
      responseQueue.push(() => Promise.resolve(res));
    },
    mockErrorOnce: (error: Error) => {
      responseQueue.push(() => Promise.reject(error));
    },
    reset: () => {
      responseQueue = [];
      fetchMock.mockClear();
    }
  };
}