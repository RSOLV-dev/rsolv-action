/**
 * Mock Factory System for Bun Tests
 * Provides isolated mock instances for each test
 */
import { mock, Mock } from 'bun:test';

// Type definitions for our mocks
export interface FetchMock extends Mock<typeof fetch> {
  mockResolvedValueOnce: (value: any) => FetchMock;
  mockRejectedValueOnce: (error: any) => FetchMock;
  mockImplementationOnce: (fn: (...args: any[]) => any) => FetchMock;
}

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
function createMockResponse(options: MockResponse = {}): Response {
  const headers = new Headers(options.headers || {});
  const body = options.json ? JSON.stringify(options.json) : (options.text || '');
  
  return {
    ok: options.ok ?? true,
    status: options.status ?? 200,
    statusText: options.statusText || 'OK',
    headers,
    redirected: false,
    type: 'basic' as ResponseType,
    url: options.url || '',
    clone: function() { return this; },
    json: async () => options.json || options.data || {},
    text: async () => options.text || (options.json ? JSON.stringify(options.json) : ''),
    arrayBuffer: async () => new ArrayBuffer(0),
    blob: async () => new Blob([body]),
    formData: async () => new FormData(),
    body: null,
    bodyUsed: false
  } as Response;
}

/**
 * Create an isolated fetch mock with convenience methods
 */
export function createFetchMock(): FetchMock {
  let mockImplementation: ((input: RequestInfo | URL, init?: RequestInit) => Promise<Response>) | null = null;
  let mockQueue: Array<() => Promise<Response>> = [];
  
  const fetchMock = mock((input: RequestInfo | URL, init?: RequestInit) => {
    // Check if we have a queued response
    if (mockQueue.length > 0) {
      const nextMock = mockQueue.shift()!;
      return nextMock();
    }
    
    // Check if we have a custom implementation
    if (mockImplementation) {
      return mockImplementation(input, init);
    }
    
    // Default mock response
    console.warn(`[TEST] Unmocked fetch call to: ${input}`);
    return Promise.resolve(createMockResponse());
  });

  // Return the mock function directly, but add our convenience methods
  // by attaching them to the function object
  const enhancedMock = Object.assign(fetchMock, {
    mockResolvedValueOnce: function(value: MockResponse | Response) {
      const response = value instanceof Response ? value : createMockResponse(value);
      mockQueue.push(() => Promise.resolve(response));
      return this;
    },
    mockRejectedValueOnce: function(error: any) {
      mockQueue.push(() => Promise.reject(error));
      return this;
    },
    mockImplementation: function(fn: (input: RequestInfo | URL, init?: RequestInit) => Promise<Response>) {
      mockImplementation = fn;
      return this;
    },
    mockImplementationOnce: function(fn: () => Promise<Response>) {
      mockQueue.push(fn);
      return this;
    }
  });

  return enhancedMock as FetchMock;
}

/**
 * Create a mock AI client response
 */
export function createAIMockResponse(content: string = 'AI response') {
  return {
    content: [{
      text: content
    }]
  };
}

/**
 * Create a mock GitHub API response
 */
export function createGitHubMockResponse(data: any) {
  return createMockResponse({
    ok: true,
    status: 200,
    json: data,
    headers: {
      'content-type': 'application/json'
    }
  });
}

/**
 * Create a mock RSOLV API response
 */
export function createRSOLVApiMockResponse(data: any = {}) {
  return createMockResponse({
    ok: true,
    status: 200,
    json: {
      success: true,
      ...data
    }
  });
}

/**
 * Mock module system for common dependencies
 */
export const mockModules = {
  fs: () => ({
    writeFileSync: mock(() => {}),
    readFileSync: mock(() => ''),
    existsSync: mock(() => true),
    mkdirSync: mock(() => {}),
    unlinkSync: mock(() => {}),
    readdirSync: mock(() => []),
    statSync: mock(() => ({ isDirectory: () => false }))
  }),

  childProcess: () => ({
    spawn: mock(() => {
      const eventHandlers: Record<string, Array<(...args: any[]) => void>> = {};
      
      const createStream = (prefix: string) => ({
        on: (event: string, handler: (...args: any[]) => void) => {
          const key = `${prefix}:${event}`;
          if (!eventHandlers[key]) {
            eventHandlers[key] = [];
          }
          eventHandlers[key].push(handler);
          
          // Auto-trigger 'end' event after 'data'
          if (event === 'data') {
            setTimeout(() => {
              const endHandlers = eventHandlers[`${prefix}:end`];
              if (endHandlers) {
                endHandlers.forEach(h => h());
              }
            }, 0);
          }
          
          return this;
        },
        emit: (event: string, ...args: any[]) => {
          const key = `${prefix}:${event}`;
          if (eventHandlers[key]) {
            eventHandlers[key].forEach(h => h(...args));
          }
        }
      });

      const proc = {
        stdout: createStream('stdout'),
        stderr: createStream('stderr'),
        on: (event: string, handler: (...args: any[]) => void) => {
          if (!eventHandlers[event]) {
            eventHandlers[event] = [];
          }
          eventHandlers[event].push(handler);
          
          // Auto-close after streams end
          if (event === 'close') {
            setTimeout(() => handler(0, null), 10);
          }
          
          return proc;
        },
        emit: (event: string, ...args: any[]) => {
          if (eventHandlers[event]) {
            eventHandlers[event].forEach(h => h(...args));
          }
        }
      };
      
      return proc;
    }),
    execSync: mock(() => Buffer.from(''))
  })
};

/**
 * Test context for managing mocks
 */
export interface TestContext {
  fetchMock: FetchMock;
  mocks: {
    fs?: ReturnType<typeof mockModules.fs>;
    childProcess?: ReturnType<typeof mockModules.childProcess>;
  };
}

/**
 * Create a test context with isolated mocks
 */
export function createTestContext(): TestContext {
  return {
    fetchMock: createFetchMock(),
    mocks: {}
  };
}

/**
 * Setup test environment with context
 */
export function setupTestEnvironment(ctx: TestContext) {
  // Replace global fetch with our mock function
  // The fetchMock is a function returned by mock(), not the wrapper object
  global.fetch = ctx.fetchMock as any;
  
  // Set test environment
  process.env.NODE_ENV = 'test';
  process.env.GITHUB_JOB = 'test_job';
  process.env.GITHUB_RUN_ID = 'test_run';
}

/**
 * Cleanup test environment
 */
export function cleanupTestEnvironment() {
  // Restore mocks
  mock.restore();
  
  // Don't restore global.fetch here - let setup-tests.ts handle it
}