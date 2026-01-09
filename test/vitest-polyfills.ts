/**
 * Polyfills for Vitest Node.js environment
 * This file MUST be loaded before any other setup files
 * to ensure browser APIs are available for libraries like MSW
 */

// Create a proper Storage implementation
class MemoryStorage implements Storage {
  private storage: Record<string, string> = {};

  get length(): number {
    return Object.keys(this.storage).length;
  }

  clear(): void {
    this.storage = {};
  }

  getItem(key: string): string | null {
    return Object.prototype.hasOwnProperty.call(this.storage, key) ? this.storage[key] : null;
  }

  key(index: number): string | null {
    const keys = Object.keys(this.storage);
    return keys[index] ?? null;
  }

  removeItem(key: string): void {
    delete this.storage[key];
  }

  setItem(key: string, value: string): void {
    this.storage[key] = String(value);
  }

  // Allow indexing by string
  [key: string]: unknown;
}

// Polyfill localStorage for MSW (required in Node.js environment)
// MSW's CookieStore uses localStorage internally
if (typeof globalThis.localStorage === 'undefined' || !(globalThis.localStorage?.getItem instanceof Function)) {
  const memStorage = new MemoryStorage();
  Object.defineProperty(globalThis, 'localStorage', {
    value: memStorage,
    writable: true,
    configurable: true,
    enumerable: true
  });
}

// Polyfill sessionStorage as well (some libraries might use it)
if (typeof globalThis.sessionStorage === 'undefined' || !(globalThis.sessionStorage?.getItem instanceof Function)) {
  const memStorage = new MemoryStorage();
  Object.defineProperty(globalThis, 'sessionStorage', {
    value: memStorage,
    writable: true,
    configurable: true,
    enumerable: true
  });
}

console.log('[Vitest Polyfills] Browser API polyfills installed');
