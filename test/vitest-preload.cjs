/**
 * Preload script for Vitest
 * This runs BEFORE any modules are loaded, ensuring polyfills are available
 * for libraries like MSW that access browser APIs at module load time.
 *
 * Must be CommonJS (.cjs) to work with Node's --require flag
 */

// Create a proper Storage implementation
class MemoryStorage {
  constructor() {
    this._storage = {};
  }

  get length() {
    return Object.keys(this._storage).length;
  }

  clear() {
    this._storage = {};
  }

  getItem(key) {
    return Object.prototype.hasOwnProperty.call(this._storage, key) ? this._storage[key] : null;
  }

  key(index) {
    const keys = Object.keys(this._storage);
    return keys[index] || null;
  }

  removeItem(key) {
    delete this._storage[key];
  }

  setItem(key, value) {
    this._storage[key] = String(value);
  }
}

// Polyfill localStorage (required by MSW's CookieStore)
if (typeof globalThis.localStorage === 'undefined') {
  globalThis.localStorage = new MemoryStorage();
}

// Polyfill sessionStorage
if (typeof globalThis.sessionStorage === 'undefined') {
  globalThis.sessionStorage = new MemoryStorage();
}

// Polyfill window if needed (some libraries check for window.localStorage)
if (typeof globalThis.window === 'undefined') {
  globalThis.window = {
    localStorage: globalThis.localStorage,
    sessionStorage: globalThis.sessionStorage
  };
}

console.log('[Vitest Preload] Browser API polyfills installed');
