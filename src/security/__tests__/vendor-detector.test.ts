/**
 * VendorDetector Tests - Iteration 9
 *
 * Tests for the isVendorFile() fix that wires containsVendorIndicators()
 * as a fallback, and the new framework-specific asset path patterns.
 */

import { describe, test, expect, beforeEach, vi } from 'vitest';
import { VendorDetector } from '../vendor-detector.js';

// Mock fs.readFile so we don't hit the filesystem
vi.mock('fs/promises', () => ({
  readFile: vi.fn().mockRejectedValue(new Error('ENOENT'))
}));

describe('VendorDetector', () => {
  let detector: VendorDetector;

  beforeEach(() => {
    detector = new VendorDetector();
  });

  describe('isVendorFile with content fallback', () => {
    test('catches files with vendor license headers even when path does not match vendor patterns', async () => {
      const content = '/*! jQuery v3.6.0 | (c) OpenJS Foundation | jquery.org/license */\n(function(){})();';
      const result = await detector.isVendorFile('src/custom-libs/utils.js', content);
      expect(result).toBe(true);
    });

    test('catches files with MIT license header via content', async () => {
      const content = '// Licensed under MIT\nmodule.exports = function() {};';
      const result = await detector.isVendorFile('random-path/helper.js', content);
      expect(result).toBe(true);
    });

    test('does not flag application code without vendor indicators', async () => {
      const content = 'const express = require("express");\napp.get("/", (req, res) => res.send("ok"));';
      const result = await detector.isVendorFile('app/controllers/main.js', content);
      expect(result).toBe(false);
    });

    test('path-based detection still works without content', async () => {
      const result = await detector.isVendorFile('node_modules/lodash/lodash.js');
      expect(result).toBe(true);
    });

    test('minified file detection still works', async () => {
      const result = await detector.isVendorFile('assets/app.min.js');
      expect(result).toBe(true);
    });
  });

  describe('Rails asset pipeline paths', () => {
    test('detects app/assets/javascripts/ as vendor', async () => {
      const result = await detector.isVendorFile('app/assets/javascripts/jquery.js');
      expect(result).toBe(true);
    });

    test('detects public/assets/ as vendor', async () => {
      const result = await detector.isVendorFile('public/assets/application-abc123.js');
      expect(result).toBe(true);
    });

    test('detects public/packs/ as vendor', async () => {
      const result = await detector.isVendorFile('public/packs/bundle.js');
      expect(result).toBe(true);
    });
  });

  describe('Django/Laravel asset paths', () => {
    test('detects static/vendor/ as vendor', async () => {
      const result = await detector.isVendorFile('static/vendor/bootstrap.js');
      expect(result).toBe(true);
    });

    test('detects public/vendor/ as vendor', async () => {
      const result = await detector.isVendorFile('public/vendor/chart.js');
      expect(result).toBe(true);
    });
  });

  describe('Build output paths', () => {
    test('detects build/ as vendor', async () => {
      const result = await detector.isVendorFile('build/static/js/main.chunk.js');
      expect(result).toBe(true);
    });

    test('detects _build/ as vendor', async () => {
      const result = await detector.isVendorFile('_build/prod/lib/app/ebin/app.beam');
      expect(result).toBe(true);
    });

    test('detects out/ as vendor', async () => {
      const result = await detector.isVendorFile('out/compiled/index.js');
      expect(result).toBe(true);
    });
  });

  describe('containsVendorIndicators', () => {
    test('detects jQuery header in content', async () => {
      const content = '/*! jQuery v3.6.0 | (c) OpenJS Foundation */';
      const result = await detector.containsVendorIndicators('any/path.js', content);
      expect(result).toBe(true);
    });

    test('detects Bootstrap header in content', async () => {
      const content = '/*! Bootstrap v5.1.3 (https://getbootstrap.com/) */';
      const result = await detector.containsVendorIndicators('any/path.css', content);
      expect(result).toBe(true);
    });

    test('detects generic library version header', async () => {
      const content = '/*! somelib.js v2.4.1 - MIT License */';
      const result = await detector.containsVendorIndicators('any/path.js', content);
      expect(result).toBe(true);
    });

    test('returns false for application code', async () => {
      const content = 'function add(a, b) { return a + b; }';
      const result = await detector.containsVendorIndicators('any/path.js', content);
      expect(result).toBe(false);
    });
  });
});
