import { describe, it, expect } from 'vitest';
import { parseScanOutput, type ScanOutputDestination } from '../scan-output.js';

describe('parseScanOutput', () => {
  describe('from action input (comma-separated string)', () => {
    it('parses single destination', () => {
      expect(parseScanOutput('issues')).toEqual(['issues']);
    });

    it('parses multiple destinations', () => {
      expect(parseScanOutput('report,dashboard')).toEqual(['report', 'dashboard']);
    });

    it('trims whitespace around destinations', () => {
      expect(parseScanOutput('report , dashboard')).toEqual(['report', 'dashboard']);
    });

    it('returns default [issues] for empty string', () => {
      expect(parseScanOutput('')).toEqual(['issues']);
    });

    it('returns default [issues] for undefined', () => {
      expect(parseScanOutput(undefined)).toEqual(['issues']);
    });

    it('filters invalid destinations', () => {
      expect(parseScanOutput('issues,bogus,report')).toEqual(['issues', 'report']);
    });

    it('deduplicates destinations', () => {
      expect(parseScanOutput('issues,issues,report')).toEqual(['issues', 'report']);
    });
  });

  describe('from YAML config (array)', () => {
    it('accepts valid array', () => {
      expect(parseScanOutput(['report', 'dashboard'])).toEqual(['report', 'dashboard']);
    });

    it('accepts empty array (dry run)', () => {
      expect(parseScanOutput([])).toEqual([]);
    });

    it('filters invalid destinations from array', () => {
      expect(parseScanOutput(['issues', 'bogus'])).toEqual(['issues']);
    });
  });

  describe('backward compatibility', () => {
    it('default is [issues] — same as pre-RFC-133 behavior', () => {
      expect(parseScanOutput(undefined)).toEqual(['issues']);
    });
  });
});
