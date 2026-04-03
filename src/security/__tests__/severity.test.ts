import { describe, it, expect } from 'vitest';
import {
  type Severity,
  SEVERITY_LEVELS,
  SEVERITY_PRIORITY,
  compareSeverity,
  isHighSeverity,
  normalizeSeverity
} from '../severity.js';

describe('Severity Utilities', () => {
  describe('SEVERITY_LEVELS constant', () => {
    it('should contain all severity levels in priority order', () => {
      expect(SEVERITY_LEVELS).toEqual(['critical', 'high', 'medium', 'low']);
    });

    it('should be readonly', () => {
      // TypeScript enforces this at compile time
      // At runtime, we can verify it's an array
      expect(Array.isArray(SEVERITY_LEVELS)).toBe(true);
    });
  });

  describe('SEVERITY_PRIORITY constant', () => {
    it('should map severity levels to priority numbers', () => {
      expect(SEVERITY_PRIORITY.critical).toBe(0);
      expect(SEVERITY_PRIORITY.high).toBe(1);
      expect(SEVERITY_PRIORITY.medium).toBe(2);
      expect(SEVERITY_PRIORITY.low).toBe(3);
    });

    it('should have critical as highest priority (lowest number)', () => {
      const priorities = Object.values(SEVERITY_PRIORITY);
      expect(Math.min(...priorities)).toBe(SEVERITY_PRIORITY.critical);
    });

    it('should have low as lowest priority (highest number)', () => {
      const priorities = Object.values(SEVERITY_PRIORITY);
      expect(Math.max(...priorities)).toBe(SEVERITY_PRIORITY.low);
    });
  });

  describe('compareSeverity', () => {
    it('should return negative when first severity is higher priority', () => {
      expect(compareSeverity('critical', 'high')).toBeLessThan(0);
      expect(compareSeverity('high', 'medium')).toBeLessThan(0);
      expect(compareSeverity('medium', 'low')).toBeLessThan(0);
    });

    it('should return positive when second severity is higher priority', () => {
      expect(compareSeverity('high', 'critical')).toBeGreaterThan(0);
      expect(compareSeverity('medium', 'high')).toBeGreaterThan(0);
      expect(compareSeverity('low', 'medium')).toBeGreaterThan(0);
    });

    it('should return zero for equal severities', () => {
      expect(compareSeverity('critical', 'critical')).toBe(0);
      expect(compareSeverity('high', 'high')).toBe(0);
      expect(compareSeverity('medium', 'medium')).toBe(0);
      expect(compareSeverity('low', 'low')).toBe(0);
    });

    it('should work correctly in array sort', () => {
      const severities: Severity[] = ['low', 'critical', 'medium', 'high'];
      const sorted = severities.sort(compareSeverity);
      expect(sorted).toEqual(['critical', 'high', 'medium', 'low']);
    });
  });

  describe('isHighSeverity', () => {
    it('should return true for critical severity', () => {
      expect(isHighSeverity('critical')).toBe(true);
    });

    it('should return true for high severity', () => {
      expect(isHighSeverity('high')).toBe(true);
    });

    it('should return false for medium severity', () => {
      expect(isHighSeverity('medium')).toBe(false);
    });

    it('should return false for low severity', () => {
      expect(isHighSeverity('low')).toBe(false);
    });
  });

  describe('normalizeSeverity', () => {
    it('should convert uppercase to lowercase', () => {
      expect(normalizeSeverity('CRITICAL')).toBe('critical');
      expect(normalizeSeverity('HIGH')).toBe('high');
      expect(normalizeSeverity('MEDIUM')).toBe('medium');
      expect(normalizeSeverity('LOW')).toBe('low');
    });

    it('should handle mixed case', () => {
      expect(normalizeSeverity('CriTiCaL')).toBe('critical');
      expect(normalizeSeverity('HiGh')).toBe('high');
    });

    it('should pass through already lowercase values', () => {
      expect(normalizeSeverity('critical')).toBe('critical');
      expect(normalizeSeverity('high')).toBe('high');
      expect(normalizeSeverity('medium')).toBe('medium');
      expect(normalizeSeverity('low')).toBe('low');
    });

    it('should throw error for invalid severity values', () => {
      expect(() => normalizeSeverity('unknown')).toThrow('Invalid severity level: unknown');
      expect(() => normalizeSeverity('severe')).toThrow('Invalid severity level: severe');
      expect(() => normalizeSeverity('')).toThrow('Invalid severity level: ');
    });
  });

  describe('Type safety', () => {
    it('should enforce Severity type for SEVERITY_PRIORITY keys', () => {
      // This is enforced at compile time by TypeScript
      // At runtime, we can verify the keys match SEVERITY_LEVELS
      const priorityKeys = Object.keys(SEVERITY_PRIORITY) as Severity[];
      expect(priorityKeys.sort()).toEqual([...SEVERITY_LEVELS].sort());
    });
  });

  describe('Sorting use case', () => {
    it('should correctly sort vulnerability groups by severity', () => {
      interface VulnGroup {
        severity: Severity;
        count: number;
      }

      const groups: VulnGroup[] = [
        { severity: 'low', count: 5 },
        { severity: 'critical', count: 1 },
        { severity: 'medium', count: 3 },
        { severity: 'high', count: 2 }
      ];

      const sorted = groups.sort((a, b) => {
        const severityDiff = SEVERITY_PRIORITY[a.severity] - SEVERITY_PRIORITY[b.severity];
        return severityDiff !== 0 ? severityDiff : b.count - a.count;
      });

      expect(sorted[0].severity).toBe('critical');
      expect(sorted[1].severity).toBe('high');
      expect(sorted[2].severity).toBe('medium');
      expect(sorted[3].severity).toBe('low');
    });

    it('should sort by count when severity is equal', () => {
      interface VulnGroup {
        severity: Severity;
        count: number;
      }

      const groups: VulnGroup[] = [
        { severity: 'high', count: 1 },
        { severity: 'high', count: 5 },
        { severity: 'high', count: 3 }
      ];

      const sorted = groups.sort((a, b) => {
        const severityDiff = SEVERITY_PRIORITY[a.severity] - SEVERITY_PRIORITY[b.severity];
        return severityDiff !== 0 ? severityDiff : b.count - a.count;
      });

      expect(sorted[0].count).toBe(5);
      expect(sorted[1].count).toBe(3);
      expect(sorted[2].count).toBe(1);
    });
  });
});
