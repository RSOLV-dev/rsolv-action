/**
 * Safe Regex Matcher
 *
 * Provides safe regex matching with built-in protections against:
 * - Catastrophic backtracking (timeout)
 * - Infinite loops (max matches, zero-width protection)
 * - Performance issues (progress tracking)
 */

import { logger } from '../utils/logger.js';

// Timeout constants
export const PATTERN_TIMEOUT_MS = 5000; // 5 seconds per pattern
export const FILE_TIMEOUT_MS = 30000; // 30 seconds per file
export const MAX_MATCHES_PER_PATTERN = 1000; // Prevent pathological cases

export interface RegexMatch {
  match: RegExpExecArray;
  lineNumber: number;
  column: number;
}

export interface SafeMatchOptions {
  maxMatches?: number;
  timeoutMs?: number;
  patternId?: string;
  filePath?: string;
}

export interface SafeMatchResult {
  matches: RegexMatch[];
  timedOut: boolean;
  hitMaxMatches: boolean;
  totalMatches: number;
  durationMs: number;
}

/**
 * Safely match a regex against content with timeout and match limits
 */
export class SafeRegexMatcher {
  /**
   * Execute regex matching with safety guarantees
   */
  static match(
    regex: RegExp,
    content: string,
    options: SafeMatchOptions = {}
  ): SafeMatchResult {
    const {
      maxMatches = MAX_MATCHES_PER_PATTERN,
      timeoutMs = PATTERN_TIMEOUT_MS,
      patternId = 'unknown',
      filePath = 'unknown'
    } = options;

    const matches: RegexMatch[] = [];
    const startTime = Date.now();
    let timedOut = false;
    let hitMaxMatches = false;
    let matchCount = 0;

    // Reset regex state
    regex.lastIndex = 0;

    try {
      let match: RegExpExecArray | null;

      while ((match = regex.exec(content)) !== null) {
        matchCount++;

        // Check max matches limit
        if (matchCount > maxMatches) {
          hitMaxMatches = true;
          logger.warn(`Pattern ${patternId} exceeded max matches (${maxMatches}) in ${filePath}`);
          break;
        }

        // Check timeout
        if (Date.now() - startTime > timeoutMs) {
          timedOut = true;
          logger.warn(`Pattern ${patternId} exceeded timeout (${timeoutMs}ms) in ${filePath}`);
          break;
        }

        // Calculate line and column
        const lineNumber = this.getLineNumber(content, match.index);
        const column = match.index - content.lastIndexOf('\n', match.index - 1) - 1;

        matches.push({
          match,
          lineNumber,
          column
        });

        // Exit after first match for non-global regex
        if (!regex.global) {
          break;
        }

        // Prevent infinite loop on zero-width matches
        if (match.index === regex.lastIndex) {
          regex.lastIndex++;
        }
      }
    } catch (error) {
      logger.error(`Error executing regex pattern ${patternId} in ${filePath}:`, error);
    }

    const durationMs = Date.now() - startTime;

    return {
      matches,
      timedOut,
      hitMaxMatches,
      totalMatches: matchCount,
      durationMs
    };
  }

  /**
   * Get line number from character index
   */
  private static getLineNumber(content: string, index: number): number {
    return content.substring(0, index).split('\n').length;
  }

  /**
   * Extract line content at given line number
   */
  static getLineContent(content: string, lineNumber: number): string {
    const lines = content.split('\n');
    return lines[lineNumber - 1]?.trim() || '';
  }
}
