/**
 * JSON repair utilities for handling malformed LLM responses
 * Extracted from AITestGenerator for better testability and reusability
 */

import { logger } from '../utils/logger.js';

export interface ProgressiveCompletionStrategy {
  suffix: string;
  description: string;
}

/**
 * Progressive completion strategies for recovering incomplete JSON.
 * Ordered from most to least common truncation patterns (based on Aider's approach).
 */
export const PROGRESSIVE_COMPLETION_STRATEGIES: ProgressiveCompletionStrategy[] = [
  { suffix: '', description: 'no modifications needed' },
  { suffix: ']}', description: 'array + object closure' },
  { suffix: '}]', description: 'object + array closure' },
  { suffix: '}]}', description: 'object + array + object closure' },
  { suffix: '"}]', description: 'string + array + object closure' },
  { suffix: '"}]}', description: 'string + nested array + object closure' },
  { suffix: '}', description: 'single object closure' },
  { suffix: ']', description: 'single array closure' },
  { suffix: '"}', description: 'string + object closure' },
] as const;

export interface ParseResult<T> {
  success: boolean;
  data?: T;
  error?: string;
  strategy?: string;
}

/**
 * Try parsing JSON with progressive completion strategies.
 * Attempts multiple completion suffixes to recover incomplete JSON from streaming truncation.
 *
 * @param jsonString - The potentially incomplete JSON string
 * @returns ParseResult with parsed data or error information
 */
export function tryParseWithProgressiveCompletion<T = any>(jsonString: string): ParseResult<T> {
  for (const strategy of PROGRESSIVE_COMPLETION_STRATEGIES) {
    try {
      const completedJson = jsonString + strategy.suffix;
      const result = JSON.parse(completedJson) as T;

      if (strategy.suffix === '') {
        logger.debug('JSON parsed successfully without modifications');
      } else {
        logger.info(`JSON recovered using "${strategy.suffix}" suffix (${strategy.description})`);
      }

      return {
        success: true,
        data: result,
        strategy: strategy.description,
      };
    } catch (error) {
      // Continue to next strategy
      continue;
    }
  }

  // All strategies failed
  const errorMessage = 'Failed to parse JSON after all progressive completion attempts';
  logger.error(errorMessage);

  // Log the malformed JSON for debugging (with smart truncation)
  const jsonPreview = jsonString.length > 1000
    ? `${jsonString.substring(0, 500)}...[${jsonString.length - 1000} chars omitted]...${jsonString.substring(jsonString.length - 500)}`
    : jsonString;
  logger.error('Malformed JSON that failed to parse:', jsonPreview);

  return {
    success: false,
    error: errorMessage,
  };
}

/**
 * Detects if a JSON string is truncated mid-string vs just containing escaped quotes.
 * Uses a state machine to track string boundaries correctly.
 *
 * @param jsonString - The JSON string to analyze
 * @returns true if the string appears to be truncated inside a string value
 */
export function isActuallyTruncatedString(jsonString: string): boolean {
  let inString = false;
  let escape = false;

  for (let i = 0; i < jsonString.length; i++) {
    const char = jsonString[i];

    if (escape) {
      escape = false;
      continue;
    }

    if (char === '\\' && inString) {
      escape = true;
      continue;
    }

    if (char === '"') {
      inString = !inString;
    }
  }

  // If we end while in a string state, and the string doesn't end with "},
  // then it's likely actually truncated
  return inString && !jsonString.trim().endsWith('"}');
}

/**
 * Count occurrences of a character in a string, respecting string boundaries and escape sequences.
 * More accurate than simple regex counting for JSON structures.
 *
 * @param text - The text to analyze
 * @param char - The character to count
 * @returns Object with counts inside and outside of strings
 */
export function countCharactersRespectingStrings(text: string, char: string): {
  total: number;
  outsideStrings: number;
} {
  let total = 0;
  let outsideStrings = 0;
  let inString = false;
  let escape = false;

  for (let i = 0; i < text.length; i++) {
    const currentChar = text[i];

    if (escape) {
      escape = false;
      continue;
    }

    if (currentChar === '\\' && inString) {
      escape = true;
      continue;
    }

    if (currentChar === '"') {
      inString = !inString;
      continue;
    }

    if (currentChar === char) {
      total++;
      if (!inString) {
        outsideStrings++;
      }
    }
  }

  return { total, outsideStrings };
}

/**
 * Properly extracts JSON from text, handling nested objects correctly.
 * This replaces buggy regex patterns that truncate at the first closing brace.
 *
 * @param text - Text potentially containing JSON
 * @returns The largest valid JSON object found, or null if none exists
 */
export function extractJsonFromText(text: string): string | null {
  const positions: Array<{ start: number; end: number }> = [];
  let depth = 0;
  let inString = false;
  let escape = false;
  let jsonStart = -1;

  for (let i = 0; i < text.length; i++) {
    const char = text[i];

    // Handle escape sequences
    if (escape) {
      escape = false;
      continue;
    }

    if (char === '\\' && inString) {
      escape = true;
      continue;
    }

    // Handle strings (quotes not escaped)
    if (char === '"' && !escape) {
      inString = !inString;
      continue;
    }

    // Only count braces outside of strings
    if (!inString) {
      if (char === '{') {
        if (depth === 0) {
          jsonStart = i;
        }
        depth++;
      } else if (char === '}') {
        depth--;
        if (depth === 0 && jsonStart !== -1) {
          positions.push({
            start: jsonStart,
            end: i + 1,
          });
          jsonStart = -1;
        }
      }
    }
  }

  // Try to parse each potential JSON object, return the largest valid one
  let largestValid: string | null = null;
  let largestSize = 0;

  for (const pos of positions) {
    const candidate = text.substring(pos.start, pos.end);
    try {
      // Validate it's actual JSON
      JSON.parse(candidate);
      if (candidate.length > largestSize) {
        largestValid = candidate;
        largestSize = candidate.length;
      }
    } catch {
      // Invalid JSON, skip
    }
  }

  return largestValid;
}

/**
 * Clean up common JSON formatting issues that can cause parse errors.
 *
 * @param jsonString - The JSON string to clean
 * @returns Cleaned JSON string
 */
export function cleanJsonString(jsonString: string): string {
  return jsonString
    .replace(/^\s*```\s*json?\s*/gm, '') // Remove stray markdown markers
    .replace(/\s*```\s*$/gm, '')
    .replace(/,(\s*[}\]])/g, '$1') // Remove trailing commas before closing brackets/braces
    .trim();
}
