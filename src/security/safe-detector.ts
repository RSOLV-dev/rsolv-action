import { Worker } from 'worker_threads';
import * as path from 'path';
import { fileURLToPath } from 'url';
import safeRegex from 'safe-regex2';
import { logger } from '../utils/logger.js';
import { createPatternSource } from './pattern-source.js';
import type { PatternSource } from './pattern-source.js';
import type { Vulnerability } from './types.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

interface WorkerMessage {
  type: 'result' | 'error';
  data?: Vulnerability[];
  error?: string;
}

interface WorkerTask {
  code: string;
  language: string;
  patterns?: any[];
  filePath?: string;
}

/**
 * SafeDetector - A security detector that uses worker threads to prevent hangs
 * from catastrophic regex backtracking. Pre-filters patterns with safe-regex2.
 */
export class SafeDetector {
  private patternSource: PatternSource;
  private skippedPatterns: Set<string> = new Set();
  private lastError: Error | null = null;
  private activeWorkers: Set<Worker> = new Set();
  private terminatedWorkers: Set<Worker> = new Set();
  private defaultTimeout: number = 30000; // 30 seconds default

  constructor(patternSource?: PatternSource) {
    this.patternSource = patternSource || createPatternSource();
  }

  /**
   * Main detection method - maintains compatibility with SecurityDetectorV2
   */
  async detect(code: string, language: string, filePath?: string): Promise<Vulnerability[]> {
    if (!code || typeof code !== 'string') {
      this.lastError = new Error('Invalid code input');
      logger.error('SafeDetector: Invalid code input');
      return [];
    }

    try {
      // Get patterns from source
      const patterns = await this.patternSource.getPatternsByLanguage(language);
      logger.info(`SafeDetector: Analyzing ${language} code with ${patterns.length} patterns`);

      // IMPORTANT: Run ALL patterns in worker threads for safety
      // safe-regex2 doesn't catch all problematic patterns, and the cumulative
      // effect of multiple patterns can still cause hangs (as seen with user.rb)
      logger.info(`SafeDetector: Running all ${patterns.length} patterns in worker thread for safety`);

      // Run all patterns in worker thread with timeout protection
      const results = await this.runPatternsInWorker(code, language, patterns, filePath, this.defaultTimeout);

      return results;
    } catch (error: any) {
      this.lastError = error;
      logger.error('SafeDetector error:', error);
      return [];
    }
  }

  /**
   * Detect with a specific pattern (for testing)
   */
  async detectWithPattern(
    code: string,
    language: string,
    pattern: any,
    timeout?: number
  ): Promise<Vulnerability[]> {
    const patterns = [pattern];
    const { safe, unsafe } = this.filterPatterns(patterns);

    if (unsafe.length > 0) {
      // Run in worker with timeout
      return this.runPatternsInWorker(code, language, unsafe, 'test.file', timeout || this.defaultTimeout);
    } else if (safe.length > 0) {
      // Run in main thread
      return this.runPatternsInMainThread(code, language, safe, 'test.file');
    }

    return [];
  }

  /**
   * Filter patterns into safe and potentially unsafe categories
   */
  private filterPatterns(patterns: any[]): { safe: any[], unsafe: any[] } {
    const safe: any[] = [];
    const unsafe: any[] = [];

    for (const pattern of patterns) {
      let isSafe = true;

      if (pattern.patterns?.regex) {
        for (const regex of pattern.patterns.regex) {
          // Check if regex is safe (limit of 25 repetitions)
          if (!safeRegex(regex, { limit: 25 })) {
            isSafe = false;
            this.skippedPatterns.add(pattern.id);
            logger.warn(`SafeDetector: Pattern ${pattern.id} marked as potentially unsafe`);
            break;
          }
        }
      }

      if (isSafe) {
        safe.push(pattern);
      } else {
        unsafe.push(pattern);
      }
    }

    return { safe, unsafe };
  }

  /**
   * Run patterns in the main thread (for safe patterns)
   */
  private async runPatternsInMainThread(
    code: string,
    language: string,
    patterns: any[],
    filePath?: string
  ): Promise<Vulnerability[]> {
    // Import the original detector for safe patterns
    const { SecurityDetectorV2 } = await import('./detector-v2.js');
    const detector = new SecurityDetectorV2();

    // Temporarily replace the pattern source to use only safe patterns
    const mockSource = {
      getPatternsByLanguage: async () => patterns
    };

    (detector as any).patternSource = mockSource;

    return detector.detect(code, language, filePath || 'unknown');
  }

  /**
   * Run patterns in a worker thread with timeout protection
   */
  private async runPatternsInWorker(
    code: string,
    language: string,
    patterns: any[],
    filePath?: string,
    timeout: number = 30000
  ): Promise<Vulnerability[]> {
    if (patterns.length === 0) {
      return [];
    }

    return new Promise((resolve) => {
      const workerPath = path.join(__dirname, 'detector-worker.js');
      const worker = new Worker(workerPath, {
        workerData: {
          code,
          language,
          patterns,
          filePath: filePath || 'unknown'
        }
      });

      this.activeWorkers.add(worker);
      let resolved = false;

      // Helper to clean up worker resources and resolve once
      const cleanupAndResolve = (result: Vulnerability[]) => {
        if (resolved) return;
        resolved = true;

        clearTimeout(timeoutId);
        this.activeWorkers.delete(worker);
        this.terminatedWorkers.add(worker);
        worker.terminate();
        resolve(result);
      };

      const timeoutId = setTimeout(() => {
        logger.warn(`SafeDetector: Worker timeout after ${timeout}ms for ${filePath || 'unknown'}`);
        cleanupAndResolve([]);
      }, timeout);

      worker.on('message', (msg: WorkerMessage) => {
        if (msg.type === 'result') {
          cleanupAndResolve(msg.data || []);
        } else {
          logger.error(`SafeDetector: Worker error: ${msg.error}`);
          this.lastError = new Error(msg.error);
          cleanupAndResolve([]);
        }
      });

      worker.on('error', (error) => {
        logger.error('SafeDetector: Worker error:', error);
        this.lastError = error;
        cleanupAndResolve([]);
      });

      worker.on('exit', (code) => {
        // Only log error if worker was NOT intentionally terminated
        if (code !== 0 && !this.terminatedWorkers.has(worker)) {
          logger.error(`SafeDetector: Worker exited with code ${code}`);
        }

        // Clean up tracking after worker exits
        this.terminatedWorkers.delete(worker);
      });
    });
  }

  /**
   * Get the list of patterns that were skipped as unsafe
   */
  getSkippedPatterns(): string[] {
    return Array.from(this.skippedPatterns);
  }

  /**
   * Get the last error that occurred
   */
  getLastError(): Error | null {
    return this.lastError;
  }

  /**
   * Get the number of active workers
   */
  getWorkerCount(): number {
    return this.activeWorkers.size;
  }

  /**
   * Check if any workers are currently tracked as terminated
   */
  getTerminatedWorkerCount(): number {
    return this.terminatedWorkers.size;
  }

  /**
   * Clean up any remaining workers
   */
  cleanup(): void {
    for (const worker of this.activeWorkers) {
      worker.terminate();
    }
    this.activeWorkers.clear();
  }
}