import { SecurityPattern, VulnerabilityType } from './types.js';
import { PatternAPIClient } from './pattern-api-client.js';
import { getMinimalPatterns, getMinimalPatternsByLanguage } from './minimal-patterns.js';
import { logger } from '../utils/logger.js';

/**
 * Interface for pattern sources
 * Implements RFC-008 Pattern Source abstraction
 */
export interface PatternSource {
  getPatternsByLanguage(language: string): Promise<SecurityPattern[]>;
  getPatternsByType(type: VulnerabilityType): Promise<SecurityPattern[]>;
  getAllPatterns(): Promise<SecurityPattern[]>;
}

/**
 * Local pattern source using minimal fallback patterns
 * Used as fallback when API is unavailable
 * Intentionally limited to protect proprietary patterns
 */
export class LocalPatternSource implements PatternSource {
  private patterns: SecurityPattern[] = [];

  constructor() {
    this.initializePatterns();
  }

  private initializePatterns(): void {
    // Use factory function to get fresh patterns with working RegExp objects
    this.patterns = getMinimalPatterns();
    logger.warn('Using minimal fallback patterns - API connection recommended for full pattern coverage');
  }

  async getPatternsByLanguage(language: string): Promise<SecurityPattern[]> {
    const patterns = getMinimalPatternsByLanguage(language);
    logger.info(`LocalPatternSource: Returning ${patterns.length} minimal ${language} patterns`);
    return patterns;
  }

  async getPatternsByType(type: VulnerabilityType): Promise<SecurityPattern[]> {
    const patterns = this.patterns.filter(p => p.type === type);
    logger.info(`LocalPatternSource: Returning ${patterns.length} minimal patterns of type ${type}`);
    return patterns;
  }

  async getAllPatterns(): Promise<SecurityPattern[]> {
    logger.info(`LocalPatternSource: Returning ${this.patterns.length} minimal patterns total`);
    return this.patterns;
  }
}

/**
 * API-based pattern source
 * Fetches patterns from RSOLV-api with caching
 */
export class ApiPatternSource implements PatternSource {
  private client: PatternAPIClient;
  private supportedLanguages = [
    'javascript', 'typescript', 'python', 'ruby', 'java', 'php', 'elixir'
  ];

  constructor(apiKey?: string, apiUrl?: string) {
    this.client = new PatternAPIClient({
      apiKey,
      apiUrl,
      cacheEnabled: true,
      cacheTTL: 3600, // 1 hour cache
      fallbackToLocal: false // We'll handle fallback at a higher level
    });
  }

  async getPatternsByLanguage(language: string): Promise<SecurityPattern[]> {
    try {
      const patterns = await this.client.fetchPatterns(language.toLowerCase());
      logger.info(`ApiPatternSource: Fetched ${patterns.length} ${language} patterns from API`);
      return patterns;
    } catch (error) {
      logger.error(`ApiPatternSource: Failed to fetch ${language} patterns`, error);
      throw error;
    }
  }

  async getPatternsByType(type: VulnerabilityType): Promise<SecurityPattern[]> {
    // Fetch all patterns and filter by type
    // In a future optimization, we could add a type-specific endpoint
    const allPatterns = await this.getAllPatterns();
    const filtered = allPatterns.filter(p => p.type === type);
    logger.info(`ApiPatternSource: Returning ${filtered.length} patterns of type ${type}`);
    return filtered;
  }

  async getAllPatterns(): Promise<SecurityPattern[]> {
    const allPatterns: SecurityPattern[] = [];
    
    // Fetch patterns for all supported languages
    for (const language of this.supportedLanguages) {
      try {
        const patterns = await this.client.fetchPatterns(language);
        allPatterns.push(...patterns);
      } catch (error) {
        logger.warn(`Failed to fetch ${language} patterns, continuing...`, error);
      }
    }
    
    logger.info(`ApiPatternSource: Fetched ${allPatterns.length} total patterns from API`);
    return allPatterns;
  }
}

/**
 * Hybrid pattern source with API primary and local fallback
 * Implements RFC-008 graceful degradation strategy
 */
export class HybridPatternSource implements PatternSource {
  private apiSource: ApiPatternSource;
  private localSource: LocalPatternSource;

  constructor(apiKey?: string, apiUrl?: string) {
    this.apiSource = new ApiPatternSource(apiKey, apiUrl);
    this.localSource = new LocalPatternSource();
  }

  async getPatternsByLanguage(language: string): Promise<SecurityPattern[]> {
    try {
      // Try API first
      return await this.apiSource.getPatternsByLanguage(language);
    } catch (error) {
      // Fall back to local patterns
      logger.warn(`Falling back to local patterns for ${language} due to API error`, error);
      return await this.localSource.getPatternsByLanguage(language);
    }
  }

  async getPatternsByType(type: VulnerabilityType): Promise<SecurityPattern[]> {
    try {
      // Try API first
      return await this.apiSource.getPatternsByType(type);
    } catch (error) {
      // Fall back to local patterns
      logger.warn(`Falling back to local patterns for type ${type} due to API error`, error);
      return await this.localSource.getPatternsByType(type);
    }
  }

  async getAllPatterns(): Promise<SecurityPattern[]> {
    try {
      // Try API first
      return await this.apiSource.getAllPatterns();
    } catch (error) {
      // Fall back to local patterns
      logger.warn('Falling back to local patterns due to API error', error);
      return await this.localSource.getAllPatterns();
    }
  }
}

/**
 * Factory function to create the appropriate pattern source
 * based on configuration and environment
 */
export function createPatternSource(): PatternSource {
  const apiKey = process.env.RSOLV_API_KEY;
  const apiUrl = process.env.RSOLV_API_URL;
  const useLocalPatterns = process.env.USE_LOCAL_PATTERNS === 'true';

  if (useLocalPatterns) {
    logger.info('Using local pattern source (USE_LOCAL_PATTERNS=true)');
    return new LocalPatternSource();
  }

  if (apiKey) {
    logger.info('Using hybrid pattern source with API key');
    return new HybridPatternSource(apiKey, apiUrl);
  }

  logger.warn('No API key provided, using local pattern source only');
  return new LocalPatternSource();
}