import { logger } from '../utils/logger.js';
import { SecurityPattern, VulnerabilityType } from './types.js';

export interface PatternResponse {
  count: number;
  language: string;
  patterns: PatternData[];
  accessible_tiers?: string[];
  tier?: string;
}

export interface PatternData {
  id: string;
  name: string;
  type: string;
  description: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  patterns: string[];  // Array of regex patterns
  languages: string[];
  frameworks?: string[];
  recommendation: string;
  cwe_id: string;      // API returns snake_case
  owasp_category: string;  // API returns snake_case
  test_cases: {        // API returns snake_case
    vulnerable: string[];
    safe: string[];
  };
  // AST Enhancement fields
  ast_rules?: {
    node_type?: string;
    [key: string]: any;
  };
  context_rules?: {
    exclude_paths?: string[];
    safe_if_wrapped?: string[];
    [key: string]: any;
  };
  confidence_rules?: {
    base?: number;
    adjustments?: Record<string, number>;
    [key: string]: any;
  };
  min_confidence?: number;
}

export interface PatternAPIConfig {
  apiUrl?: string;
  apiKey?: string;
  cacheEnabled?: boolean;
  cacheTTL?: number; // in seconds
  fallbackToLocal?: boolean;
}

/**
 * Client for fetching security patterns from RSOLV-api
 * Implements RFC-008 Pattern Serving API
 */
export class PatternAPIClient {
  private apiUrl: string;
  private apiKey?: string;
  private cache: Map<string, { patterns: SecurityPattern[]; timestamp: number }> = new Map();
  private cacheTTL: number;
  private fallbackToLocal: boolean;

  constructor(config: PatternAPIConfig = {}) {
    const baseUrl = config.apiUrl || process.env.RSOLV_API_URL || 'https://api.rsolv.dev';
    // Ensure the base URL doesn't end with a slash
    const cleanBaseUrl = baseUrl.replace(/\/$/, '');
    // Append the patterns API path if not already included
    this.apiUrl = cleanBaseUrl.includes('/api/v1/patterns') ? cleanBaseUrl : `${cleanBaseUrl}/api/v1/patterns`;
    
    this.apiKey = config.apiKey || process.env.RSOLV_API_KEY;
    this.cacheTTL = (config.cacheTTL || 3600) * 1000; // Convert to milliseconds
    this.fallbackToLocal = config.fallbackToLocal ?? true;
    
    if (!this.apiKey) {
      logger.warn('No RSOLV API key provided - will only have access to public patterns');
    }
  }

  /**
   * Fetch patterns for a specific language
   * Uses tiered access based on API key permissions
   */
  async fetchPatterns(language: string): Promise<SecurityPattern[]> {
    const cacheKey = `${language}-${this.apiKey || 'public'}`;
    
    // Check cache first
    const cached = this.cache.get(cacheKey);
    if (cached && Date.now() - cached.timestamp < this.cacheTTL) {
      logger.info(`Using cached patterns for ${language} (${cached.patterns.length} patterns)`);
      return cached.patterns;
    }

    try {
      const headers: HeadersInit = {
        'Content-Type': 'application/json',
      };
      
      if (this.apiKey) {
        headers['Authorization'] = `Bearer ${this.apiKey}`;
      }

      // Request enhanced patterns with AST rules
      const response = await fetch(`${this.apiUrl}/${language}?format=enhanced`, { headers });
      
      if (!response.ok) {
        throw new Error(`Failed to fetch patterns: ${response.status} ${response.statusText}`);
      }

      const data: PatternResponse = await response.json();
      logger.info(`Fetched ${data.count} ${language} patterns from API (tiers: ${data.accessible_tiers?.join(', ') || 'public'})`);
      
      // Convert API patterns to SecurityPattern format
      const patterns = data.patterns.map(p => this.convertToSecurityPattern(p));
      
      // Cache the results
      this.cache.set(cacheKey, { patterns, timestamp: Date.now() });
      
      return patterns;
    } catch (error) {
      logger.error(`Failed to fetch ${language} patterns from API:`, error);
      
      if (this.fallbackToLocal) {
        logger.warn(`Falling back to local patterns for ${language}`);
        // TODO: Return basic local patterns as fallback
        return [];
      }
      
      throw error;
    }
  }

  /**
   * Fetch patterns for a specific tier
   */
  async fetchPatternsByTier(tier: 'public' | 'protected' | 'ai' | 'enterprise', language?: string): Promise<SecurityPattern[]> {
    const endpoint = language ? `${tier}/${language}` : tier;
    const cacheKey = `tier-${endpoint}-${this.apiKey || 'public'}`;
    
    // Check cache first
    const cached = this.cache.get(cacheKey);
    if (cached && Date.now() - cached.timestamp < this.cacheTTL) {
      logger.info(`Using cached ${tier} patterns (${cached.patterns.length} patterns)`);
      return cached.patterns;
    }

    try {
      const headers: HeadersInit = {
        'Content-Type': 'application/json',
      };
      
      // Protected, AI, and Enterprise tiers require authentication
      if (tier !== 'public' && !this.apiKey) {
        throw new Error(`API key required for ${tier} tier patterns`);
      }
      
      if (this.apiKey) {
        headers['Authorization'] = `Bearer ${this.apiKey}`;
      }

      const response = await fetch(`${this.apiUrl}/${endpoint}`, { headers });
      
      if (!response.ok) {
        if (response.status === 403) {
          throw new Error(`Access denied to ${tier} tier patterns - upgrade your plan`);
        }
        throw new Error(`Failed to fetch patterns: ${response.status} ${response.statusText}`);
      }

      const data: PatternResponse = await response.json();
      logger.info(`Fetched ${data.count} ${tier} patterns from API`);
      
      // Convert API patterns to SecurityPattern format
      const patterns = data.patterns.map(p => this.convertToSecurityPattern(p));
      
      // Cache the results
      this.cache.set(cacheKey, { patterns, timestamp: Date.now() });
      
      return patterns;
    } catch (error) {
      logger.error(`Failed to fetch ${tier} patterns from API:`, error);
      throw error;
    }
  }

  /**
   * Clear pattern cache
   */
  clearCache(): void {
    this.cache.clear();
    logger.info('Pattern cache cleared');
  }

  /**
   * Convert API pattern format to RSOLV-action SecurityPattern format
   */
  private convertToSecurityPattern(apiPattern: PatternData): SecurityPattern {
    // Compile regex patterns from strings
    const regexPatterns = apiPattern.patterns.map(r => {
      try {
        // Handle both simple patterns and patterns with flags
        const match = r.match(/^\/(.*)\/([gimsuvy]*)$/);
        if (match) {
          return new RegExp(match[1], match[2]);
        }
        return new RegExp(r);
      } catch (error) {
        logger.warn(`Failed to compile regex for pattern ${apiPattern.id}: ${r}`, error);
        return null;
      }
    }).filter(Boolean) as RegExp[];

    // Convert context rules exclude_paths to RegExp objects
    const contextRules = apiPattern.context_rules ? {
      ...apiPattern.context_rules,
      excludePaths: apiPattern.context_rules.exclude_paths?.map(path => 
        typeof path === 'string' ? new RegExp(path) : path
      ) || []
    } : undefined;

    return {
      id: apiPattern.id,
      name: apiPattern.name,
      type: this.mapVulnerabilityType(apiPattern.type),
      severity: apiPattern.severity,
      description: apiPattern.description,
      patterns: {
        regex: regexPatterns
      },
      languages: apiPattern.languages,
      frameworks: apiPattern.frameworks || [],
      cweId: apiPattern.cwe_id,
      owaspCategory: apiPattern.owasp_category,
      remediation: apiPattern.recommendation,
      testCases: apiPattern.test_cases,
      // AST Enhancement fields
      astRules: apiPattern.ast_rules,
      contextRules,
      confidenceRules: apiPattern.confidence_rules,
      minConfidence: apiPattern.min_confidence
    };
  }

  /**
   * Map API vulnerability types to RSOLV-action VulnerabilityType enum
   */
  private mapVulnerabilityType(type: string): VulnerabilityType {
    const typeMap: Record<string, VulnerabilityType> = {
      'sql_injection': VulnerabilityType.SQL_INJECTION,
      'xss': VulnerabilityType.XSS,
      'command_injection': VulnerabilityType.COMMAND_INJECTION,
      'path_traversal': VulnerabilityType.PATH_TRAVERSAL,
      'xxe': VulnerabilityType.XXE,
      'ssrf': VulnerabilityType.SSRF,
      'insecure_deserialization': VulnerabilityType.INSECURE_DESERIALIZATION,
      'deserialization': VulnerabilityType.INSECURE_DESERIALIZATION,
      'weak_crypto': VulnerabilityType.WEAK_CRYPTO,
      'hardcoded_secret': VulnerabilityType.HARDCODED_SECRET,
      'insecure_random': VulnerabilityType.INSECURE_RANDOM,
      'open_redirect': VulnerabilityType.OPEN_REDIRECT,
      'ldap_injection': VulnerabilityType.LDAP_INJECTION,
      'xpath_injection': VulnerabilityType.XPATH_INJECTION,
      'nosql_injection': VulnerabilityType.NOSQL_INJECTION,
      'rce': VulnerabilityType.RCE,
      'dos': VulnerabilityType.DOS,
      'denial_of_service': VulnerabilityType.DOS,
      'timing_attack': VulnerabilityType.TIMING_ATTACK,
      'csrf': VulnerabilityType.CSRF,
      'jwt': VulnerabilityType.JWT,
      'authentication': VulnerabilityType.JWT,
      'debug': VulnerabilityType.INFORMATION_DISCLOSURE,
      'information_disclosure': VulnerabilityType.INFORMATION_DISCLOSURE,
      'cve': VulnerabilityType.CVE,
      'file_upload': VulnerabilityType.PATH_TRAVERSAL,
      'input_validation': VulnerabilityType.XSS,
      'session_management': VulnerabilityType.CSRF,
      'resource_exhaustion': VulnerabilityType.DOS,
    };
    
    return typeMap[type] || VulnerabilityType.UNKNOWN;
  }
}