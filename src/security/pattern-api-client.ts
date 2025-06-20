import { logger } from '../utils/logger.js';
import { SecurityPattern, VulnerabilityType } from './types.js';

export interface PatternResponse {
  patterns: PatternData[];
  metadata?: {
    count?: number;
    language?: string;
    format?: string;
    enhanced?: boolean;
    access_level?: 'demo' | 'full';
  };
  // Deprecated fields for backward compatibility
  count?: number;
  language?: string;
  accessible_tiers?: string[];
  tier?: string;
}

export interface PatternData {
  id: string;
  name: string;
  type: string;
  description: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  patterns: string[] | { regex: string[] };  // Can be array or object with regex array
  languages: string[];
  frameworks?: string[];
  recommendation: string;
  cwe_id?: string;      // API returns snake_case, optional for compatibility
  cweId?: string;       // Alternative camelCase format
  owasp_category?: string;  // API returns snake_case, optional
  owaspCategory?: string;   // Alternative camelCase format
  test_cases?: {        // API returns snake_case, optional
    vulnerable: string[];
    safe: string[];
  };
  testCases?: {         // Alternative camelCase format
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
      logger.warn('No RSOLV API key provided - only demo patterns available');
    }
  }

  /**
   * Fetch patterns for a specific language
   * Returns all patterns with API key, or demo patterns without
   */
  async fetchPatterns(language: string): Promise<SecurityPattern[]> {
    const cacheKey = `${language}-${this.apiKey || 'demo'}`;
    
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

      // Use the new tier-less endpoint with standard format 
      // (enhanced format temporarily disabled due to API issues)
      const response = await fetch(`${this.apiUrl}?language=${language}&format=standard`, { headers });
      
      if (!response.ok) {
        throw new Error(`Failed to fetch patterns: ${response.status} ${response.statusText}`);
      }

      const data: PatternResponse = await response.json();
      const count = data.metadata?.count || data.count || data.patterns.length;
      logger.info(`Fetched ${count} ${language} patterns from API`);
      
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
   * @deprecated Tier system has been removed. Use fetchPatterns() instead.
   * All patterns are now available with a valid API key.
   * This method is kept for backward compatibility only.
   */
  async fetchPatternsByTier(tier: 'public' | 'protected' | 'ai' | 'enterprise', language?: string): Promise<SecurityPattern[]> {
    logger.warn(`fetchPatternsByTier is deprecated. Tier '${tier}' is ignored. Use fetchPatterns() instead.`);
    
    // For backward compatibility, just call fetchPatterns
    if (language) {
      return this.fetchPatterns(language);
    }

    try {
      // Without language, we can't fetch patterns in the new API
      // Return empty array for backward compatibility
      logger.warn('fetchPatternsByTier called without language parameter. Returning empty array.');
      return [];
    } catch (error) {
      logger.error('Failed to fetch patterns from API:', error);
      throw error;
    }
  }


  /**
   * Convert API pattern format to RSOLV-action SecurityPattern format
   */
  private convertToSecurityPattern(apiPattern: PatternData): SecurityPattern {
    // Handle different API response formats
    let patternStrings: string[] = [];
    
    // Check if patterns is an array (language endpoint format)
    if (Array.isArray(apiPattern.patterns)) {
      patternStrings = apiPattern.patterns;
    } 
    // Check if patterns is an object with regex array (tier endpoint format)
    else if (apiPattern.patterns && typeof apiPattern.patterns === 'object' && 
             'regex' in apiPattern.patterns && Array.isArray((apiPattern.patterns as any).regex)) {
      patternStrings = (apiPattern.patterns as any).regex;
    }
    // Fallback for unexpected format
    else {
      logger.warn(`Unexpected patterns format for ${apiPattern.id}:`, apiPattern.patterns);
      patternStrings = [];
    }
    
    // Compile regex patterns from strings
    const regexPatterns = patternStrings.map(r => {
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

    // Convert context rules if present
    const contextRules = apiPattern.context_rules || undefined;

    return {
      id: apiPattern.id,
      name: apiPattern.name,
      type: this.mapVulnerabilityType(apiPattern.type),
      severity: apiPattern.severity,
      description: apiPattern.description,
      patterns: {
        regex: regexPatterns,
        // Add AST rules to patterns object if present
        ast: apiPattern.ast_rules ? [JSON.stringify(apiPattern.ast_rules)] : undefined
      },
      languages: apiPattern.languages,
      frameworks: apiPattern.frameworks || [],
      cweId: apiPattern.cwe_id || apiPattern.cweId || '',
      owaspCategory: apiPattern.owasp_category || apiPattern.owaspCategory || '',
      remediation: apiPattern.recommendation,
      examples: {
        vulnerable: apiPattern.test_cases?.vulnerable?.[0] || apiPattern.testCases?.vulnerable?.[0] || '',
        secure: apiPattern.test_cases?.safe?.[0] || apiPattern.testCases?.safe?.[0] || ''
      },
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

  /**
   * Clear the pattern cache
   * Useful when patterns might have been updated on the server
   */
  clearCache(): void {
    this.cache.clear();
    logger.info('Pattern cache cleared');
  }

  /**
   * Check the health of the Pattern API
   * @returns Health status object
   */
  async checkHealth(): Promise<{ status: string; message?: string }> {
    try {
      const response = await fetch(`${this.apiUrl}/health`, {
        method: 'GET',
        headers: {
          'User-Agent': 'RSOLV-Action/1.0'
        }
      });

      if (response.ok) {
        return { status: 'healthy' };
      } else {
        return { 
          status: 'unhealthy', 
          message: `API returned status ${response.status}` 
        };
      }
    } catch (error) {
      return { 
        status: 'unhealthy', 
        message: error instanceof Error ? error.message : 'Unknown error' 
      };
    }
  }
}