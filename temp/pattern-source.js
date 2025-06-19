// @bun
// src/utils/logger.ts
class Logger {
  minLevel;
  defaultOptions;
  constructor(options = {}) {
    this.minLevel = process.env.LOG_LEVEL?.toLowerCase() || "info";
    this.defaultOptions = {
      timestamp: true,
      ...options
    };
  }
  debug(message, metadata) {
    this.log("debug", message, metadata);
  }
  info(message, metadata) {
    this.log("info", message, metadata);
  }
  warn(message, metadata) {
    this.log("warn", message, metadata);
  }
  error(message, error) {
    let metadata;
    if (error) {
      metadata = {
        error: error instanceof Error ? { message: error.message, stack: error.stack } : error
      };
    }
    this.log("error", message, metadata);
  }
  log(level, message, metadata) {
    if (!this.shouldLog(level)) {
      return;
    }
    const logEntry = this.formatLogEntry(level, message, metadata);
    switch (level) {
      case "debug":
        console.debug(logEntry);
        break;
      case "info":
        console.info(logEntry);
        break;
      case "warn":
        console.warn(logEntry);
        break;
      case "error":
        console.error(logEntry);
        break;
    }
  }
  shouldLog(level) {
    const levels = ["debug", "info", "warn", "error"];
    const minLevelIndex = levels.indexOf(this.minLevel);
    const currentLevelIndex = levels.indexOf(level);
    return currentLevelIndex >= minLevelIndex;
  }
  formatLogEntry(level, message, metadata) {
    const timestamp = this.defaultOptions.timestamp ? `[${new Date().toISOString()}]` : "";
    const levelStr = `[${level.toUpperCase()}]`;
    let logMessage = `${timestamp}${levelStr} ${message}`;
    if (metadata) {
      try {
        const metadataStr = JSON.stringify(metadata, null, 2);
        logMessage += `
${metadataStr}`;
      } catch (error) {
        logMessage += `
[Error serializing metadata]`;
      }
    }
    return logMessage;
  }
  setMinLevel(level) {
    this.minLevel = level;
  }
  getMinLevel() {
    return this.minLevel;
  }
}
var logger = new Logger;

// src/security/types.ts
var VulnerabilityType;
((VulnerabilityType2) => {
  VulnerabilityType2["SQL_INJECTION"] = "sql_injection";
  VulnerabilityType2["XSS"] = "xss";
  VulnerabilityType2["BROKEN_AUTHENTICATION"] = "broken_authentication";
  VulnerabilityType2["SENSITIVE_DATA_EXPOSURE"] = "sensitive_data_exposure";
  VulnerabilityType2["XML_EXTERNAL_ENTITIES"] = "xml_external_entities";
  VulnerabilityType2["BROKEN_ACCESS_CONTROL"] = "broken_access_control";
  VulnerabilityType2["SECURITY_MISCONFIGURATION"] = "security_misconfiguration";
  VulnerabilityType2["INSECURE_DESERIALIZATION"] = "insecure_deserialization";
  VulnerabilityType2["VULNERABLE_COMPONENTS"] = "vulnerable_components";
  VulnerabilityType2["INSUFFICIENT_LOGGING"] = "insufficient_logging";
  VulnerabilityType2["COMMAND_INJECTION"] = "command_injection";
  VulnerabilityType2["PATH_TRAVERSAL"] = "path_traversal";
  VulnerabilityType2["WEAK_CRYPTOGRAPHY"] = "weak_cryptography";
  VulnerabilityType2["DEBUG_MODE"] = "debug_mode";
  VulnerabilityType2["MASS_ASSIGNMENT"] = "mass_assignment";
  VulnerabilityType2["OPEN_REDIRECT"] = "open_redirect";
  VulnerabilityType2["HARDCODED_SECRETS"] = "hardcoded_secrets";
  VulnerabilityType2["XPATH_INJECTION"] = "xpath_injection";
  VulnerabilityType2["LDAP_INJECTION"] = "ldap_injection";
  VulnerabilityType2["INSECURE_TRANSPORT"] = "insecure_transport";
  VulnerabilityType2["UNVALIDATED_REDIRECT"] = "unvalidated_redirect";
  VulnerabilityType2["PROTOTYPE_POLLUTION"] = "prototype_pollution";
  VulnerabilityType2["SSRF"] = "server_side_request_forgery";
  VulnerabilityType2["TYPE_CONFUSION"] = "type_confusion";
  VulnerabilityType2["NULL_POINTER_DEREFERENCE"] = "null_pointer_dereference";
  VulnerabilityType2["CSRF"] = "cross_site_request_forgery";
  VulnerabilityType2["DENIAL_OF_SERVICE"] = "denial_of_service";
  VulnerabilityType2["NOSQL_INJECTION"] = "nosql_injection";
  VulnerabilityType2["INFORMATION_DISCLOSURE"] = "information_disclosure";
  VulnerabilityType2["IMPROPER_INPUT_VALIDATION"] = "improper_input_validation";
  VulnerabilityType2["TEMPLATE_INJECTION"] = "template_injection";
})(VulnerabilityType ||= {});

// src/security/pattern-api-client.ts
class PatternAPIClient {
  apiUrl;
  apiKey;
  cache = new Map;
  cacheTTL;
  fallbackToLocal;
  constructor(config = {}) {
    const baseUrl = config.apiUrl || process.env.RSOLV_API_URL || "https://api.rsolv.dev";
    const cleanBaseUrl = baseUrl.replace(/\/$/, "");
    this.apiUrl = cleanBaseUrl.includes("/api/v1/patterns") ? cleanBaseUrl : `${cleanBaseUrl}/api/v1/patterns`;
    this.apiKey = config.apiKey || process.env.RSOLV_API_KEY;
    this.cacheTTL = (config.cacheTTL || 3600) * 1000;
    this.fallbackToLocal = config.fallbackToLocal ?? true;
    if (!this.apiKey) {
      logger.warn("No RSOLV API key provided - will only have access to public patterns");
    }
  }
  async fetchPatterns(language) {
    const cacheKey = `${language}-${this.apiKey || "public"}`;
    const cached = this.cache.get(cacheKey);
    if (cached && Date.now() - cached.timestamp < this.cacheTTL) {
      logger.info(`Using cached patterns for ${language} (${cached.patterns.length} patterns)`);
      return cached.patterns;
    }
    try {
      const headers = {
        "Content-Type": "application/json"
      };
      if (this.apiKey) {
        headers["Authorization"] = `Bearer ${this.apiKey}`;
      }
      const response = await fetch(`${this.apiUrl}/${language}?format=enhanced`, { headers });
      if (!response.ok) {
        throw new Error(`Failed to fetch patterns: ${response.status} ${response.statusText}`);
      }
      const data = await response.json();
      logger.info(`Fetched ${data.count} ${language} patterns from API (tiers: ${data.accessible_tiers?.join(", ") || "public"})`);
      const patterns = data.patterns.map((p) => this.convertToSecurityPattern(p));
      this.cache.set(cacheKey, { patterns, timestamp: Date.now() });
      return patterns;
    } catch (error) {
      logger.error(`Failed to fetch ${language} patterns from API:`, error);
      if (this.fallbackToLocal) {
        logger.warn(`Falling back to local patterns for ${language}`);
        return [];
      }
      throw error;
    }
  }
  async fetchPatternsByTier(tier, language) {
    const endpoint = language ? `${tier}/${language}` : tier;
    const cacheKey = `tier-${endpoint}-${this.apiKey || "public"}`;
    const cached = this.cache.get(cacheKey);
    if (cached && Date.now() - cached.timestamp < this.cacheTTL) {
      logger.info(`Using cached ${tier} patterns (${cached.patterns.length} patterns)`);
      return cached.patterns;
    }
    try {
      const headers = {
        "Content-Type": "application/json"
      };
      if (tier !== "public" && !this.apiKey) {
        throw new Error(`API key required for ${tier} tier patterns`);
      }
      if (this.apiKey) {
        headers["Authorization"] = `Bearer ${this.apiKey}`;
      }
      const response = await fetch(`${this.apiUrl}/${endpoint}`, { headers });
      if (!response.ok) {
        if (response.status === 403) {
          throw new Error(`Access denied to ${tier} tier patterns - upgrade your plan`);
        }
        throw new Error(`Failed to fetch patterns: ${response.status} ${response.statusText}`);
      }
      const data = await response.json();
      logger.info(`Fetched ${data.count} ${tier} patterns from API`);
      const patterns = data.patterns.map((p) => this.convertToSecurityPattern(p));
      this.cache.set(cacheKey, { patterns, timestamp: Date.now() });
      return patterns;
    } catch (error) {
      logger.error(`Failed to fetch ${tier} patterns from API:`, error);
      throw error;
    }
  }
  clearCache() {
    this.cache.clear();
    logger.info("Pattern cache cleared");
  }
  convertToSecurityPattern(apiPattern) {
    let patternStrings = [];
    if (Array.isArray(apiPattern.patterns)) {
      patternStrings = apiPattern.patterns;
    } else if (apiPattern.patterns && typeof apiPattern.patterns === "object" && "regex" in apiPattern.patterns && Array.isArray(apiPattern.patterns.regex)) {
      patternStrings = apiPattern.patterns.regex;
    } else {
      logger.warn(`Unexpected patterns format for ${apiPattern.id}:`, apiPattern.patterns);
      patternStrings = [];
    }
    const regexPatterns = patternStrings.map((r) => {
      try {
        const match = r.match(/^\/(.*)\/([gimsuvy]*)$/);
        if (match) {
          return new RegExp(match[1], match[2]);
        }
        return new RegExp(r);
      } catch (error) {
        logger.warn(`Failed to compile regex for pattern ${apiPattern.id}: ${r}`, error);
        return null;
      }
    }).filter(Boolean);
    const contextRules = apiPattern.context_rules || undefined;
    return {
      id: apiPattern.id,
      name: apiPattern.name,
      type: this.mapVulnerabilityType(apiPattern.type),
      severity: apiPattern.severity,
      description: apiPattern.description,
      patterns: {
        regex: regexPatterns,
        ast: apiPattern.ast_rules ? [JSON.stringify(apiPattern.ast_rules)] : undefined
      },
      languages: apiPattern.languages,
      frameworks: apiPattern.frameworks || [],
      cweId: apiPattern.cwe_id || apiPattern.cweId || "",
      owaspCategory: apiPattern.owasp_category || apiPattern.owaspCategory || "",
      remediation: apiPattern.recommendation,
      examples: {
        vulnerable: apiPattern.test_cases?.vulnerable?.[0] || apiPattern.testCases?.vulnerable?.[0] || "",
        secure: apiPattern.test_cases?.safe?.[0] || apiPattern.testCases?.safe?.[0] || ""
      },
      astRules: apiPattern.ast_rules,
      contextRules,
      confidenceRules: apiPattern.confidence_rules,
      minConfidence: apiPattern.min_confidence
    };
  }
  mapVulnerabilityType(type) {
    const typeMap = {
      sql_injection: "sql_injection" /* SQL_INJECTION */,
      xss: "xss" /* XSS */,
      command_injection: "command_injection" /* COMMAND_INJECTION */,
      path_traversal: "path_traversal" /* PATH_TRAVERSAL */,
      xxe: VulnerabilityType.XXE,
      ssrf: "server_side_request_forgery" /* SSRF */,
      insecure_deserialization: "insecure_deserialization" /* INSECURE_DESERIALIZATION */,
      deserialization: "insecure_deserialization" /* INSECURE_DESERIALIZATION */,
      weak_crypto: VulnerabilityType.WEAK_CRYPTO,
      hardcoded_secret: VulnerabilityType.HARDCODED_SECRET,
      insecure_random: VulnerabilityType.INSECURE_RANDOM,
      open_redirect: "open_redirect" /* OPEN_REDIRECT */,
      ldap_injection: "ldap_injection" /* LDAP_INJECTION */,
      xpath_injection: "xpath_injection" /* XPATH_INJECTION */,
      nosql_injection: "nosql_injection" /* NOSQL_INJECTION */,
      rce: VulnerabilityType.RCE,
      dos: VulnerabilityType.DOS,
      denial_of_service: VulnerabilityType.DOS,
      timing_attack: VulnerabilityType.TIMING_ATTACK,
      csrf: "cross_site_request_forgery" /* CSRF */,
      jwt: VulnerabilityType.JWT,
      authentication: VulnerabilityType.JWT,
      debug: "information_disclosure" /* INFORMATION_DISCLOSURE */,
      information_disclosure: "information_disclosure" /* INFORMATION_DISCLOSURE */,
      cve: VulnerabilityType.CVE,
      file_upload: "path_traversal" /* PATH_TRAVERSAL */,
      input_validation: "xss" /* XSS */,
      session_management: "cross_site_request_forgery" /* CSRF */,
      resource_exhaustion: VulnerabilityType.DOS
    };
    return typeMap[type] || VulnerabilityType.UNKNOWN;
  }
  clearCache() {
    this.cache.clear();
    logger.info("Pattern cache cleared");
  }
  async checkHealth() {
    try {
      const response = await fetch(`${this.apiUrl}/health`, {
        method: "GET",
        headers: {
          "User-Agent": "RSOLV-Action/1.0"
        }
      });
      if (response.ok) {
        return { status: "healthy" };
      } else {
        return {
          status: "unhealthy",
          message: `API returned status ${response.status}`
        };
      }
    } catch (error) {
      return {
        status: "unhealthy",
        message: error instanceof Error ? error.message : "Unknown error"
      };
    }
  }
}

// src/security/minimal-patterns.ts
var minimalFallbackPatterns = [
  {
    id: "basic-sql-injection",
    name: "Basic SQL Injection",
    type: "sql_injection" /* SQL_INJECTION */,
    severity: "high",
    description: "Potential SQL injection via string concatenation",
    patterns: {
      regex: [
        /["'`].*?(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER).*?["'`]\s*\+/gi,
        /execute\s*\(\s*['"`].*\+/gi
      ]
    },
    languages: ["javascript", "typescript"],
    frameworks: [],
    cweId: "CWE-89",
    owaspCategory: "A03:2021",
    remediation: "Use parameterized queries or prepared statements",
    testCases: { vulnerable: [], safe: [] }
  },
  {
    id: "basic-xss",
    name: "Basic Cross-Site Scripting",
    type: "xss" /* XSS */,
    severity: "high",
    description: "Potential XSS via innerHTML",
    patterns: {
      regex: [
        /innerHTML\s*=\s*[^'"`;]*(?:req\.|request\.)/gi,
        /document\.write\s*\(/gi
      ]
    },
    languages: ["javascript", "typescript"],
    frameworks: [],
    cweId: "CWE-79",
    owaspCategory: "A03:2021",
    remediation: "Use textContent or proper encoding",
    testCases: { vulnerable: [], safe: [] }
  },
  {
    id: "basic-command-injection",
    name: "Basic Command Injection",
    type: "command_injection" /* COMMAND_INJECTION */,
    severity: "critical",
    description: "Potential command injection",
    patterns: {
      regex: [
        /exec\s*\(\s*['"`].*\+/gi,
        /system\s*\(\s*['"`].*\+/gi
      ]
    },
    languages: ["javascript", "python", "ruby"],
    frameworks: [],
    cweId: "CWE-78",
    owaspCategory: "A03:2021",
    remediation: "Validate and sanitize all user input",
    testCases: { vulnerable: [], safe: [] }
  }
];
function getMinimalPatternsByLanguage(language) {
  const normalizedLang = language.toLowerCase();
  return minimalFallbackPatterns.filter((p) => p.languages.includes(normalizedLang) || normalizedLang === "typescript" && p.languages.includes("javascript"));
}

// src/security/pattern-source.ts
class LocalPatternSource {
  patterns = [];
  constructor() {
    this.initializePatterns();
  }
  initializePatterns() {
    this.patterns = minimalFallbackPatterns;
    logger.warn("Using minimal fallback patterns - API connection recommended for full pattern coverage");
  }
  async getPatternsByLanguage(language) {
    const patterns = getMinimalPatternsByLanguage(language);
    logger.info(`LocalPatternSource: Returning ${patterns.length} minimal ${language} patterns`);
    return patterns;
  }
  async getPatternsByType(type) {
    const patterns = this.patterns.filter((p) => p.type === type);
    logger.info(`LocalPatternSource: Returning ${patterns.length} minimal patterns of type ${type}`);
    return patterns;
  }
  async getAllPatterns() {
    logger.info(`LocalPatternSource: Returning ${this.patterns.length} minimal patterns total`);
    return this.patterns;
  }
}

class ApiPatternSource {
  client;
  supportedLanguages = [
    "javascript",
    "typescript",
    "python",
    "ruby",
    "java",
    "php",
    "elixir"
  ];
  constructor(apiKey, apiUrl) {
    this.client = new PatternAPIClient({
      apiKey,
      apiUrl,
      cacheEnabled: true,
      cacheTTL: 3600,
      fallbackToLocal: false
    });
  }
  async getPatternsByLanguage(language) {
    try {
      const patterns = await this.client.fetchPatterns(language.toLowerCase());
      logger.info(`ApiPatternSource: Fetched ${patterns.length} ${language} patterns from API`);
      return patterns;
    } catch (error) {
      logger.error(`ApiPatternSource: Failed to fetch ${language} patterns`, error);
      throw error;
    }
  }
  async getPatternsByType(type) {
    const allPatterns = await this.getAllPatterns();
    const filtered = allPatterns.filter((p) => p.type === type);
    logger.info(`ApiPatternSource: Returning ${filtered.length} patterns of type ${type}`);
    return filtered;
  }
  async getAllPatterns() {
    const allPatterns = [];
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

class HybridPatternSource {
  apiSource;
  localSource;
  constructor(apiKey, apiUrl) {
    this.apiSource = new ApiPatternSource(apiKey, apiUrl);
    this.localSource = new LocalPatternSource;
  }
  async getPatternsByLanguage(language) {
    try {
      return await this.apiSource.getPatternsByLanguage(language);
    } catch (error) {
      logger.warn(`Falling back to local patterns for ${language} due to API error`, error);
      return await this.localSource.getPatternsByLanguage(language);
    }
  }
  async getPatternsByType(type) {
    try {
      return await this.apiSource.getPatternsByType(type);
    } catch (error) {
      logger.warn(`Falling back to local patterns for type ${type} due to API error`, error);
      return await this.localSource.getPatternsByType(type);
    }
  }
  async getAllPatterns() {
    try {
      return await this.apiSource.getAllPatterns();
    } catch (error) {
      logger.warn("Falling back to local patterns due to API error", error);
      return await this.localSource.getAllPatterns();
    }
  }
}
function createPatternSource() {
  const apiKey = process.env.RSOLV_API_KEY;
  const apiUrl = process.env.RSOLV_API_URL;
  const useLocalPatterns = process.env.USE_LOCAL_PATTERNS === "true";
  if (useLocalPatterns) {
    logger.info("Using local pattern source (USE_LOCAL_PATTERNS=true)");
    return new LocalPatternSource;
  }
  if (apiKey) {
    logger.info("Using hybrid pattern source with API key");
    return new HybridPatternSource(apiKey, apiUrl);
  }
  logger.warn("No API key provided, using local pattern source only");
  return new LocalPatternSource;
}
export {
  createPatternSource,
  LocalPatternSource,
  HybridPatternSource,
  ApiPatternSource
};
