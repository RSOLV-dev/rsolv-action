/**
 * Type definitions for RFC-031 Elixir AST Analysis Service
 */

// Request types

export interface ASTAnalysisRequest {
  // Unique request ID for tracking
  requestId: string;
  
  // Session management
  sessionId?: string;  // Optional for first request
  
  // Files to analyze (max 10)
  files: AnalysisFile[];
  
  // Analysis options
  options: AnalysisOptions;
}

export interface AnalysisFile {
  // Relative path from repo root
  path: string;
  
  // File content (encrypted)
  encryptedContent: string;
  
  // Encryption metadata
  encryption: {
    // Initialization vector (base64)
    iv: string;
    
    // Algorithm used
    algorithm: "aes-256-gcm";
    
    // Auth tag for GCM mode (base64)
    authTag: string;
  };
  
  // File metadata
  metadata: {
    // Language (auto-detected if not provided)
    language?: "javascript" | "typescript" | "python" | "ruby" | "php" | "java" | "elixir";
    
    // File size in bytes (for validation)
    size: number;
    
    // SHA256 hash of original content
    contentHash: string;
  };
}

export interface AnalysisOptions {
  // Pattern format to use
  patternFormat: "standard" | "enhanced";
  
  // Include security pattern detection
  includeSecurityPatterns: boolean;
  
  // Performance hints
  performance?: {
    // Max time per file in ms
    maxParseTime?: number;
    
    // Skip files larger than this
    maxFileSize?: number;
  };
  
  // Debug options
  debug?: {
    // Include raw AST in response
    includeRawAst?: boolean;
    
    // Include timing information
    includeTiming?: boolean;
  };
}

// Response types

export interface ASTAnalysisResponse {
  // Request ID echo
  requestId: string;
  
  // Session info
  session: {
    // Session ID for subsequent requests
    sessionId: string;
    
    // Session expiry timestamp
    expiresAt: string;  // ISO 8601
  };
  
  // Analysis results per file
  results: FileAnalysisResult[];
  
  // Overall summary
  summary: AnalysisSummary;
  
  // Timing information
  timing?: {
    totalMs: number;
    breakdown: {
      decryption: number;
      parsing: number;
      analysis: number;
      encryption: number;
    };
  };
}

export interface FileAnalysisResult {
  // File path
  path: string;
  
  // Analysis status
  status: "success" | "error" | "timeout" | "skipped";
  
  // Error details if status is "error"
  error?: {
    type: string;
    message: string;
    line?: number;
    column?: number;
  };
  
  // Detected language
  language: string;
  
  // Security findings
  findings: SecurityFinding[];
  
  // AST statistics
  astStats?: {
    nodeCount: number;
    maxDepth: number;
    parseTimeMs: number;
  };
  
  // Raw AST (if requested)
  rawAst?: any;
}

export interface SecurityFinding {
  // Pattern that matched
  patternId: string;
  patternName: string;
  
  // Vulnerability details
  type: string;
  severity: "low" | "medium" | "high" | "critical";
  
  // Location in file
  location: {
    startLine: number;
    startColumn: number;
    endLine: number;
    endColumn: number;
  };
  
  // Code snippet (encrypted)
  encryptedSnippet?: string;
  
  // Confidence score (0-1)
  confidence: number;
  
  // AST-based context
  context?: {
    nodeType: string;
    parentNodeType?: string;
    inTestFile: boolean;
    hasValidation: boolean;
    usesSecurePattern: boolean;
  };
  
  // Recommendation
  recommendation: string;
  
  // References
  references?: {
    cwe?: string;
    owasp?: string;
  };
}

export interface AnalysisSummary {
  // Total files analyzed
  filesAnalyzed: number;
  
  // Files with findings
  filesWithFindings: number;
  
  // Total findings
  totalFindings: number;
  
  // Findings by severity
  findingsBySeverity: {
    critical: number;
    high: number;
    medium: number;
    low: number;
  };
  
  // Findings by language
  findingsByLanguage: {
    [language: string]: number;
  };
  
  // Performance metrics
  performance: {
    avgParseTimeMs: number;
    totalTimeMs: number;
  };
}

// Error response

export interface ErrorResponse {
  error: {
    // Error code
    code: string;
    
    // Human-readable message
    message: string;
    
    // Additional details
    details?: any;
  };
  
  // Request ID for tracking
  requestId?: string;
}

// Error codes enum
export enum ASTErrorCode {
  AUTH_REQUIRED = "AUTH_REQUIRED",
  INVALID_API_KEY = "INVALID_API_KEY",
  SESSION_EXPIRED = "SESSION_EXPIRED",
  RATE_LIMITED = "RATE_LIMITED",
  INVALID_REQUEST = "INVALID_REQUEST",
  FILE_TOO_LARGE = "FILE_TOO_LARGE",
  TOO_MANY_FILES = "TOO_MANY_FILES",
  PARSER_ERROR = "PARSER_ERROR",
  TIMEOUT = "TIMEOUT",
  INTERNAL_ERROR = "INTERNAL_ERROR"
}

// Encryption types

export interface EncryptionKey {
  // Base64 encoded key
  key: string;
  
  // Key ID for rotation
  keyId: string;
  
  // Creation timestamp
  createdAt: string;
}

export interface SessionInfo {
  // Session ID
  sessionId: string;
  
  // Encryption key for session
  encryptionKey: EncryptionKey;
  
  // Session expiry
  expiresAt: string;
}

// File selection types

export interface FileSelectionOptions {
  // Maximum files to select
  maxFiles: number;
  
  // Languages to include
  languages?: string[];
  
  // Path patterns to exclude
  excludePatterns?: RegExp[];
  
  // Maximum file size
  maxFileSize?: number;
  
  // Prioritize changed files
  prioritizeChanges?: boolean;
}

export interface SelectedFile {
  // File path
  path: string;
  
  // File content
  content: string;
  
  // Detected language
  language: string;
  
  // File size
  size: number;
  
  // Content hash
  hash: string;
}

// Configuration

export interface ElixirASTAnalyzerConfig {
  // API endpoint
  apiUrl: string;
  
  // API key
  apiKey: string;
  
  // Request timeout (ms)
  timeout?: number;
  
  // Retry configuration
  retry?: {
    maxAttempts: number;
    backoffMs: number;
  };
  
  // Debug mode
  debug?: boolean;
}