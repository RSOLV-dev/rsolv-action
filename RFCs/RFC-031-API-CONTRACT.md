# RFC-031 AST Service API Contract

## Overview

This document defines the API contract between the TypeScript client (RSOLV-action) and the Elixir AST service backend (RSOLV-api) for RFC-031: Elixir-Powered AST Analysis Service.

## API Endpoint

### AST Analysis Endpoint

**URL**: `POST /api/v1/ast/analyze`  
**Authentication**: Required (API key in header)  
**Content-Type**: `application/json`  
**Timeout**: 30 seconds

## Request Format

```typescript
interface ASTAnalysisRequest {
  // Unique request ID for tracking
  requestId: string;
  
  // Session management
  sessionId?: string;  // Optional for first request
  
  // Files to analyze (max 10)
  files: AnalysisFile[];
  
  // Analysis options
  options: AnalysisOptions;
}

interface AnalysisFile {
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

interface AnalysisOptions {
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
```

## Response Format

```typescript
interface ASTAnalysisResponse {
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

interface FileAnalysisResult {
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

interface SecurityFinding {
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

interface AnalysisSummary {
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
```

## Error Responses

```typescript
interface ErrorResponse {
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
```

### Error Codes

- `AUTH_REQUIRED`: No API key provided
- `INVALID_API_KEY`: API key is invalid or expired
- `SESSION_EXPIRED`: Session has expired, create new session
- `RATE_LIMITED`: Too many requests
- `INVALID_REQUEST`: Request format is invalid
- `FILE_TOO_LARGE`: File exceeds size limit (10MB)
- `TOO_MANY_FILES`: More than 10 files in request
- `PARSER_ERROR`: Parser failed for a specific file
- `TIMEOUT`: Analysis timed out
- `INTERNAL_ERROR`: Unexpected server error

## Encryption Details

### Client-Side Encryption

1. Generate AES-256 key for session
2. Encrypt file content using AES-256-GCM
3. Include IV and auth tag with each file
4. Session key exchanged via secure channel

### Server-Side Decryption

1. Validate session and retrieve key
2. Decrypt file content
3. Process and analyze
4. Encrypt any code snippets in response
5. Delete decrypted content immediately

## Usage Example

### TypeScript Client

```typescript
// Initialize analyzer
const analyzer = new ElixirASTAnalyzer({
  apiKey: process.env.RSOLV_API_KEY,
  apiUrl: 'https://api.rsolv.io'
});

// Select files for analysis
const files = await selectFilesForAnalysis(repository, {
  maxFiles: 10,
  languages: ['python', 'ruby', 'php']
});

// Encrypt and analyze
const response = await analyzer.analyze(files, {
  patternFormat: 'enhanced',
  includeSecurityPatterns: true
});

// Process findings
for (const result of response.results) {
  if (result.status === 'success') {
    for (const finding of result.findings) {
      console.log(`${finding.severity}: ${finding.patternName} at ${finding.location.startLine}`);
    }
  }
}
```

### Elixir Backend

```elixir
defmodule RSOLVWeb.Api.V1.ASTController do
  use RSOLVWeb, :controller
  
  alias RsolvApi.AST.AnalysisService
  alias RsolvApi.AST.SessionManager
  
  def analyze(conn, params) do
    with {:ok, api_key} <- get_api_key(conn),
         {:ok, _customer} <- validate_api_key(api_key),
         {:ok, request} <- validate_request(params),
         {:ok, session} <- get_or_create_session(request),
         {:ok, results} <- AnalysisService.analyze(request, session) do
      
      json(conn, %{
        requestId: request.request_id,
        session: format_session(session),
        results: format_results(results),
        summary: build_summary(results)
      })
    else
      {:error, reason} ->
        conn
        |> put_status(error_status(reason))
        |> json(%{error: format_error(reason)})
    end
  end
end
```

## Rate Limiting

- **Requests per minute**: 60
- **Concurrent requests**: 10
- **Files per request**: 10
- **Max file size**: 10MB
- **Session duration**: 1 hour

## Security Considerations

1. **Zero Code Retention**: All decrypted code deleted after analysis
2. **Session Isolation**: Each session has isolated parser processes
3. **Process Sandboxing**: Parsers run with limited permissions
4. **Audit Logging**: All requests logged (without code content)
5. **Encryption**: E2E encryption for all code transmission

## Backward Compatibility

The AST service is additive and does not break existing pattern API:
- Pattern API continues to work unchanged
- AST analysis is opt-in via new endpoint
- Clients can fall back to regex patterns if AST fails

## Migration Path

1. **Phase 1**: Deploy AST service, test with small subset
2. **Phase 2**: Enable for customers with API keys
3. **Phase 3**: Gradually increase usage based on metrics
4. **Phase 4**: Make AST primary analysis method

## Performance SLAs

- **P50 latency**: < 500ms for 5 files
- **P95 latency**: < 2s for 10 files
- **P99 latency**: < 5s for 10 files
- **Availability**: 99.9% uptime
- **Parser crash recovery**: < 1s

## Monitoring and Metrics

Key metrics to track:
- Request volume by language
- Parse time by language and file size
- Finding accuracy (when ground truth available)
- Session creation/cleanup rates
- Parser process health
- Memory usage per language

## Future Enhancements

1. **Incremental Analysis**: Only analyze changed files
2. **AST Caching**: Cache parsed ASTs by file hash
3. **Custom Patterns**: Allow customers to define AST patterns
4. **Batch API**: Analyze entire repositories asynchronously
5. **WebSocket Support**: Real-time analysis during coding