# RFC-023: Elixir-Powered AST Analysis Service

**Status**: Draft  
**Created**: 2025-06-24  
**Author**: RSOLV Team

## Summary

Leverage RSOLV's Elixir backend to provide accurate multi-language AST analysis as a service, solving the current limitation where only JavaScript/TypeScript can be parsed effectively. This service would receive encrypted code files, perform AST analysis, and return only vulnerability metadata while ensuring customer code security.

## Problem Statement

Our current AST analysis has critical limitations discovered during Phase 6C:

1. **Single Language Parser**: AST interpreter uses Babel, supporting only JavaScript/TypeScript
2. **Regex-Only Fallback**: Other languages fall back to less accurate regex matching
3. **High False Positive Rate**: Without AST context, regex patterns over-match
4. **Maintenance Burden**: Each language needs separate parser integration in TypeScript
5. **Performance Issues**: Client-side parsing of large files is resource-intensive

This results in:
- 0% detection rate for Java/PHP vulnerabilities with AST-enhanced patterns
- Inability to understand language-specific safe patterns
- Poor differentiation between vulnerable and secure code constructs

## Proposed Solution

### Architecture Overview

```
┌─────────────────────┐
│   GitHub Action     │
│   (TypeScript)      │
└──────────┬──────────┘
           │ HTTPS + E2E Encryption
           │ {files, language, patterns}
┌──────────▼──────────┐
│   RSOLV API         │
│   (Elixir)          │
│ ┌─────────────────┐ │
│ │  AST Service    │ │
│ │ ┌─────────────┐ │ │
│ │ │Lang Parsers │ │ │
│ │ └─────────────┘ │ │
│ └─────────────────┘ │
└──────────┬──────────┘
           │ Metadata Only
           │ {findings, confidence, fixes}
┌──────────▼──────────┐
│   GitHub Action     │
│   (Results)         │
└─────────────────────┘
```

### Core Components

#### 1. Secure File Transmission

```typescript
interface ASTAnalysisRequest {
  sessionId: string;           // Unique session for audit trail
  files: EncryptedFile[];      // E2E encrypted file contents
  language: string;            // Target language
  patterns: string[];          // Vulnerability patterns to check
  options: {
    maxFiles: number;          // Limit files per request (default: 10)
    timeout: number;           // Analysis timeout (default: 30s)
    includeFixSuggestions: boolean;
  };
}

interface EncryptedFile {
  path: string;                // Relative file path
  content: string;             // Base64 encoded encrypted content
  hash: string;                // SHA-256 of original content
}
```

#### 2. Elixir AST Service

```elixir
defmodule RSOLV.AST.Service do
  @moduledoc """
  Multi-language AST analysis service with security-first design
  """
  
  def analyze_files(request) do
    with {:ok, session} <- create_session(request.session_id),
         {:ok, files} <- decrypt_files(request.files),
         {:ok, parser} <- get_parser(request.language),
         {:ok, results} <- perform_analysis(files, parser, request.patterns),
         :ok <- cleanup_session(session) do
      
      {:ok, build_metadata_response(results)}
    else
      error -> handle_error(error)
    end
  end
  
  defp perform_analysis(files, parser, patterns) do
    files
    |> Task.async_stream(&analyze_file(&1, parser, patterns), 
         timeout: 10_000,
         max_concurrency: 5)
    |> Enum.map(&handle_result/1)
    |> aggregate_findings()
  end
  
  defp cleanup_session(session) do
    # Immediately delete all code from memory and any temporary storage
    SessionStore.delete(session.id)
    GC.run() # Force garbage collection
    :ok
  end
end
```

#### 3. Language Parser Registry

```elixir
defmodule RSOLV.AST.ParserRegistry do
  @parsers %{
    "elixir" => RSOLV.AST.Parsers.Elixir,      # Native Code.string_to_quoted
    "javascript" => RSOLV.AST.Parsers.Babel,    # Babel via Port
    "typescript" => RSOLV.AST.Parsers.Babel,    # Babel via Port
    "java" => RSOLV.AST.Parsers.Java,          # TreeSitter NIF
    "python" => RSOLV.AST.Parsers.Python,      # Python AST via Port
    "ruby" => RSOLV.AST.Parsers.Ruby,          # Parser gem via Port
    "php" => RSOLV.AST.Parsers.PHP,            # PHP-Parser via Port
    "go" => RSOLV.AST.Parsers.Go,              # go/parser via Port
    "rust" => RSOLV.AST.Parsers.Rust,          # syn via Port
    "csharp" => RSOLV.AST.Parsers.CSharp       # Roslyn via Port
  }
  
  def get_parser(language) do
    case Map.get(@parsers, language) do
      nil -> {:error, :unsupported_language}
      parser -> {:ok, parser}
    end
  end
end
```

#### 4. Pattern Matching Engine

```elixir
defmodule RSOLV.AST.PatternMatcher do
  @doc """
  Elixir's pattern matching makes AST analysis elegant
  """
  
  # SQL Injection Detection
  def match_pattern(:sql_injection, {:binary_op, _, :concat, left, right}) do
    if sql_query?(left) and user_input?(right) do
      {:match, confidence: 0.95}
    else
      :no_match
    end
  end
  
  # Command Injection Detection
  def match_pattern(:command_injection, {:call, _, func, args}) 
      when func in [:exec, :system, :spawn] do
    if any_user_input?(args) do
      {:match, confidence: 0.90}
    else
      :no_match
    end
  end
  
  # Language-specific safe pattern detection
  def safe_pattern?(:java, {:call, _, "prepareStatement", _}), do: true
  def safe_pattern?(:python, {:call, _, "execute", [_query, _params]}), do: true
  def safe_pattern?(:ruby, {:call, _, "where", [{:hash, _}]}), do: true
end
```

### Security Measures

#### 1. Encryption
- **In Transit**: TLS 1.3 + additional E2E encryption layer
- **At Rest**: Encrypted temporary storage with automatic expiration
- **Key Management**: Separate ephemeral keys per session

#### 2. Data Retention
- **Zero Retention**: All code deleted immediately after analysis
- **Audit Trail**: Only metadata kept (file paths, timestamps, findings)
- **Memory Clearing**: Explicit garbage collection after each session

#### 3. Access Control
- **Rate Limiting**: Per-customer limits on API usage
- **File Limits**: Maximum 10 files per request
- **Size Limits**: Maximum 1MB per file
- **Timeout**: 30-second hard timeout per analysis

#### 4. Isolation
- **Process Isolation**: Each parser runs in isolated OS process
- **Resource Limits**: CPU and memory limits per analysis
- **Network Isolation**: Parsers have no network access

### Client Integration

```typescript
class ElixirASTAnalyzer implements ASTAnalyzer {
  private encryptionKey: CryptoKey;
  
  async analyzeFiles(files: FileMap, patterns: SecurityPattern[]): Promise<Finding[]> {
    // 1. Select files for analysis (limit to 10 most likely)
    const selectedFiles = this.selectHighValueFiles(files, patterns);
    
    // 2. Encrypt files
    const encryptedFiles = await this.encryptFiles(selectedFiles);
    
    // 3. Send to Elixir service
    const response = await this.rsolvAPI.analyzeAST({
      sessionId: crypto.randomUUID(),
      files: encryptedFiles,
      language: this.detectLanguage(selectedFiles),
      patterns: patterns.map(p => p.id),
      options: {
        maxFiles: 10,
        timeout: 30000,
        includeFixSuggestions: true
      }
    });
    
    // 4. Process metadata response
    return this.processFindings(response.findings);
  }
  
  private selectHighValueFiles(files: FileMap, patterns: SecurityPattern[]): File[] {
    // Intelligent selection based on:
    // - File extensions matching pattern languages
    // - Files containing pattern keywords
    // - Recently modified files
    // - Files in security-sensitive directories
    return files
      .filter(f => this.isHighValue(f, patterns))
      .slice(0, 10);
  }
}
```

## Benefits

1. **Accuracy**: Real AST parsing for all major languages
2. **Performance**: Elixir's concurrent processing and pattern matching
3. **Maintainability**: Centralized parser updates
4. **Security**: Customer code never persisted
5. **Scalability**: Horizontal scaling of Elixir nodes
6. **Consistency**: Same analysis engine for all languages

## Drawbacks

1. **Network Dependency**: Requires API connectivity
2. **Latency**: Additional round-trip time (mitigated by batching)
3. **Complexity**: More moving parts than client-side parsing
4. **Trust**: Customers must trust RSOLV with their code (mitigated by security measures)

## Implementation Plan

### Phase 1: Core Infrastructure (2 weeks)
1. Design encryption protocol
2. Implement session management
3. Create parser registry
4. Build security isolation layer

### Phase 2: Language Parsers (4 weeks)
1. **Week 1**: JavaScript/TypeScript (already supported)
2. **Week 2**: Python, Ruby (high-usage languages)
3. **Week 3**: Java, C# (enterprise languages)
4. **Week 4**: Go, Rust, PHP (growing adoption)

### Phase 3: Pattern Engine (2 weeks)
1. Port existing patterns to Elixir matchers
2. Create language-specific safe pattern detection
3. Implement confidence scoring

### Phase 4: Client Integration (1 week)
1. Update TypeScript AST analyzer
2. Add encryption layer
3. Implement intelligent file selection
4. Create fallback mechanisms

### Phase 5: Security Hardening (1 week)
1. Penetration testing
2. Performance testing
3. Security audit
4. Documentation

## Success Metrics

1. **Detection Accuracy**: >95% true positive rate (vs current ~60% for non-JS)
2. **Performance**: <2s analysis time for 10 files
3. **Security**: Zero code retention verified by audit
4. **Adoption**: 80% of customers using AST analysis
5. **Languages**: 10+ languages supported

## Alternatives Considered

1. **Client-Side Parsers**: Too heavy, maintenance burden
2. **WebAssembly Parsers**: Limited language support
3. **Tree-sitter Only**: Good but lacks semantic understanding
4. **External Service**: Security and latency concerns

## Open Questions

1. Should we offer an on-premise version for high-security customers?
2. How do we handle very large files (>1MB)?
3. Should we cache AST results by file hash?
4. What's the pricing model for this service?
5. How do we handle parser version updates?

## Security Considerations

1. **Compliance**: Ensure SOC2, GDPR compliance
2. **Audit Logging**: Complete audit trail without storing code
3. **Encryption**: Consider post-quantum cryptography
4. **Rate Limiting**: Prevent abuse and DoS
5. **Input Validation**: Prevent parser exploits

## Migration Strategy

1. **Opt-in Beta**: Selected customers can enable AST service
2. **Gradual Rollout**: Language by language activation
3. **Fallback**: Always fall back to regex if service unavailable
4. **Monitoring**: Track accuracy improvements

## References

- [RFC-021: Multi-Language AST Parsing Architecture](./RFC-021-MULTI-LANGUAGE-AST-PARSING.md)
- [Elixir AST Metaprogramming Guide](https://hexdocs.pm/elixir/quote-and-unquote.html)
- [TreeSitter Language Parsers](https://tree-sitter.github.io/tree-sitter/)
- [OWASP Secure Coding Practices](https://owasp.org/www-project-secure-coding-practices-quick-reference-guide/)