# RFC-031 AST Analysis Service Technical Review

**Date**: December 25, 2024  
**Reviewer**: Claude Code

## Executive Summary

The RFC-031 AST Analysis Service implementation shows a solid foundation with proper architecture for security, scalability, and reliability. However, several technical compromises, security considerations, and operational concerns need attention before production deployment.

## 1. Technical Compromises & Shortcuts

### 1.1 Hardcoded Pattern Detection (CRITICAL)
**Location**: `lib/rsolv_api/ast/analysis_service.ex:317-393`
- Pattern detection uses simple regex instead of actual AST analysis
- The service claims to use AST but falls back to regex patterns
- No actual integration with parsed AST data for pattern matching
- This defeats the primary purpose of AST-based analysis

**Recommendation**: Implement proper AST traversal and pattern matching using the parsed AST structure.

### 1.2 Test Parser Configuration (HIGH)
**Location**: `lib/rsolv_api/ast/parser_registry.ex:77-95`
- Parser paths hardcoded to test fixtures: `test/rsolv_api/ast/fixtures`
- Using Python scripts as parsers instead of proper language parsers
- No production parser binaries configured
- No fallback if test parsers are unavailable

**Recommendation**: 
- Move parser configurations to config files
- Use actual language parsers (tree-sitter, babel, etc.)
- Implement parser discovery mechanism

### 1.3 Missing Timing Metrics (MEDIUM)
**Location**: `lib/rsolv_api_web/controllers/api/v1/ast_controller.ex:403-406`
```elixir
decryption: 0,  # TODO: Track this
analysis: 0,    # TODO: Track this
encryption: 0   # TODO: Track this
```
- Timing breakdown not implemented
- Makes performance optimization difficult

**Recommendation**: Implement proper timing instrumentation for each phase.

## 2. Security Considerations

### 2.1 Parser Process Isolation (HIGH)
**Issue**: Limited sandboxing of parser processes
- Port processes have access to file system
- No proper resource isolation beyond environment variables
- Potential for parser exploits to affect the system

**Recommendation**:
- Run parsers in Docker containers or proper sandboxes
- Use seccomp/AppArmor profiles
- Implement proper resource limits at OS level

### 2.2 Encryption Key Management (MEDIUM)
**Location**: `lib/rsolv_api/ast/session_manager.ex`
- Encryption keys stored in ETS (in-memory)
- No key rotation mechanism
- Keys persist for full session duration (1 hour)
- No audit trail for key usage

**Recommendation**:
- Implement key rotation for long sessions
- Add key usage auditing
- Consider using external key management service

### 2.3 Rate Limiting Granularity (MEDIUM)
**Location**: `lib/rsolv_api_web/controllers/api/v1/ast_controller.ex:133`
- Rate limiting only by customer ID
- No per-file or per-language limits
- Could be exploited with large files

**Recommendation**: Implement multi-tier rate limiting:
- Per-customer request rate
- Per-customer file count rate
- Per-customer data volume rate

## 3. Performance Bottlenecks

### 3.1 Sequential File Decryption (HIGH)
**Location**: `lib/rsolv_api_web/controllers/api/v1/ast_controller.ex:223-241`
- Files are decrypted in parallel tasks
- But Task.await_many blocks until all complete
- One slow decryption blocks entire request

**Recommendation**: Implement streaming decryption with timeouts per file.

### 3.2 AST Cache Key Strategy (MEDIUM)
**Location**: `lib/rsolv_api/ast/analysis_service.ex:258`
```elixir
cache_key = {:ast, file.path, :erlang.phash2(file.content)}
```
- Cache key includes full file content hash
- Large files cause expensive hashing
- No cache warming strategy

**Recommendation**:
- Use file metadata for cache keys
- Implement cache warming for common files
- Add cache size limits

### 3.3 Port Process Pool Management (MEDIUM)
**Location**: `lib/rsolv_api/ast/port_supervisor.ex`
- No pre-warming of parser processes
- Cold start penalty for first request per language
- Idle timeout might be too aggressive (5 minutes)

**Recommendation**:
- Pre-warm parser pools on startup
- Implement adaptive pool sizing
- Adjust idle timeout based on usage patterns

## 4. Integration Points Needing Attention

### 4.1 Pattern Service Integration (CRITICAL)
- No integration with existing pattern service
- AST findings format differs from pattern API
- No fallback to pattern-based detection

**Recommendation**: 
- Unify finding formats
- Implement hybrid detection (AST + patterns)
- Add feature flags for gradual rollout

### 4.2 Monitoring & Observability (HIGH)
- No Prometheus metrics for AST operations
- Limited logging for debugging
- No distributed tracing support

**Recommendation**:
- Add Prometheus metrics for all operations
- Implement structured logging
- Add OpenTelemetry support

### 4.3 Error Recovery (MEDIUM)
- Parser crashes affect entire session
- No partial results on timeout
- Binary parser output not validated

**Recommendation**:
- Implement per-file error isolation
- Return partial results when possible
- Add parser output validation

## 5. Testing Gaps & Edge Cases

### 5.1 Large File Handling
- No tests for 10MB file limit
- No tests for memory pressure scenarios
- No tests for concurrent large files

### 5.2 Parser Failure Modes
- No tests for corrupt parser output
- No tests for parser memory leaks
- No tests for parser infinite loops

### 5.3 Security Edge Cases
- No tests for malformed encryption
- No tests for session hijacking attempts
- No tests for parser command injection

### 5.4 Performance Under Load
- No load testing results
- No benchmarks for concurrent sessions
- No capacity planning data

## 6. Configuration & Deployment Considerations

### 6.1 Missing Configuration Options
- Parser paths hardcoded
- Timeouts hardcoded
- Resource limits hardcoded
- No environment-specific configs

**Recommendation**: Move to configuration:
```elixir
config :rsolv_api, :ast_service,
  parsers: %{
    javascript: %{
      command: System.get_env("JS_PARSER_PATH", "/usr/local/bin/js-parser"),
      timeout: 5_000,
      max_memory: 100_000_000
    }
  },
  session_ttl: :timer.hours(1),
  cache_ttl: :timer.minutes(15),
  max_files_per_request: 10,
  max_file_size: 10_485_760
```

### 6.2 Deployment Requirements Not Documented
- Required system packages (Python3, etc.)
- Memory requirements per language
- CPU requirements for concurrent parsing
- Network security requirements

### 6.3 Operational Procedures Missing
- How to add new language parsers
- How to update parser versions
- How to monitor parser health
- How to debug parser failures

## 7. Critical Action Items

1. **Implement Real AST Pattern Matching** - Current regex approach defeats the purpose
2. **Production Parser Configuration** - Move away from test fixtures
3. **Security Hardening** - Proper sandboxing and isolation
4. **Complete Timing Metrics** - Essential for optimization
5. **Load Testing** - Validate performance assumptions
6. **Operational Documentation** - Deployment and maintenance guides

## 8. Positive Aspects

Despite the issues, the implementation has several strong points:
- Clean architecture with proper separation of concerns
- Good test coverage for implemented features
- Proper use of OTP patterns (GenServer, Supervisor)
- E2E encryption properly implemented
- Session management with automatic cleanup
- Comprehensive error handling structure

## Conclusion

The RFC-031 implementation provides a solid foundation but requires significant work before production readiness. The most critical issue is the lack of actual AST-based pattern matching, which should be the primary focus. Security hardening and operational concerns should be addressed before handling untrusted code.

Estimated additional work needed: 2-3 weeks for critical items, 4-6 weeks for full production readiness.