# ADR-014: Elixir-Powered AST Analysis Service

**Status**: Implemented  
**Date**: June 28, 2025  
**RFC**: RFC-031  

## Context

RSOLV was experiencing unacceptably high false positive rates (40%+) on non-JavaScript/TypeScript codebases because AST parsing was only available client-side for JS/TS. Other languages relied solely on regex patterns, missing critical context and code structure information.

## Decision

We implemented a centralized AST analysis service in the Elixir backend that:
1. Supports multi-language AST parsing via Ports
2. Provides E2E encryption for code security
3. Enables AST-based pattern matching for all languages
4. Maintains process isolation and sandboxing

## Architecture

### Core Components

1. **AST Service** (`/lib/rsolv_api/ast/`)
   - Session management with encryption
   - Port supervisor for parser processes
   - Language-specific parser modules
   - Pattern matching engine
   - Caching and pooling for performance

2. **External Parsers** (`/priv/parsers/`)
   - Python parser using native AST
   - Ruby parser using Parser gem
   - PHP parser using PHP-Parser
   - Java parser using JavaParser
   - Go parser using go/ast

3. **Security Layers**
   - E2E encryption (AES-256-GCM)
   - Process sandboxing with resource limits
   - No code retention after analysis
   - Session-based key management

4. **Client Integration**
   - ElixirASTAnalyzer in RSOLV-action
   - Intelligent file selection (10 file limit)
   - Graceful fallback to regex patterns
   - Confidence scoring normalization

## Implementation Details

### Port Communication
```elixir
# JSON-based protocol for parser communication
port = Port.open({:spawn_executable, parser_path}, 
  [:binary, :exit_status, line: 65536])
  
request = JSON.encode!(%{action: "parse", id: id, code: code})
Port.command(port, request <> "\n")
```

### Security Hardening
- Enhanced sandbox with validation modes
- Parser pool pre-warming
- Batch processing for efficiency
- Comprehensive audit logging

### Performance Optimizations
- AST caching layer
- Connection pooling
- Parallel batch processing
- Smart file prioritization

## Results

### Accuracy Improvements
- False positive rate: 40% → <5% for Python/Ruby
- True positive rate: >95% across all languages
- Context-aware detection preventing noise

### Performance Metrics
- Parse time: <200ms per file
- Total time for 10 files: <2s
- Memory usage: <50MB per parser
- Concurrent handling: 50+ requests

### Security Achievements
- Zero code retention verified
- Process isolation maintained
- Resource limits enforced
- Full audit trail without code storage

## Lessons Learned

1. **Ports over NIFs**: Safety and isolation outweigh performance
2. **JSON over custom protocols**: Simplicity and debugging win
3. **Caching is critical**: AST parsing is expensive
4. **Fallback strategies**: Always have regex patterns as backup
5. **E2E encryption complexity**: Session management needs careful design

## Test Coverage

- 71 security-specific tests
- 2,773 pattern tests passing
- Comprehensive E2E validation
- Performance benchmarks documented

## Production Considerations

1. **Parser version management**: Each parser reports its version
2. **Resource monitoring**: Track parser memory/CPU usage
3. **Graceful degradation**: Fallback to regex when AST fails
4. **Language coverage**: Extensible to new languages

## Future Enhancements

1. **Enhanced patterns**: Currently blocked by JSON encoding (RFC-032)
2. **More languages**: Rust, C/C++, Kotlin support
3. **Incremental parsing**: For large files
4. **Parser clustering**: For horizontal scaling

## References

- Original RFC: RFC-031-ELIXIR-AST-ANALYSIS-SERVICE.md
- Implementation tracking: RFC-031-ELIXIR-AST-SERVICE-METHODOLOGY.md
- Pattern API enhancement: RFC-032-PATTERN-API-JSON-MIGRATION.md