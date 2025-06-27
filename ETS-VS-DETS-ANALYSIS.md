# ETS vs DETS Analysis for AST Caching in RSOLV

**Date**: 2025-06-26  
**Author**: Claude Code  
**Context**: Evaluating persistent storage options for AST caching in RSOLV's distributed future

## Executive Summary

Based on analysis of RSOLV's AST caching requirements and DETS characteristics, **DETS is NOT suitable** as a primary caching solution. A hybrid approach using ETS with external persistence (Redis/PostgreSQL) or distributed ETS solutions (like Mnesia or Cachex with Nebulex) would be more appropriate.

## Current Implementation Overview

RSOLV currently uses ETS for caching:
- **AST Cache**: 15-minute TTL for parsed ASTs
- **Context Cache**: 5-minute TTL for analysis results
- **Single-node**: Beta deployment on single node
- **Performance**: Target <2s for 10 files

```elixir
# Current implementation in analysis_service.ex
:ets.new(:ast_cache, [:set, :public, :named_table, {:read_concurrency, true}])
cache_key = {:ast, file.path, :erlang.phash2(file.content)}
```

## DETS Capabilities and Limitations

### Capabilities
1. **Persistence**: Survives process/node restarts
2. **Simple API**: Similar to ETS (insert/lookup/delete)
3. **Built-in**: Part of OTP, no external dependencies
4. **Atomic operations**: Single-writer guarantees consistency

### Critical Limitations
1. **File size limit**: 2GB maximum table size
2. **Single writer**: Only one process can write at a time
3. **Performance**: ~10-100x slower than ETS for reads/writes
4. **No distribution**: DETS is local-only, no clustering support
5. **Blocking operations**: All operations are synchronous
6. **Memory overhead**: Must load entire table into memory on open

## Performance Comparison

| Operation | ETS | DETS | Impact on AST Caching |
|-----------|-----|------|----------------------|
| Read (cached) | ~1-10 μs | ~100-1000 μs | 100x slower cache hits |
| Write | ~10-50 μs | ~1-10 ms | Significant parsing overhead |
| Concurrent reads | Excellent | Good (after open) | ETS better for high concurrency |
| Concurrent writes | Good | Poor (single writer) | Bottleneck for parallel parsing |
| Memory usage | In-memory only | Disk + memory | DETS uses more total resources |

## Clustering/Distribution Analysis

### DETS Clustering Reality
DETS provides **NO clustering support**. Each node would have its own separate DETS file:

```elixir
# Node A: dets:open_file(:ast_cache, [{:file, "ast_cache_node_a.dets"}])
# Node B: dets:open_file(:ast_cache, [{:file, "ast_cache_node_b.dets"}])
# These are completely independent - no synchronization
```

### Distribution Challenges
1. **No replication**: Changes on one node don't propagate
2. **No consistency**: Same file could have different ASTs on different nodes
3. **No failover**: If a node dies, its cache is inaccessible
4. **Manual sync required**: Would need custom distribution layer

## Hybrid Approach Analysis

### Option 1: DETS + ETS (Not Recommended)
```elixir
defmodule HybridCache do
  # ETS for fast reads
  # DETS for persistence
  # Problems:
  # - Still no distribution
  # - Complex synchronization
  # - Performance overhead
end
```

### Option 2: ETS + External Store (Recommended)
```elixir
defmodule DistributedASTCache do
  # ETS for local caching
  # Redis/PostgreSQL for persistence and distribution
  # Benefits:
  # - True distribution
  # - Proven scalability
  # - Better performance
end
```

## Specific Gotchas for AST Caching

1. **AST Size**: Large ASTs could quickly hit DETS 2GB limit
   ```elixir
   # Large JavaScript file AST can be 10-50MB
   # Only ~40-200 files before hitting limit
   ```

2. **Write Bottleneck**: Parallel file analysis would serialize on DETS writes
   ```elixir
   # Current parallel analysis
   tasks = Enum.map(files, fn file ->
     Task.async(fn -> analyze_file(file) end)  # Would block on DETS
   end)
   ```

3. **Cache Invalidation**: DETS makes TTL implementation complex
   ```elixir
   # Current ETS approach with TTL
   expiry = System.monotonic_time(:millisecond) + @cache_ttl
   
   # DETS would need manual cleanup process
   # Risk of stale data accumulation
   ```

4. **Recovery Time**: DETS must load entire file on startup
   ```elixir
   # 2GB DETS file = several seconds startup delay
   # Impacts availability during deployments
   ```

## Recommendations

### 1. Stick with ETS for Local Caching
- Maintains current performance characteristics
- No code changes required
- Proven solution

### 2. For Distribution, Consider:

**Option A: Mnesia (Built-in)**
```elixir
:mnesia.create_table(:ast_cache, [
  disc_copies: [node()],
  attributes: [:key, :ast, :expiry],
  type: :set
])
```
- Pros: Built-in, supports distribution, RAM + disk
- Cons: Complex configuration, network partitions

**Option B: Cachex with Nebulex**
```elixir
defmodule RsolvApi.Cache do
  use Nebulex.Cache,
    otp_app: :rsolv_api,
    adapter: Nebulex.Adapters.Multilevel,
    levels: [
      {RsolvApi.Cache.L1, [gc_interval: :timer.hours(12)]},
      {RsolvApi.Cache.L2, [adapter: NebulexRedis.Adapter]}
    ]
end
```
- Pros: Modern, flexible, good abstractions
- Cons: External dependencies

**Option C: Redis/Valkey**
- Pros: Battle-tested, great performance, TTL support
- Cons: External service, operational overhead

### 3. AST-Specific Optimizations
```elixir
defmodule RsolvApi.AST.CacheStrategy do
  # 1. Compress ASTs before caching (10x size reduction)
  defp compress_ast(ast), do: :zlib.compress(:erlang.term_to_binary(ast))
  
  # 2. Cache only frequently accessed files
  defp should_cache?(file_path, access_count) when access_count > 2, do: true
  
  # 3. Implement cache warming for common files
  defp warm_cache(common_patterns), do: # ...
end
```

## Conclusion

DETS is not suitable for RSOLV's AST caching needs due to:
1. No clustering support (critical for production)
2. Performance degradation (100x slower than ETS)
3. Size limitations (2GB max)
4. Write bottlenecks (single writer)

Recommended path:
1. **Short term**: Keep ETS as-is
2. **Medium term**: Add Redis for persistence if needed
3. **Long term**: Implement proper distributed caching with Mnesia or Cachex

The performance and scalability requirements of AST caching (especially with parallel analysis of multiple files) make in-memory solutions with external persistence far more suitable than DETS.