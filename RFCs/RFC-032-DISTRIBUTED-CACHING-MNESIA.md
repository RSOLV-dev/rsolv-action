# RFC-032: Distributed AST Caching with Mnesia

**Status**: Proposed  
**Created**: 2025-01-30  
**Author**: RSOLV Engineering Team

## Summary

Replace the planned Redis caching layer with Mnesia-based distributed caching for AST storage, leveraging Erlang/OTP's built-in distributed database capabilities.

## Motivation

Our current AST caching implementation uses local ETS tables, which works well for single-node deployments but doesn't scale across multiple nodes. While our original plan included Redis for distributed caching, we can achieve the same goals using Mnesia - Erlang's built-in distributed database - eliminating an external dependency.

### Current Architecture
- **L1 Cache**: Local ETS (implemented in Phase 6.1)
- **L2 Cache**: Planned Redis (not yet implemented)
- **L3 Storage**: Planned PostgreSQL for analytics

### Proposed Architecture
- **L1 Cache**: Local ETS (no change)
- **L2 Cache**: Distributed Mnesia RAM tables
- **L3 Storage**: PostgreSQL for analytics (optional)

## Design

### Mnesia Configuration

```elixir
defmodule RsolvApi.AST.DistributedCache do
  @moduledoc """
  Distributed AST cache using Mnesia RAM-only tables.
  Provides cluster-wide caching without external dependencies.
  """
  
  use GenServer
  require Logger
  
  @table_name :ast_cache_distributed
  @local_ets :ast_cache_local
  
  def start_link(opts) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end
  
  def init(opts) do
    # Initialize Mnesia
    setup_mnesia()
    
    # Create local ETS for L1 cache
    :ets.new(@local_ets, [:set, :public, :named_table,
      read_concurrency: true,
      write_concurrency: true
    ])
    
    {:ok, %{opts: opts}}
  end
  
  defp setup_mnesia do
    # Ensure Mnesia schema exists
    case :mnesia.create_schema([node()]) do
      :ok -> :ok
      {:error, {_, {:already_exists, _}}} -> :ok
    end
    
    :ok = :mnesia.start()
    
    # Create distributed table
    case :mnesia.create_table(@table_name, [
      ram_copies: [node()],
      attributes: [:cache_key, :ast_data, :metadata],
      type: :set,
      index: [:language, :inserted_at]
    ]) do
      {:atomic, :ok} -> 
        Logger.info("Created Mnesia table #{@table_name}")
      {:aborted, {:already_exists, @table_name}} ->
        add_table_copy()
      error ->
        Logger.error("Failed to create Mnesia table: #{inspect(error)}")
    end
  end
  
  defp add_table_copy do
    case :mnesia.add_table_copy(@table_name, node(), :ram_copies) do
      {:atomic, :ok} -> :ok
      {:aborted, {:already_exists, @table_name, _}} -> :ok
      error -> Logger.error("Failed to add table copy: #{inspect(error)}")
    end
  end
end
```

### Hybrid Cache Implementation

```elixir
defmodule RsolvApi.AST.HybridCache do
  @moduledoc """
  Two-tier caching strategy:
  1. Local ETS for microsecond access (L1)
  2. Distributed Mnesia for cluster-wide caching (L2)
  """
  
  @local_ttl :timer.minutes(5)
  @distributed_ttl :timer.hours(1)
  
  def get(file_hash, language) do
    cache_key = {file_hash, language}
    
    # Try L1 cache first
    case get_from_local(cache_key) do
      {:ok, ast} -> 
        {:hit, :local, ast}
      
      :miss ->
        # Try L2 distributed cache
        case get_from_mnesia(cache_key) do
          {:ok, ast} ->
            # Populate L1 for next time
            put_to_local(cache_key, ast)
            {:hit, :distributed, ast}
          
          :miss ->
            :miss
        end
    end
  end
  
  def put(file_hash, language, ast) do
    cache_key = {file_hash, language}
    
    # Write to both layers
    put_to_local(cache_key, ast)
    put_to_mnesia(cache_key, ast)
    
    :ok
  end
  
  defp get_from_local(cache_key) do
    case :ets.lookup(:ast_cache_local, cache_key) do
      [{^cache_key, ast, expiry}] ->
        if System.system_time(:second) < expiry do
          {:ok, ast}
        else
          :ets.delete(:ast_cache_local, cache_key)
          :miss
        end
      [] ->
        :miss
    end
  end
  
  defp put_to_mnesia(cache_key, ast) do
    metadata = %{
      inserted_at: System.system_time(:second),
      node: node(),
      size_bytes: :erlang.external_size(ast)
    }
    
    :mnesia.transaction(fn ->
      :mnesia.write({:ast_cache_distributed, cache_key, ast, metadata})
    end)
  end
end
```

### Cluster Management

```elixir
defmodule RsolvApi.AST.CacheCluster do
  @moduledoc """
  Manages Mnesia cluster formation and monitoring
  """
  
  def join_cluster(nodes) when is_list(nodes) do
    case :mnesia.change_config(:extra_db_nodes, nodes) do
      {:ok, connected_nodes} ->
        Logger.info("Connected to nodes: #{inspect(connected_nodes)}")
        sync_tables()
        
      {:error, reason} ->
        Logger.error("Failed to join cluster: #{inspect(reason)}")
    end
  end
  
  def cluster_status do
    %{
      running_nodes: :mnesia.system_info(:running_db_nodes),
      local_tables: :mnesia.system_info(:local_tables),
      ram_copies: :mnesia.table_info(:ast_cache_distributed, :ram_copies),
      size: :mnesia.table_info(:ast_cache_distributed, :size),
      memory: :mnesia.table_info(:ast_cache_distributed, :memory)
    }
  end
end
```

## Benefits

1. **No External Dependencies**: Mnesia is built into OTP
2. **Consistent Performance**: All RAM-based, similar to ETS
3. **Automatic Replication**: Handles node joins/leaves gracefully
4. **Native Integration**: Natural fit with Erlang/Elixir ecosystem
5. **Cost Effective**: No additional infrastructure needed

## Trade-offs

1. **Erlang-Only**: Requires Erlang distribution (epmd, cookies)
2. **Scale Limitations**: Best for <10 nodes (sufficient for RSOLV)
3. **Network Partitions**: More complex than Redis handling
4. **No Polyglot Access**: Other languages can't access cache directly

## Performance Characteristics

| Cache Layer | Latency | Throughput | Use Case |
|-------------|---------|------------|----------|
| Local ETS (L1) | ~1μs | 1M+ ops/sec | Hot cache |
| Mnesia RAM (L2) | ~100μs | 100K ops/sec | Cluster cache |
| Network Fetch | ~50ms | 1K ops/sec | Cache miss |

## Migration Path

1. **Phase 1**: Implement Mnesia tables alongside existing ETS cache
2. **Phase 2**: Add cluster formation logic
3. **Phase 3**: Implement hybrid cache with automatic failover
4. **Phase 4**: Remove Redis from infrastructure plans

## Configuration

```elixir
config :rsolv_api, :ast_cache,
  # L1: Local ETS cache
  local_cache: [
    max_entries: 10_000,
    ttl_seconds: 300,  # 5 minutes
    max_memory_mb: 100
  ],
  
  # L2: Distributed Mnesia cache  
  distributed_cache: [
    ttl_seconds: 3600,  # 1 hour
    max_memory_mb: 500,
    auto_sync: true,
    cluster_nodes: [:node1@host1, :node2@host2]
  ]
```

## Security Considerations

1. **Erlang Cookie**: Must be secured and rotated
2. **Network**: Erlang distribution should use TLS
3. **Access Control**: Mnesia has no built-in auth (relies on BEAM security)

## Future Considerations

If we need cache access from non-Erlang services (Python, Node.js), we can:
1. Add an HTTP API layer
2. Implement a gRPC service
3. Reconsider Redis at that time

## Decision

We will implement distributed caching using Mnesia RAM tables, eliminating the need for Redis in our current architecture. This simplifies our infrastructure while maintaining the performance characteristics needed for AST caching.

## References

- [Mnesia User's Guide](https://www.erlang.org/doc/apps/mnesia/users_guide.html)
- [OTP Distributed Applications](https://www.erlang.org/doc/design_principles/distributed_applications.html)
- [ETS and Mnesia Performance](https://www.erlang.org/doc/efficiency_guide/tablesDatabases.html)