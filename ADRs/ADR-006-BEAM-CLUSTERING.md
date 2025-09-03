# ADR-006: BEAM Clustering for Horizontal Scalability

**Status**: Accepted and Implemented  
**Date**: June 6, 2025  
**Decision Makers**: Development Team

## Context

Both RSOLV Landing (customer-facing Phoenix LiveView application) and RSOLV API (Phoenix API service) need to scale horizontally in Kubernetes while maintaining:
- Shared state consistency (feature flags, caches)
- Real-time updates across instances
- Zero-downtime deployments
- Automatic pod discovery during scaling

The Erlang/Elixir BEAM VM provides built-in clustering capabilities that can solve these requirements elegantly.

## Decision

We will implement BEAM clustering for both Phoenix applications using:
1. **libcluster** library with Kubernetes DNS strategy
2. **Headless services** for pod-to-pod discovery
3. **Phoenix.PubSub** for distributed messaging
4. **Erlang distribution** for node communication

## Rationale

### Why BEAM Clustering?

1. **Native Support**: BEAM was designed for distributed systems
2. **No External Dependencies**: Unlike Redis/Memcached clustering
3. **Automatic Failover**: Nodes handle disconnections gracefully
4. **Low Latency**: Direct node-to-node communication
5. **Battle-Tested**: Used by WhatsApp, Discord, etc. at scale

### Why libcluster?

1. **Kubernetes Integration**: Built-in DNS strategy for K8s
2. **Automatic Discovery**: No manual node configuration
3. **Production Ready**: Widely used in Elixir community
4. **Simple Configuration**: Minimal setup required

### Alternative Considered: Redis PubSub

- **Pros**: Familiar, language-agnostic
- **Cons**: Additional infrastructure, single point of failure, network hop
- **Decision**: BEAM clustering is superior for Elixir applications

## Implementation Details

### 1. Dependencies
```elixir
# mix.exs
{:libcluster, "~> 3.3"}
```

### 2. Cluster Configuration
```elixir
# config/runtime.exs
config :libcluster,
  topologies: [
    k8s: [
      strategy: Cluster.Strategy.Kubernetes.DNS,
      config: [
        service: System.get_env("CLUSTER_SERVICE_NAME", "app-headless"),
        application_name: "app",
        polling_interval: 5_000
      ]
    ]
  ]
```

### 3. Kubernetes Resources
```yaml
# Headless service for discovery
apiVersion: v1
kind: Service
metadata:
  name: app-headless
spec:
  clusterIP: None
  selector:
    app: app-name
  ports:
  - name: epmd
    port: 4369
  - name: erlang
    port: 9000
```

### 4. Application Supervision
```elixir
# lib/app/application.ex
children = [
  {Cluster.Supervisor, [topologies, [name: MyApp.ClusterSupervisor]]},
  MyApp.ClusterMonitor,  # Optional: track node events
  # ... other children
]
```

## Consequences

### Positive

1. **Horizontal Scalability**: Pods can be scaled up/down dynamically
2. **Shared State**: Feature flags, caches work across all nodes
3. **Real-time Updates**: Changes propagate instantly via PubSub
4. **Cost Effective**: No additional infrastructure needed
5. **Developer Experience**: Transparent to application code
6. **Fault Tolerance**: Cluster continues with node failures

### Negative

1. **BEAM Specific**: Only works with Elixir/Erlang applications
2. **Network Security**: Requires open EPMD/distribution ports
3. **Cookie Security**: Shared secret must be managed carefully
4. **Debugging Complexity**: Distributed systems are harder to debug
5. **Local Development**: Requires multi-node setup for full testing

### Mitigations

1. **Security**: Use Kubernetes secrets for Erlang cookie
2. **Monitoring**: Add cluster size metrics to Grafana
3. **Local Dev**: Provide docker-compose.cluster.yml
4. **Documentation**: Comprehensive guides for troubleshooting

## Validation

### Production Testing Results

1. **Scaling**: Successfully tested 2 → 3 → 1 → 3 replicas
2. **Node Discovery**: Automatic within 5 seconds
3. **Feature Flags**: Cache invalidation working across nodes
4. **Health Checks**: All pods remain healthy during scaling

### Performance Impact

- **Memory**: ~10MB overhead per node for clustering
- **CPU**: Negligible (<1% for heartbeats)
- **Network**: ~1KB/s per node for health checks
- **Latency**: <1ms for cross-node messaging

## Future Considerations

1. **Global Distribution**: Multi-region clustering possible
2. **Service Mesh**: Compatible with Istio/Linkerd
3. **Monitoring**: Add distributed tracing
4. **Security**: Implement TLS for node communication
5. **Scale Limits**: Test with 10+ nodes

## References

- [libcluster Documentation](https://hexdocs.pm/libcluster)
- [Erlang Distribution Protocol](https://erlang.org/doc/reference_manual/distributed.html)
- [Phoenix PubSub Guide](https://hexdocs.pm/phoenix_pubsub)
- [Kubernetes DNS for Services](https://kubernetes.io/docs/concepts/services-networking/dns-pod-service/)

## Decision Log

- **2025-06-06**: Initial implementation for both services
- **2025-06-06**: Production deployment and testing completed
- **2025-06-06**: Documentation and local dev setup added