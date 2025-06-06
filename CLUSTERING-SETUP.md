# RSOLV API BEAM Clustering Setup

This document describes the BEAM clustering implementation for RSOLV API, enabling automatic pod discovery and distributed state management in Kubernetes.

## Overview

The clustering solution uses:
- **libcluster** for automatic node discovery via Kubernetes DNS
- **Kubernetes headless service** for pod-to-pod communication
- **Erlang distribution** for BEAM clustering
- **Phoenix.PubSub** for distributed messaging

## Components

### 1. Dependencies
- `libcluster ~> 3.3` added to mix.exs

### 2. Cluster Configuration
- **Runtime Config** (`config/runtime.exs`): Configures libcluster with Kubernetes DNS strategy
- **Cluster Module** (`lib/rsolv/cluster.ex`): Manages cluster configuration and events
- **Cluster Monitor** (`lib/rsolv/cluster_monitor.ex`): Handles node up/down events

### 3. Kubernetes Resources
- **Headless Service** (`rsolv-api-headless`): Enables DNS-based pod discovery
- **Deployment Updates**: Added environment variables for clustering
- **Pod Configuration**: Automatic node naming based on pod name and IP

### 4. Application Changes
- Updated supervision tree to include Cluster.Supervisor
- Added ClusterMonitor to track node events
- Enhanced health endpoint with cluster information

## Deployment

### 1. Update Kubernetes Secrets

First, add an Erlang cookie to your secrets:

```bash
cd RSOLV-api
./k8s/update-secrets-for-clustering.sh
```

This will generate a secure cookie or use the one you provide via `ERLANG_COOKIE` env var.

### 2. Deploy with Clustering

Apply the new deployment configuration:

```bash
kubectl apply -f k8s/deployment-with-clustering.yaml
```

### 3. Verify Clustering

Check the health endpoint to see cluster status:

```bash
# Get the cluster status
curl https://api.rsolv.dev/health | jq .clustering

# Example response:
{
  "enabled": true,
  "current_node": "rsolv_api@10.0.1.5",
  "connected_nodes": ["rsolv_api@10.0.1.6"],
  "node_count": 2
}
```

Watch the logs to see clustering events:

```bash
kubectl logs -f -l app=rsolv-api | grep -E "(Node connected|Node disconnected|cluster)"
```

## Features Enabled by Clustering

### 1. Distributed Caching
The Cachex cache is local to each node, but you can implement cache warming strategies when nodes join.

### 2. Distributed PubSub
Phoenix.PubSub automatically works across the cluster, enabling:
- Real-time updates across all pods
- Distributed event handling
- Load distribution for webhook processing

### 3. Shared State
While most state should be in the database, clustering enables:
- Distributed rate limiting counters
- Shared in-memory state for performance
- Coordinated background jobs

### 4. Graceful Scaling
- New pods automatically join the cluster
- Removed pods gracefully leave
- State synchronization on node join/leave

## Configuration Options

### Environment Variables

- `POD_NAME`: Injected by Kubernetes, used for node naming
- `POD_NAMESPACE`: Kubernetes namespace for DNS discovery
- `RELEASE_COOKIE`: Erlang cookie for secure clustering
- `CLUSTER_SERVICE_NAME`: Name of the headless service (default: `rsolv-api-headless`)

### Clustering Modes

The implementation supports:
1. **Production Mode**: Full clustering with Kubernetes DNS discovery
2. **Development Mode**: Single node without clustering
3. **Test Mode**: Clustering disabled by default

## Monitoring

### Health Check
The `/health` endpoint now includes clustering information:
- Current node name
- Connected nodes
- Total node count

### Logs
Key log messages:
- "Node connected to cluster: ..."
- "Node disconnected from cluster: ..."
- "Current cluster members: ..."

### Metrics
Consider adding Telemetry metrics for:
- Node join/leave events
- Cluster size over time
- Cross-node communication latency

## Troubleshooting

### Pods Not Discovering Each Other

1. Check the headless service:
```bash
kubectl get svc rsolv-api-headless
kubectl get endpoints rsolv-api-headless
```

2. Verify DNS resolution:
```bash
kubectl exec -it [pod-name] -- nslookup rsolv-api-headless
```

3. Check Erlang cookie:
```bash
kubectl get secret rsolv-api-secrets -o jsonpath='{.data.erlang-cookie}' | base64 -d
```

### Node Connection Issues

1. Check EPMD port (4369) is accessible
2. Verify Erlang distribution port (9100) is open
3. Ensure pods have unique names
4. Check logs for cookie mismatch errors

### Performance Considerations

1. **Network Overhead**: Clustering adds network traffic for:
   - Heartbeats between nodes
   - Distributed PubSub messages
   - State synchronization

2. **Memory Usage**: Each node maintains:
   - Connection state to other nodes
   - Distributed process registry
   - PubSub subscription tables

3. **CPU Usage**: Minimal overhead for:
   - Health checks and heartbeats
   - Message routing
   - Cluster management

## Future Enhancements

1. **Distributed Rate Limiting**: Share rate limit counters across nodes
2. **Session Affinity**: Implement sticky sessions for stateful operations
3. **Distributed Tasks**: Use libraries like Oban for distributed job processing
4. **Cache Synchronization**: Implement cache warming and invalidation strategies
5. **Blue-Green Deployments**: Leverage clustering for zero-downtime deployments

## References

- [libcluster Documentation](https://hexdocs.pm/libcluster/)
- [Erlang Distribution](http://erlang.org/doc/reference_manual/distributed.html)
- [Phoenix.PubSub Clustering](https://hexdocs.pm/phoenix_pubsub/Phoenix.PubSub.html)
- [Kubernetes DNS for Services](https://kubernetes.io/docs/concepts/services-networking/dns-pod-service/)