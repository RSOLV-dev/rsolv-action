# Pushgateway Deployment Guide

This document provides step-by-step instructions for deploying Prometheus Pushgateway to enable CI/CD metrics export from GitHub Actions.

## Overview

**Problem:** GitHub Actions workflows cannot directly push metrics to Prometheus because they run externally. The workflow was failing with:
```
curl: (6) Could not resolve host: pushgateway
```

**Solution:** Deploy Prometheus Pushgateway to the existing Kubernetes monitoring namespace and configure GitHub Actions to use the public endpoint.

## Architecture

```
GitHub Actions Workflow
  │
  └─→ HTTPS POST metrics
      │
      ↓
  Prometheus Pushgateway (pushgateway.rsolv.dev)
      │
      └─→ Scraped by Prometheus
          │
          └─→ Visualized in Grafana
```

## Prerequisites

- Access to Kubernetes cluster with `kubectl` configured
- Monitoring namespace already exists with Prometheus and Grafana
- DNS configured for `pushgateway.rsolv.dev`
- cert-manager installed for TLS certificates

## Deployment Steps

### 1. Review the Manifest

The Pushgateway manifest is located at `config/monitoring/pushgateway.yaml` and includes:

- **Deployment**: Single replica with resource limits
- **Service**: ClusterIP on port 9091
- **Ingress**: Public HTTPS endpoint with TLS
- **Health checks**: Liveness and readiness probes

**Key Configuration:**
- Image: `prom/pushgateway:v1.9.0`
- Resources: 100m CPU / 128Mi RAM (request), 200m CPU / 256Mi RAM (limit)
- Prometheus annotations for auto-discovery
- Namespace: `monitoring`

### 2. Deploy to Staging

```bash
# Switch to staging context
kubectl config use-context staging

# Apply the manifest
kubectl apply -f config/monitoring/pushgateway.yaml

# Verify deployment
kubectl get pods -n monitoring -l app=pushgateway
kubectl get service -n monitoring pushgateway
kubectl get ingress -n monitoring pushgateway-ingress
```

**Expected Output:**
```
NAME                           READY   STATUS    RESTARTS   AGE
pushgateway-xxxxxxxxxx-xxxxx   1/1     Running   0          30s

NAME          TYPE        CLUSTER-IP      EXTERNAL-IP   PORT(S)    AGE
pushgateway   ClusterIP   10.xxx.xxx.xxx   <none>        9091/TCP   30s

NAME                   CLASS   HOSTS                    ADDRESS         PORTS     AGE
pushgateway-ingress    nginx   pushgateway.rsolv.dev    xxx.xxx.xxx.xxx 80, 443   30s
```

### 3. Verify Pushgateway is Running

```bash
# Check logs
kubectl logs -n monitoring -l app=pushgateway

# Test internal access (from within cluster)
kubectl run -it --rm debug --image=curlimages/curl --restart=Never -- \
  curl http://pushgateway.monitoring.svc.cluster.local:9091/metrics

# Test external access (once DNS is configured)
curl https://pushgateway.rsolv.dev/metrics
```

**Expected:** Should return Pushgateway's own metrics in Prometheus format.

### 4. Configure Prometheus to Scrape Pushgateway

The Pushgateway deployment has Prometheus annotations, so it should be auto-discovered. Verify:

```bash
# Check Prometheus targets
curl https://prometheus.rsolv.dev/api/v1/targets | jq '.data.activeTargets[] | select(.labels.app == "pushgateway")'
```

If not auto-discovered, add this to Prometheus configuration:

```yaml
scrape_configs:
  - job_name: 'pushgateway'
    honor_labels: true
    static_configs:
      - targets: ['pushgateway.monitoring.svc.cluster.local:9091']
```

### 5. Test Metrics Export from Local Machine

```bash
# Push a test metric
cat <<EOF | curl --data-binary @- https://pushgateway.rsolv.dev/metrics/job/test/instance/local
# HELP test_metric A test metric
# TYPE test_metric gauge
test_metric{label="value"} 42
EOF

# Verify it's stored in Pushgateway
curl https://pushgateway.rsolv.dev/metrics | grep test_metric

# Query Prometheus (wait ~30s for scrape)
curl 'https://prometheus.rsolv.dev/api/v1/query?query=test_metric' | jq .

# Clean up test metric
curl -X DELETE https://pushgateway.rsolv.dev/metrics/job/test/instance/local
```

### 6. Update GitHub Repository Secrets

The workflow defaults to `https://pushgateway.rsolv.dev`, but you can override this:

```bash
# Optional: Set a different Pushgateway URL
gh secret set PUSHGATEWAY_URL --body "https://pushgateway.rsolv.dev"
```

**Note:** If the secret is not set, the workflow uses the production URL by default.

### 7. Test GitHub Actions Integration

Trigger the test monitoring workflow:

```bash
# The workflow runs automatically after "Elixir/Phoenix CI" completes
# To manually test, trigger the main CI workflow
gh workflow run "Elixir/Phoenix CI"

# Monitor the test-monitoring workflow
gh run watch

# Check for errors
gh run view --log
```

**Expected:** No "Could not resolve host" errors. Metrics should be exported successfully.

### 8. Deploy to Production

**Status:** ✅ COMPLETED (2025-10-30)

Production deployment uses separate hostnames to avoid staging conflicts:
- **Staging:** `https://pushgateway.rsolv-staging.com`
- **Production:** `https://pushgateway.rsolv.dev` and `https://pushgateway.rsolv.ai`

Deployment is managed via kustomize overlays:

```bash
# Deploy to production
kubectl apply -k ~/dev/rsolv/RSOLV-infrastructure/shared/monitoring/overlays/production

# Verify deployment
kubectl get pods -n rsolv-monitoring -l app=pushgateway
kubectl get service pushgateway -n rsolv-monitoring
kubectl get ingress pushgateway-ingress -n rsolv-monitoring

# Test external access (requires authentication)
curl -I https://pushgateway.rsolv.dev/metrics  # Should return 401
curl --user "github-actions:PASSWORD" https://pushgateway.rsolv.dev/metrics  # Returns metrics
```

**Production Credentials:** Separate password from staging, stored in:
- Kubernetes: `pushgateway-auth` secret in `rsolv-monitoring` namespace
- GitHub: `PUSHGATEWAY_PASSWORD` repository secret (updated with production password)

## Monitoring and Maintenance

### Check Pushgateway Metrics

```bash
# View all stored metrics
curl https://pushgateway.rsolv.dev/metrics

# Check Pushgateway's own metrics
curl https://pushgateway.rsolv.dev/metrics | grep -E "^pushgateway_"
```

### View CI Metrics in Grafana

1. Access Grafana: https://grafana.rsolv.dev
2. Import the CI dashboard from `config/monitoring/ci_dashboard.json` (if not already imported)
3. Look for panels showing:
   - Test execution duration
   - Test pass/fail counts
   - Code coverage percentage
   - Workflow execution status

### Clean Up Old Metrics

Pushgateway stores metrics indefinitely. To prevent unbounded growth:

```bash
# Delete metrics for a specific job
curl -X DELETE https://pushgateway.rsolv.dev/metrics/job/ci/workflow/test-monitoring

# Or use the Pushgateway API to manage metrics programmatically
```

### Update Pushgateway

```bash
# Update the image version in pushgateway.yaml
# Then apply:
kubectl apply -f config/monitoring/pushgateway.yaml

# Or use kubectl set image:
kubectl set image deployment/pushgateway pushgateway=prom/pushgateway:v1.10.0 -n monitoring
```

## Troubleshooting

### Pushgateway Pod Not Starting

```bash
# Check pod status
kubectl describe pod -n monitoring -l app=pushgateway

# Check logs
kubectl logs -n monitoring -l app=pushgateway

# Common issues:
# - Resource limits too low
# - Image pull errors
# - Port conflicts
```

### Cannot Reach Pushgateway Externally

```bash
# Check ingress configuration
kubectl describe ingress -n monitoring pushgateway-ingress

# Check cert-manager certificate
kubectl get certificate -n monitoring pushgateway-rsolv-dev-tls
kubectl describe certificate -n monitoring pushgateway-rsolv-dev-tls

# Check DNS resolution
nslookup pushgateway.rsolv.dev
dig pushgateway.rsolv.dev

# Test from within cluster
kubectl run -it --rm debug --image=curlimages/curl --restart=Never -- \
  curl http://pushgateway.monitoring.svc.cluster.local:9091/-/healthy
```

### Metrics Not Appearing in Prometheus

```bash
# Verify Prometheus is scraping Pushgateway
curl https://prometheus.rsolv.dev/api/v1/targets | jq '.data.activeTargets[] | select(.labels.app == "pushgateway")'

# Check Prometheus scrape configuration
kubectl get configmap -n monitoring prometheus-config -o yaml

# Check Prometheus logs
kubectl logs -n monitoring -l app=prometheus | grep pushgateway
```

### GitHub Actions Still Failing

```bash
# Check workflow logs
gh run view --log | grep -A 5 "Export metrics to Prometheus"

# Common issues:
# - PUSHGATEWAY_URL not set correctly
# - Network connectivity from GitHub Actions
# - TLS certificate issues
# - Rate limiting

# Test from external network (similar to GitHub Actions)
curl -v https://pushgateway.rsolv.dev/metrics
```

## Security Considerations

### Access Control

The current configuration allows public access to Pushgateway. To restrict access:

1. **GitHub Actions IP Ranges**: Update the ingress annotation:
   ```yaml
   nginx.ingress.kubernetes.io/whitelist-source-range: "IP_RANGES_HERE"
   ```

2. **Authentication**: Add basic auth or API key requirement
3. **Network Policies**: Restrict ingress/egress at the Kubernetes level

### Metric Retention

Pushgateway stores metrics in memory. To prevent abuse:

1. **Resource Limits**: Already configured (256Mi memory limit)
2. **Metric Cleanup**: Implement periodic cleanup via cron job
3. **Monitoring**: Alert on high memory usage

## Related Documentation

- **Main Infrastructure**: `~/dev/rsolv/RSOLV-infrastructure/MONITORING.md`
- **Test Monitoring**: `config/monitoring/README.md`
- **RFC-060**: Observability and validation monitoring
- **Prometheus Pushgateway Docs**: https://github.com/prometheus/pushgateway

## Success Criteria

- ✅ Pushgateway deployed and healthy in Kubernetes
- ✅ Public HTTPS endpoint accessible at `https://pushgateway.rsolv.dev`
- ✅ Prometheus scraping Pushgateway successfully
- ✅ GitHub Actions workflow exports metrics without errors
- ✅ Metrics visible in Grafana dashboards
- ✅ No "Could not resolve host" errors in workflow logs

## Rollback Plan

If issues occur:

```bash
# Remove Pushgateway deployment
kubectl delete -f config/monitoring/pushgateway.yaml

# Revert workflow changes (uses GitHub check run fallback)
git revert <commit-hash>

# Or set PUSHGATEWAY_URL to empty string to skip export
gh secret set PUSHGATEWAY_URL --body ""
```

**Note:** The workflow has a built-in fallback that creates GitHub check runs with metrics even if Pushgateway export fails, so the monitoring data is not lost.

---

**Last Updated:** 2025-10-29
**Status:** Ready for deployment
**Tested:** Staging environment recommended before production
