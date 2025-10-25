# Documentation Site Deployment

**Date**: 2025-10-23
**Status**: Deployed (DNS pending)

## Overview

Deployed static documentation sites for RSOLV to Kubernetes cluster to resolve the critical blocker for GitHub Marketplace submission.

## Deployed Resources

### Staging Environment (rsolv-staging namespace)

**ConfigMaps:**
- `docs-content` - HTML documentation content
- `docs-nginx-config` - Nginx server configuration

**Deployment:**
- Name: `docs-rsolv`
- Replicas: 1
- Image: `nginx:alpine`
- Status: ✅ Running

**Service:**
- Name: `docs-rsolv`
- Type: ClusterIP
- Port: 80

**Ingress:**
- Name: `docs-rsolv-ingress`
- Host: `docs.rsolv-testing.com`
- TLS: Let's Encrypt (letsencrypt-production)
- Certificate: `docs-rsolv-testing-com-tls` (provisioning)

### Production Environment (rsolv-production namespace)

**ConfigMaps:**
- `docs-content` - HTML documentation content
- `docs-nginx-config` - Nginx server configuration

**Deployment:**
- Name: `docs-rsolv`
- Replicas: 2 (high availability)
- Image: `nginx:alpine`
- Status: ✅ Running (2/2 pods)

**Service:**
- Name: `docs-rsolv`
- Type: ClusterIP
- Port: 80

**Ingress:**
- Name: `docs-rsolv-ingress`
- Host: `docs.rsolv.dev`
- TLS: Let's Encrypt (letsencrypt-production)
- Certificate: `docs-rsolv-dev-tls` (will auto-provision after DNS)

## Documentation Content

The deployed documentation includes:

### 1. Installation Guide
- Step 1: Get API key at rsolv.dev/signup
- Step 2: Add API key to GitHub Secrets
- Step 3: Create workflow file
- Complete workflow YAML example

### 2. Troubleshooting
- Authentication errors (401, invalid API key)
- Pull request creation failures
- File path issues (relative vs absolute)
- Rate limit errors (500/hour)

### 3. API Reference
- Core inputs table (rsolvApiKey, mode, max_issues)
- Support links (email, GitHub, marketplace)

## Required Actions

### DNS Configuration

**For staging (docs.rsolv-testing.com):**
```
Type: A
Name: docs.rsolv-testing.com
Value: 10.5.200.0
```

**For production (docs.rsolv.dev):**
```
Type: A
Name: docs.rsolv.dev
Value: 10.5.200.0
```

### SSL Certificate Status

Once DNS is configured:
1. cert-manager will automatically detect the new domain
2. Let's Encrypt will issue SSL certificates via HTTP-01 challenge
3. Certificates will be stored in secrets:
   - Staging: `docs-rsolv-testing-com-tls`
   - Production: `docs-rsolv-dev-tls`

Current status:
- ⚠️ Certificates are waiting for DNS resolution
- Expected: Auto-provision within 5 minutes of DNS propagation

## Testing After DNS Propagation

### Staging Test
```bash
curl -I https://docs.rsolv-testing.com
# Should return: HTTP/2 200
```

### Production Test
```bash
curl -I https://docs.rsolv.dev
# Should return: HTTP/2 200
```

### Browser Test
Visit:
- https://docs.rsolv-testing.com
- https://docs.rsolv.dev

Expected: Clean documentation page with:
- 🛡️ RSOLV Documentation header
- Blue theme (#2563eb)
- Navigation: Installation, Troubleshooting, API Reference
- Working links and styling

## Rollback Plan

If issues occur:

```bash
# Delete staging resources
kubectl delete ingress docs-rsolv-ingress -n rsolv-staging
kubectl delete service docs-rsolv -n rsolv-staging
kubectl delete deployment docs-rsolv -n rsolv-staging
kubectl delete configmap docs-content docs-nginx-config -n rsolv-staging

# Delete production resources
kubectl delete ingress docs-rsolv-ingress -n rsolv-production
kubectl delete service docs-rsolv -n rsolv-production
kubectl delete deployment docs-rsolv -n rsolv-production
kubectl delete configmap docs-content docs-nginx-config -n rsolv-production
```

## Next Steps

1. ✅ **Immediate**: Configure DNS A records (manual step)
2. ⏳ **Wait**: 5-15 minutes for DNS propagation
3. ✅ **Verify**: SSL certificates auto-provision
4. ✅ **Test**: Both docs sites accessible via HTTPS
5. ✅ **Update RFC-067 Progress**: Mark docs.rsolv.dev blocker as resolved

## Technical Details

### Nginx Configuration

- Root: `/usr/share/nginx/html`
- Index: `index.html`
- Try files: `$uri $uri/ /index.html` (SPA-style routing)
- Security headers:
  - `X-Frame-Options: SAMEORIGIN`
  - `X-Content-Type-Options: nosniff`
  - `X-XSS-Protection: 1; mode=block`
- Static asset caching: 1 year

### Resource Labels

All resources tagged with:
- `app: docs-rsolv`
- `environment: staging|production`
- `managed-by: RSOLV-infrastructure`

### Load Balancer

Ingress assigned to: `10.5.200.0` (MetalLB)

## Maintenance

### Updating Documentation Content

To update the HTML content:

```bash
# Edit the ConfigMap
kubectl edit configmap docs-content -n rsolv-production

# Or apply a new version
kubectl apply -f docs-configmap.yaml -n rsolv-production

# Restart pods to pick up changes
kubectl rollout restart deployment docs-rsolv -n rsolv-production
```

### Monitoring

Check pod status:
```bash
kubectl get pods -n rsolv-production -l app=docs-rsolv
```

Check ingress status:
```bash
kubectl get ingress docs-rsolv-ingress -n rsolv-production
```

View logs:
```bash
kubectl logs -n rsolv-production -l app=docs-rsolv
```

## References

- RFC-067: `/home/dylan/dev/rsolv/RFCs/RFC-067-GITHUB-MARKETPLACE-PUBLISHING.md`
- RFC-067 Week 1 Progress: `RFC-067-WEEK-1-PROGRESS.md`
- Ingress Controller: nginx-ingress (already deployed)
- Certificate Manager: cert-manager with letsencrypt-production issuer

---

**Deployment completed**: 2025-10-23 00:50 UTC
**Deployed by**: Claude Code
**Status**: ✅ Pods running, ⚠️ DNS pending
