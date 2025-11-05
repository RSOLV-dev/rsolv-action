# Sealed Secrets Quick Start Guide

**Last Updated**: 2025-11-05
**Related RFC**: [RFC-080: Sealed Secrets for Production Secret Management](../RFCs/RFC-080-SEALED-SECRETS.md)

## What is Sealed Secrets?

Sealed Secrets solves the problem: "I can manage all my K8s config in git, except Secrets."

- Encrypt secrets that can be safely committed to git
- Only the cluster controller can decrypt them
- Prevents accidental secret deletion during `kubectl apply -k` operations

## Quick Commands

### For Developers

```bash
# Install kubeseal CLI (one-time)
brew install kubeseal  # macOS
# or download from: https://github.com/bitnami-labs/sealed-secrets/releases

# Fetch public certificate (one-time per environment)
kubectl config use-context production
kubeseal --fetch-cert > .sealed-secrets/production-cert.pem

# Create a new sealed secret
kubectl create secret generic my-secret \
  --from-literal=api-key="secret-value" \
  --namespace rsolv-production \
  --dry-run=client -o yaml | \
kubeseal --cert .sealed-secrets/production-cert.pem \
  --scope namespace-wide --format yaml \
  > services/unified/overlays/production/sealed-secrets.yaml

# Commit to git (safe!)
git add services/unified/overlays/production/sealed-secrets.yaml
git commit -m "Add new secret"
git push

# Apply to cluster
kubectl apply -k environments/production
```

### For Operators

```bash
# Install controller (one-time per cluster)
helm install sealed-secrets sealed-secrets/sealed-secrets \
  --namespace kube-system --create-namespace \
  --set fullnameOverride=sealed-secrets-controller

# Backup certificates (monthly)
kubectl get secret -n kube-system \
  -l sealedsecrets.bitnami.com/sealed-secrets-key \
  -o yaml > sealed-secrets-keys-backup-$(date +%Y%m%d).yaml

# Verify controller status
kubectl get pods -n kube-system -l app.kubernetes.io/name=sealed-secrets

# Check if sealed secret was unsealed
kubectl get sealedsecret rsolv-secrets -n rsolv-production
kubectl get secret rsolv-secrets -n rsolv-production
```

## Troubleshooting

### Secret not unsealing

```bash
# Check controller logs
kubectl logs -n kube-system -l app.kubernetes.io/name=sealed-secrets

# Verify sealed secret status
kubectl describe sealedsecret SECRETNAME -n NAMESPACE

# Common issue: Wrong namespace scope
# Sealed secrets are bound to namespace by default
# Use --scope namespace-wide for flexibility
```

### Certificate not found

```bash
# Re-fetch certificate
kubeseal --fetch-cert > cert.pem

# If controller not responding:
kubectl get pods -n kube-system -l app.kubernetes.io/name=sealed-secrets
kubectl logs -n kube-system -l app.kubernetes.io/name=sealed-secrets
```

### Need to update existing sealed secret

```bash
# Option 1: Merge update
kubectl create secret generic rsolv-secrets \
  --from-literal=new-key="new-value" \
  --namespace rsolv-production \
  --dry-run=client -o yaml | \
kubeseal --cert production-cert.pem \
  --merge-into sealed-secrets.yaml \
  --format yaml

# Option 2: Re-encrypt entire secret
# (See "Create a new sealed secret" above)
```

## Migration Checklist

When migrating from manual secrets to sealed-secrets:

- [ ] Install sealed-secrets controller
- [ ] Backup initial certificates to 1Password and S3
- [ ] Export existing secrets: `kubectl get secret NAME -o yaml`
- [ ] Remove metadata fields: `creationTimestamp`, `resourceVersion`, `uid`
- [ ] Seal the secret: `kubeseal --cert cert.pem < secret.yaml > sealed-secret.yaml`
- [ ] Deploy sealed secret: `kubectl apply -f sealed-secret.yaml`
- [ ] Verify unsealing: `kubectl get secret NAME`
- [ ] Compare data: `kubectl get secret NAME -o jsonpath='{.data}'`
- [ ] Update kustomization.yaml to reference sealed secret
- [ ] Test full deployment: `kubectl apply -k environments/ENV`
- [ ] Remove `post-deploy-secrets.sh` script
- [ ] Update documentation

## Security Notes

**Safe to Commit**:
- ✅ SealedSecret YAML files (encrypted)
- ✅ Public certificates (.pem files)

**NEVER Commit**:
- ❌ Plaintext Secret YAML files
- ❌ Private keys (.key files)
- ❌ Backup YAML files containing private keys

**Backup Locations**:
- 1Password vault: "RSOLV Infrastructure"
- S3 bucket: `s3://rsolv-backups/sealed-secrets/` (encrypted)
- Secure workstation: Air-gapped backup drive

## Resources

- **Full RFC**: [RFC-080-SEALED-SECRETS.md](../RFCs/RFC-080-SEALED-SECRETS.md)
- **Sealed Secrets Docs**: https://github.com/bitnami-labs/sealed-secrets
- **DEPLOYMENT.md**: [RSOLV-infrastructure/DEPLOYMENT.md](../RSOLV-infrastructure/DEPLOYMENT.md)

## Support

For issues or questions:
1. Check sealed-secrets controller logs
2. Review [RFC-080 Troubleshooting Section](../RFCs/RFC-080-SEALED-SECRETS.md#troubleshooting)
3. Consult #infrastructure Slack channel
4. File issue in RSOLV-infrastructure repo
