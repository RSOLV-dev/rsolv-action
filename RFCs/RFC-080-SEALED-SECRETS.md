# RFC-080: Sealed Secrets for Production Secret Management

**RFC Number**: 080
**Title**: Sealed Secrets for Production Secret Management
**Author**: Infrastructure Team
**Status**: Draft
**Created**: 2025-11-05
**Related Incidents**: INCIDENT-2025-11-05-SECRET-LOSS

## Summary

This RFC proposes implementing Bitnami Sealed Secrets to prevent accidental secret deletion during infrastructure deployments. Multiple production incidents have occurred where `kubectl apply -k` operations wiped manually-created secrets, causing service outages. Sealed Secrets enables GitOps-friendly secret management by encrypting secrets that can be safely committed to version control.

## Motivation

### Current Problems

1. **Secret Loss During Deployments**: `kubectl apply -k environments/production` overwrites manually-created secrets with empty values from base `secrets.yaml`, causing immediate service disruption
2. **Manual Secret Recovery**: Post-deployment secret restoration requires running manual scripts (`post-deploy-secrets.sh`) which is error-prone
3. **No Version Control**: Secrets exist only in the cluster; no audit trail or disaster recovery capability
4. **Knowledge Silos**: Secret values are scattered across wikis, 1Password, and tribal knowledge
5. **Deployment Anxiety**: Engineers fear infrastructure changes due to secret loss risk

### Recent Incidents

- **2025-11-05**: `kubectl apply -k` wiped production database credentials, requiring emergency manual restoration
- **Previous incidents**: Multiple occurrences documented in DEPLOYMENT.md warning sections

### Desired State

- Secrets versioned alongside infrastructure code
- Encrypted secrets safe for git commits and public repositories
- Automated deployment workflow without manual secret patching
- Disaster recovery capability with backed-up encryption keys
- Clear audit trail of secret changes

## Proposed Solution

### Architecture Overview

Deploy Bitnami Sealed Secrets with the following components:

```
┌─────────────────────────────────────────────────────────────┐
│                      Git Repository                         │
│  ┌────────────────────────────────────────────────────┐    │
│  │  RSOLV-infrastructure/                              │    │
│  │  └── services/unified/overlays/                     │    │
│  │      ├── production/                                │    │
│  │      │   ├── kustomization.yaml                     │    │
│  │      │   └── sealed-secrets.yaml (encrypted)        │    │
│  │      └── staging/                                   │    │
│  │          ├── kustomization.yaml                     │    │
│  │          └── sealed-secrets.yaml (encrypted)        │    │
│  └────────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────────┘
                              │
                              │ kubectl apply -k
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                    Kubernetes Cluster                       │
│                                                             │
│  ┌──────────────────────────────────────────────────┐     │
│  │  Sealed Secrets Controller (kube-system ns)       │     │
│  │  - Monitors SealedSecret resources                │     │
│  │  - Decrypts using private key                     │     │
│  │  - Creates Secret resources                       │     │
│  └──────────────────────────────────────────────────┘     │
│                              │                              │
│                              ▼                              │
│  ┌──────────────────────────────────────────────────┐     │
│  │  Application Namespaces                           │     │
│  │  rsolv-production:                                │     │
│  │    - SealedSecret: rsolv-secrets (committed)      │     │
│  │    - Secret: rsolv-secrets (auto-generated)       │     │
│  │  rsolv-staging:                                   │     │
│  │    - SealedSecret: rsolv-secrets (committed)      │     │
│  │    - Secret: rsolv-secrets (auto-generated)       │     │
│  └──────────────────────────────────────────────────┘     │
└─────────────────────────────────────────────────────────────┘
```

### Installation Method: Helm

**Rationale**: Helm provides versioned releases, easy upgrades, and consistent configuration management compared to raw manifests.

```bash
# Add Bitnami Sealed Secrets repo
helm repo add sealed-secrets https://bitnami-labs.github.io/sealed-secrets
helm repo update

# Install controller to kube-system namespace
helm install sealed-secrets sealed-secrets/sealed-secrets \
  --namespace kube-system \
  --create-namespace \
  --set fullnameOverride=sealed-secrets-controller \
  --set commandArgs[0]=--update-status
```

**Key Configuration**:
- Namespace: `kube-system` (cluster-wide visibility)
- Controller name: `sealed-secrets-controller` (standard naming)
- Update status: Enabled for monitoring sealed secret health
- Auto-renewal: Default 30-day certificate rotation enabled

### Namespace Scoping Strategy

**Decision**: Use **namespace-wide** scoping for all secrets.

**Rationale**:

| Scope Level | Pros | Cons | Use Case |
|------------|------|------|----------|
| **Strict** | Maximum security | Can't rename secrets | High-security environments |
| **Namespace-wide** ✅ | Flexibility within namespace, good security boundary | Can't move between namespaces | Standard deployments (RSOLV) |
| **Cluster-wide** | Maximum flexibility | Weakest security boundary | Development/testing only |

**Implementation**:
```yaml
apiVersion: bitnami.com/v1alpha1
kind: SealedSecret
metadata:
  name: rsolv-secrets
  namespace: rsolv-production
  annotations:
    sealedsecrets.bitnami.com/namespace-wide: "true"
spec:
  encryptedData:
    database-url: AgBy3i4OJSWK+PiTySYZZA9rO...
```

This allows renaming secrets within the same namespace while preventing cross-namespace secret reuse (critical security boundary for production vs staging).

### Certificate Management

#### Initial Certificate Generation

**Option 1: Auto-generated (Recommended for MVP)**
- Controller generates certificates on first startup
- Certificates stored in `kube-system` namespace as secrets
- 30-day auto-renewal by default

**Option 2: Bring-Your-Own-Certificate (Future Enhancement)**
```bash
# Generate custom certificate with longer expiry
openssl req -x509 -days 3650 -nodes -newkey rsa:4096 \
  -keyout tls.key -out tls.crt \
  -subj "/CN=sealed-secret/O=rsolv"

# Create labeled secret
kubectl create secret tls sealed-secrets-custom \
  --cert=tls.crt --key=tls.key \
  --namespace kube-system

kubectl label secret sealed-secrets-custom \
  sealedsecrets.bitnami.com/sealed-secrets-key=active \
  --namespace kube-system

# Restart controller to load
kubectl delete pod -n kube-system -l app.kubernetes.io/name=sealed-secrets
```

#### Certificate Backup Procedures

**CRITICAL**: Backup encryption keys immediately after installation and after any rotation.

```bash
# Backup all sealing keys
kubectl get secret -n kube-system \
  -l sealedsecrets.bitnami.com/sealed-secrets-key \
  -o yaml > sealed-secrets-keys-backup-$(date +%Y%m%d).yaml

# Store in secure location
# - 1Password vault: "RSOLV Infrastructure"
# - Encrypted S3 bucket: s3://rsolv-backups/sealed-secrets/
# - Air-gapped backup drive

# Test backup integrity
kubectl get secret -n kube-system -l sealedsecrets.bitnami.com/sealed-secrets-key -o yaml | \
  grep -E '(name:|sealedsecrets.bitnami.com/sealed-secrets-key:)'
```

**Backup Schedule**:
- Immediately after installation
- Monthly (first day of month)
- Before any certificate rotation
- After any disaster recovery exercise

#### Certificate Rotation Strategy

**Default Behavior**: Controller auto-generates new certificates every 30 days and keeps old ones for decryption.

**Rotation Policy**:
1. **Automatic rotation**: Keep default 30-day rotation enabled
2. **Key retention**: Controller keeps old keys indefinitely for backward compatibility
3. **Manual rotation**: Only needed for security incidents

**Manual Rotation Process** (emergency only):
```bash
# 1. Generate new certificate
openssl req -x509 -days 365 -nodes -newkey rsa:4096 \
  -keyout tls.key -out tls.crt \
  -subj "/CN=sealed-secret/O=rsolv"

# 2. Create secret with active label
kubectl create secret tls sealed-secrets-key-$(date +%Y%m%d) \
  --cert=tls.crt --key=tls.key \
  --namespace kube-system

kubectl label secret sealed-secrets-key-$(date +%Y%m%d) \
  sealedsecrets.bitnami.com/sealed-secrets-key=active \
  --namespace kube-system

# 3. Backup immediately
kubectl get secret sealed-secrets-key-$(date +%Y%m%d) -n kube-system -o yaml > \
  sealed-secrets-emergency-key-$(date +%Y%m%d).yaml

# 4. Restart controller
kubectl delete pod -n kube-system -l app.kubernetes.io/name=sealed-secrets

# 5. Re-seal all secrets with new certificate
kubeseal --fetch-cert > new-cert.pem
# Re-encrypt each secret (see migration section)
```

#### Disaster Recovery Procedures

**Scenario 1: Controller Pod Deleted**
```bash
# No action needed - controller recreates automatically
# Sealed secrets remain intact
kubectl get sealedsecret -A
```

**Scenario 2: Certificate Secret Deleted**
```bash
# Restore from backup
kubectl apply -f sealed-secrets-keys-backup-YYYYMMDD.yaml

# Verify restoration
kubectl get secret -n kube-system -l sealedsecrets.bitnami.com/sealed-secrets-key

# Restart controller
kubectl delete pod -n kube-system -l app.kubernetes.io/name=sealed-secrets
```

**Scenario 3: Complete Cluster Loss**
```bash
# 1. Restore cluster from backup/rebuild
# 2. Reinstall sealed-secrets controller
helm install sealed-secrets sealed-secrets/sealed-secrets --namespace kube-system

# 3. Restore certificate secrets BEFORE deploying applications
kubectl apply -f sealed-secrets-keys-backup-YYYYMMDD.yaml

# 4. Restart controller to load old keys
kubectl delete pod -n kube-system -l app.kubernetes.io/name=sealed-secrets

# 5. Deploy applications (sealed secrets will decrypt with old keys)
kubectl apply -k environments/production
```

**Scenario 4: Offline Decryption** (for audit/debug)
```bash
# Extract private key from backup
kubectl get secret -n kube-system sealed-secrets-key-YYYYMMDD \
  -o jsonpath='{.data.tls\.key}' | base64 -d > private-key.pem

# Decrypt sealed secret offline
kubeseal --recovery-unseal --recovery-private-key private-key.pem \
  < sealed-secret.yaml

# SECURITY: Delete private-key.pem immediately after use
shred -u private-key.pem
```

### Integration with Kustomize Overlays

**Current Structure** (with manual secrets):
```
services/unified/
├── base/
│   ├── deployment.yaml
│   ├── service.yaml
│   └── secrets.yaml (empty placeholders)
└── overlays/
    ├── production/
    │   ├── kustomization.yaml
    │   ├── secrets-patch.yaml (empty placeholders)
    │   └── post-deploy-secrets.sh (manual patching)
    └── staging/
        ├── kustomization.yaml
        └── secrets-patch.yaml (empty placeholders)
```

**Proposed Structure** (with sealed-secrets):
```
services/unified/
├── base/
│   ├── deployment.yaml
│   ├── service.yaml
│   └── secrets.yaml (REMOVED - no longer needed)
└── overlays/
    ├── production/
    │   ├── kustomization.yaml (updated)
    │   ├── sealed-secrets.yaml (committed to git ✅)
    │   └── post-deploy-secrets.sh (REMOVED)
    └── staging/
        ├── kustomization.yaml (updated)
        └── sealed-secrets.yaml (committed to git ✅)
```

**Updated Kustomization Files**:
```yaml
# overlays/production/kustomization.yaml
apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization

namespace: rsolv-production

resources:
  - ../../base
  - sealed-secrets.yaml  # Add sealed secrets

patches:
  # Remove secrets-patch.yaml reference

images:
  - name: ghcr.io/rsolv-dev/rsolv-platform
    newTag: production-20251105
```

**Benefits**:
- ✅ No more empty placeholder secrets in base
- ✅ No more post-deployment manual patching
- ✅ Secrets version-controlled alongside infrastructure
- ✅ Consistent deployment workflow
- ✅ Eliminates human error in secret management

### Local Development Workflow

**Developer Setup** (one-time):
```bash
# 1. Install kubeseal CLI
brew install kubeseal  # macOS
# or
wget https://github.com/bitnami-labs/sealed-secrets/releases/download/v0.24.0/kubeseal-0.24.0-linux-amd64.tar.gz
tar -xvzf kubeseal-0.24.0-linux-amd64.tar.gz
sudo mv kubeseal /usr/local/bin/

# 2. Fetch public certificate (one-time, store in repo)
kubectl config use-context production  # or staging
kubeseal --fetch-cert > .sealed-secrets/production-cert.pem

# 3. Add to gitignore (private keys only, not public certs)
echo ".sealed-secrets/*.key" >> .gitignore
```

**Creating New Sealed Secrets**:
```bash
# 1. Create secret YAML (not applied to cluster)
cat > temp-secret.yaml <<EOF
apiVersion: v1
kind: Secret
metadata:
  name: rsolv-secrets
  namespace: rsolv-production
type: Opaque
stringData:
  database-url: "postgresql://user:pass@postgres-nfs.default.svc.cluster.local:5432/rsolv_prod"
  secret-key-base: "$(openssl rand -hex 32)"
  anthropic-api-key: "sk-ant-xxxxx"
EOF

# 2. Seal the secret using offline certificate
kubeseal --cert .sealed-secrets/production-cert.pem \
  --scope namespace-wide \
  --format yaml \
  < temp-secret.yaml \
  > services/unified/overlays/production/sealed-secrets.yaml

# 3. Clean up plaintext secret
shred -u temp-secret.yaml

# 4. Commit sealed secret to git
git add services/unified/overlays/production/sealed-secrets.yaml
git commit -m "Update production secrets"
git push
```

**Updating Existing Sealed Secrets**:
```bash
# Option 1: Merge update into existing sealed secret
kubectl create secret generic rsolv-secrets \
  --namespace rsolv-production \
  --from-literal=new-api-key="value" \
  --dry-run=client -o yaml | \
kubeseal --cert .sealed-secrets/production-cert.pem \
  --merge-into services/unified/overlays/production/sealed-secrets.yaml \
  --format yaml

# Option 2: Replace entire sealed secret (full re-encryption)
# (Use method from "Creating New Sealed Secrets" above)

git add services/unified/overlays/production/sealed-secrets.yaml
git commit -m "Add new-api-key to production secrets"
```

**Local Testing** (development cluster):
```bash
# Developers use local k3d/minikube cluster
k3d cluster create test

# Install sealed-secrets controller
helm install sealed-secrets sealed-secrets/sealed-secrets \
  --namespace kube-system --create-namespace

# Fetch local cert
kubeseal --fetch-cert > .sealed-secrets/local-cert.pem

# Create and seal test secrets
kubectl create secret generic test-secret \
  --from-literal=api-key="test-value" \
  --dry-run=client -o yaml | \
kubeseal --cert .sealed-secrets/local-cert.pem \
  --scope namespace-wide --format yaml | \
kubectl apply -f -

# Verify unsealing
kubectl get secret test-secret -o yaml
```

### CI/CD Integration

**Automation Principles**:
- Sealed secrets created by developers, committed to git
- CI/CD applies sealed secrets like any other Kubernetes resource
- No plaintext secrets in CI/CD pipelines
- Certificate rotation doesn't break existing sealed secrets

**GitHub Actions Workflow** (example):
```yaml
name: Deploy Infrastructure

on:
  push:
    branches: [main]
    paths:
      - 'services/**'
      - 'environments/**'

jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Configure kubectl
        uses: azure/k8s-set-context@v3
        with:
          kubeconfig: ${{ secrets.KUBECONFIG }}

      - name: Deploy to production
        run: |
          # No special handling needed - sealed secrets work like regular resources
          kubectl apply -k environments/production

      - name: Wait for rollout
        run: |
          kubectl rollout status deployment/rsolv-platform -n rsolv-production --timeout=5m

      - name: Verify health
        run: |
          kubectl wait --for=condition=ready pod -l app=rsolv-platform \
            -n rsolv-production --timeout=2m
```

**Secret Update Workflow**:
```yaml
name: Update Sealed Secret

# Manual workflow_dispatch for secret updates
on:
  workflow_dispatch:
    inputs:
      environment:
        description: 'Environment (staging/production)'
        required: true
        default: 'staging'

jobs:
  update-secret:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Install kubeseal
        run: |
          wget https://github.com/bitnami-labs/sealed-secrets/releases/download/v0.24.0/kubeseal-0.24.0-linux-amd64.tar.gz
          tar -xvzf kubeseal-0.24.0-linux-amd64.tar.gz
          sudo mv kubeseal /usr/local/bin/

      - name: Configure kubectl
        uses: azure/k8s-set-context@v3
        with:
          kubeconfig: ${{ secrets.KUBECONFIG }}

      - name: Fetch current certificate
        run: |
          kubeseal --fetch-cert > cert.pem

      - name: Seal secrets from 1Password
        env:
          OP_SERVICE_ACCOUNT_TOKEN: ${{ secrets.OP_SERVICE_ACCOUNT_TOKEN }}
        run: |
          # Fetch secrets from 1Password
          DATABASE_URL=$(op read "op://Infrastructure/Database/${{ inputs.environment }}/url")
          API_KEY=$(op read "op://Infrastructure/API Keys/${{ inputs.environment }}/key")

          # Create and seal secret
          kubectl create secret generic rsolv-secrets \
            --namespace rsolv-${{ inputs.environment }} \
            --from-literal=database-url="$DATABASE_URL" \
            --from-literal=anthropic-api-key="$API_KEY" \
            --dry-run=client -o yaml | \
          kubeseal --cert cert.pem --scope namespace-wide --format yaml \
            > services/unified/overlays/${{ inputs.environment }}/sealed-secrets.yaml

      - name: Commit and push
        run: |
          git config user.name "github-actions[bot]"
          git config user.email "github-actions[bot]@users.noreply.github.com"
          git add services/unified/overlays/${{ inputs.environment }}/sealed-secrets.yaml
          git commit -m "Update ${{ inputs.environment }} sealed secrets"
          git push
```

**Certificate Rotation in CI/CD**:
```yaml
name: Backup Sealed Secrets Keys

on:
  schedule:
    - cron: '0 0 1 * *'  # Monthly backup on 1st of month
  workflow_dispatch:

jobs:
  backup:
    runs-on: ubuntu-latest
    steps:
      - name: Configure kubectl
        uses: azure/k8s-set-context@v3
        with:
          kubeconfig: ${{ secrets.KUBECONFIG }}

      - name: Backup sealing keys
        run: |
          kubectl get secret -n kube-system \
            -l sealedsecrets.bitnami.com/sealed-secrets-key \
            -o yaml > sealed-secrets-keys-$(date +%Y%m%d).yaml

      - name: Encrypt and upload to S3
        env:
          AWS_ACCESS_KEY_ID: ${{ secrets.AWS_ACCESS_KEY_ID }}
          AWS_SECRET_ACCESS_KEY: ${{ secrets.AWS_SECRET_ACCESS_KEY }}
        run: |
          # Encrypt with GPG before upload
          gpg --symmetric --cipher-algo AES256 \
            --passphrase "${{ secrets.BACKUP_ENCRYPTION_KEY }}" \
            sealed-secrets-keys-$(date +%Y%m%d).yaml

          aws s3 cp sealed-secrets-keys-$(date +%Y%m%d).yaml.gpg \
            s3://rsolv-backups/sealed-secrets/

          # Clean up local files
          shred -u sealed-secrets-keys-$(date +%Y%m%d).yaml*

      - name: Verify backup
        run: |
          aws s3 ls s3://rsolv-backups/sealed-secrets/ --recursive | tail -5
```

## Implementation Plan

### Phase 1: Controller Installation (Week 1)

**Staging Environment**:
```bash
# 1. Install controller to staging cluster
helm install sealed-secrets sealed-secrets/sealed-secrets \
  --namespace kube-system --create-namespace \
  --set fullnameOverride=sealed-secrets-controller

# 2. Backup initial certificates
kubectl get secret -n kube-system \
  -l sealedsecrets.bitnami.com/sealed-secrets-key \
  -o yaml > backups/sealed-secrets-staging-initial-$(date +%Y%m%d).yaml

# 3. Fetch public certificate
kubeseal --fetch-cert > .sealed-secrets/staging-cert.pem

# 4. Store backup in 1Password
```

**Tasks**:
- [ ] Install sealed-secrets controller to staging
- [ ] Verify controller pod running
- [ ] Backup initial certificates to 1Password and S3
- [ ] Fetch and commit public certificate to git
- [ ] Test basic secret sealing and unsealing

**Success Criteria**:
- Controller pod status: Running
- Can seal and unseal test secret
- Backup verified and stored securely

### Phase 2: Migration Strategy (Week 2)

**Approach**: Parallel deployment (sealed secrets + manual secrets) to ensure zero downtime.

**Steps**:
```bash
# 1. Create sealed versions of existing secrets
kubectl get secret rsolv-secrets -n rsolv-staging -o yaml > temp-secret.yaml

# Remove metadata and status fields
yq eval 'del(.metadata.creationTimestamp, .metadata.resourceVersion, .metadata.uid, .status)' \
  temp-secret.yaml > clean-secret.yaml

# Seal the secret
kubeseal --cert .sealed-secrets/staging-cert.pem \
  --scope namespace-wide --format yaml \
  < clean-secret.yaml \
  > services/unified/overlays/staging/sealed-secrets.yaml

# 2. Deploy sealed secret (manual secret still exists)
kubectl apply -f services/unified/overlays/staging/sealed-secrets.yaml

# 3. Verify both secrets have identical data
diff <(kubectl get secret rsolv-secrets -n rsolv-staging -o jsonpath='{.data}' | jq -S) \
     <(kubectl get secret rsolv-secrets -n rsolv-staging -o jsonpath='{.data}' | jq -S)

# 4. Update kustomization.yaml to use sealed secret
# 5. Apply full kustomization
kubectl apply -k environments/staging

# 6. Verify application still healthy
kubectl rollout status deployment/rsolv-platform -n rsolv-staging
curl https://rsolv-staging.com/health
```

**Tasks**:
- [ ] Export existing staging secrets
- [ ] Create sealed versions of all secrets
- [ ] Deploy sealed secrets alongside manual secrets
- [ ] Verify data parity
- [ ] Update kustomization.yaml
- [ ] Remove manual secret creation from runbooks
- [ ] Delete `post-deploy-secrets.sh` script

**Success Criteria**:
- Sealed secrets unsealed correctly
- Application health unchanged
- No manual secret patching required
- Clean kustomization deployment

### Phase 3: Production Deployment (Week 3)

**Pre-deployment Checklist**:
- [ ] Staging sealed-secrets running for 1+ week without issues
- [ ] All team members trained on sealed-secrets workflow
- [ ] Backup procedures tested and verified
- [ ] Disaster recovery procedure documented and tested
- [ ] Change window scheduled (low-traffic period)

**Production Deployment**:
```bash
# 1. Install controller to production
kubectl config use-context production
helm install sealed-secrets sealed-secrets/sealed-secrets \
  --namespace kube-system --create-namespace \
  --set fullnameOverride=sealed-secrets-controller

# 2. IMMEDIATELY backup certificates
kubectl get secret -n kube-system \
  -l sealedsecrets.bitnami.com/sealed-secrets-key \
  -o yaml > backups/sealed-secrets-production-initial-$(date +%Y%m%d).yaml

# Upload to 1Password and S3 (encrypted)

# 3. Fetch public certificate
kubeseal --fetch-cert > .sealed-secrets/production-cert.pem

# 4. Create sealed secrets (DO NOT APPLY YET)
kubectl get secret rsolv-secrets -n rsolv-production -o yaml > temp-secret.yaml
yq eval 'del(.metadata.creationTimestamp, .metadata.resourceVersion, .metadata.uid, .status)' \
  temp-secret.yaml > clean-secret.yaml
kubeseal --cert .sealed-secrets/production-cert.pem \
  --scope namespace-wide --format yaml \
  < clean-secret.yaml \
  > services/unified/overlays/production/sealed-secrets.yaml
shred -u temp-secret.yaml clean-secret.yaml

# 5. Deploy sealed secret (manual secret still exists as backup)
kubectl apply -f services/unified/overlays/production/sealed-secrets.yaml

# 6. Verify sealed secret unsealed correctly
kubectl wait --for=jsonpath='{.status.conditions[0].status}'=True \
  sealedsecret/rsolv-secrets -n rsolv-production --timeout=60s

# 7. Compare data with manual secret
kubectl get secret rsolv-secrets -n rsolv-production -o json | \
  jq '.data | to_entries | map({key, value: (.value | @base64d)}) | from_entries' \
  > manual-secret-data.json

kubectl get secret rsolv-secrets -n rsolv-production -o json | \
  jq '.data | to_entries | map({key, value: (.value | @base64d)}) | from_entries' \
  > sealed-secret-data.json

diff manual-secret-data.json sealed-secret-data.json
# Should be identical

# 8. Update kustomization.yaml (in git)
# 9. Apply full kustomization
kubectl apply -k environments/production

# 10. Monitor deployment
kubectl rollout status deployment/rsolv-platform -n rsolv-production
kubectl wait --for=condition=ready pod -l app=rsolv-platform \
  -n rsolv-production --timeout=5m

# 11. Verify health endpoints
curl -f https://api.rsolv.dev/health
curl -f https://rsolv.dev/health

# 12. Monitor for 1 hour before declaring success
```

**Rollback Plan**:
```bash
# If sealed secrets fail:
# 1. Revert kustomization.yaml to previous version
git revert HEAD
kubectl apply -k environments/production

# 2. Run post-deploy-secrets.sh to restore manual secrets
cd services/unified/overlays/production
./post-deploy-secrets.sh

# 3. Restart deployment
kubectl rollout restart deployment/rsolv-platform -n rsolv-production

# 4. Investigate sealed-secrets controller logs
kubectl logs -n kube-system -l app.kubernetes.io/name=sealed-secrets
```

**Tasks**:
- [ ] Schedule change window with team
- [ ] Install sealed-secrets controller to production
- [ ] Backup certificates immediately
- [ ] Create sealed versions of production secrets
- [ ] Deploy sealed secrets (parallel with manual)
- [ ] Verify data parity
- [ ] Update kustomization.yaml
- [ ] Apply full kustomization
- [ ] Monitor for 1 hour
- [ ] Update deployment documentation

**Success Criteria**:
- Zero downtime during deployment
- All health endpoints green
- No manual secret patching required
- Clean rollout without errors
- Monitoring shows normal behavior

### Phase 4: Documentation & Training (Week 4)

**Documentation Updates**:
- [ ] Update DEPLOYMENT.md with sealed-secrets workflow
- [ ] Remove `post-deploy-secrets.sh` references
- [ ] Add sealed-secrets troubleshooting section
- [ ] Document disaster recovery procedures
- [ ] Create quick reference guide for developers

**Training Materials**:
- [ ] Create "Sealed Secrets 101" guide for team
- [ ] Record demo video of common workflows
- [ ] Add examples to CLAUDE.md project guidelines
- [ ] Update onboarding documentation

**Runbook Updates**:
- [ ] Remove manual secret creation steps
- [ ] Add sealed secret creation workflow
- [ ] Document certificate backup procedures
- [ ] Add disaster recovery playbook

### Phase 5: Ongoing Operations

**Monthly Tasks**:
- [ ] Backup sealed-secrets certificates (automated via GitHub Actions)
- [ ] Verify backups are accessible and encrypted
- [ ] Review audit logs for secret changes
- [ ] Test disaster recovery procedure (quarterly)

**Certificate Management**:
- [ ] Monitor certificate expiration (controller auto-renews)
- [ ] Verify old certificates retained for backward compatibility
- [ ] Document manual rotation procedures (emergency only)

**Security Practices**:
- [ ] Rotate secrets in case of suspected compromise
- [ ] Audit sealed secret access permissions
- [ ] Review kube-system namespace RBAC
- [ ] Keep kubeseal CLI updated

## Alternatives Considered

### Alternative 1: External Secrets Operator (ESO)

**Pros**:
- Integrates with external secret stores (AWS Secrets Manager, HashiCorp Vault, 1Password)
- Centralized secret management across multiple clusters
- Automatic secret rotation from external source

**Cons**:
- Requires external secret store infrastructure (additional cost/complexity)
- Network dependency on external service (availability risk)
- More complex setup and operational overhead
- Secrets still not in git (different problem)

**Decision**: Rejected. ESO solves a different problem (centralized secret management). We need GitOps-friendly version control, not external secret store integration.

### Alternative 2: SOPS (Secrets OPerationS)

**Pros**:
- Encrypts YAML files in place (cleaner diffs)
- Supports multiple cloud KMS providers (AWS KMS, GCP KMS, Azure Key Vault)
- Can encrypt non-Kubernetes secrets (flexible)

**Cons**:
- Requires cloud KMS provider (vendor lock-in)
- Additional cost for KMS operations
- Developers need cloud credentials/access
- Manual decrypt step in CI/CD pipeline
- Not Kubernetes-native (requires SOPS CLI everywhere)

**Decision**: Rejected. SOPS requires cloud KMS provider dependency and is not Kubernetes-native. Sealed Secrets is self-contained within the cluster.

### Alternative 3: Helm Secrets Plugin

**Pros**:
- Integrates with Helm workflow
- Uses SOPS under the hood
- Encrypts `values.yaml` files

**Cons**:
- Only works with Helm deployments (we use Kustomize)
- Still requires cloud KMS (SOPS dependency)
- Doesn't solve raw Kubernetes Secret encryption

**Decision**: Rejected. We use Kustomize, not Helm, for application deployments. Helm is only used for third-party charts like sealed-secrets controller itself.

### Alternative 4: Git-Crypt

**Pros**:
- Transparent encryption in git (simple developer experience)
- No additional infrastructure needed
- Automatic encrypt/decrypt on git operations

**Cons**:
- Not Kubernetes-aware (can't scope by namespace)
- Every team member needs GPG key access
- Key distribution problem (how do CI/CD workers get keys?)
- Encrypts entire files (poor diffs, merge conflicts)
- No audit trail of who decrypted what

**Decision**: Rejected. Git-crypt is too coarse-grained and has key distribution challenges. Not designed for Kubernetes secrets.

### Alternative 5: Keep Current Manual Process

**Pros**:
- No changes needed (zero migration risk)
- Familiar to team

**Cons**:
- Frequent secret loss incidents (multiple production outages)
- Manual post-deployment patching (human error prone)
- No version control or audit trail
- Deployment anxiety (fear of breaking things)
- Doesn't scale with team growth

**Decision**: Rejected. Current process is causing production incidents. Sealed Secrets directly addresses this problem.

## Security Considerations

### Threat Model

**Threats Mitigated**:
1. ✅ **Secret Loss**: Encrypted secrets in git prevent accidental deletion during deployments
2. ✅ **Version Control Exposure**: Encrypted secrets safe for public repositories
3. ✅ **Audit Trail**: Git history shows when secrets changed and by whom
4. ✅ **Disaster Recovery**: Backed-up certificates enable cluster rebuild

**Threats NOT Mitigated**:
1. ⚠️ **Compromised Cluster**: Attacker with cluster access can read unsealed Secrets (same as current)
2. ⚠️ **Certificate Compromise**: Attacker with sealing key can decrypt all sealed secrets
3. ⚠️ **Insider Threat**: Team members with kubectl access can read unsealed secrets (same as current)

### Security Best Practices

**Certificate Protection**:
- Private keys stored only in `kube-system` namespace secrets
- Backup certificates encrypted at rest (GPG/S3 server-side encryption)
- Limit access to kube-system namespace (RBAC)
- Public certificates can be committed to git (safe)

**Access Control**:
```yaml
# Limit sealed-secrets controller access
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: sealed-secrets-key-admin
  namespace: kube-system
rules:
- apiGroups: [""]
  resources: ["secrets"]
  resourceNames: ["sealed-secrets-key*"]
  verbs: ["get", "list"]
---
# Only infra team can access sealing keys
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: sealed-secrets-key-admin
  namespace: kube-system
subjects:
- kind: Group
  name: infra-admins
  apiGroup: rbac.authorization.k8s.io
roleRef:
  kind: Role
  name: sealed-secrets-key-admin
  apiGroup: rbac.authorization.k8s.io
```

**Audit Logging**:
```bash
# Enable Kubernetes audit logging for sealed-secrets operations
# (Add to cluster audit policy)
apiVersion: audit.k8s.io/v1
kind: Policy
rules:
- level: RequestResponse
  verbs: ["create", "update", "patch", "delete"]
  resources:
  - group: "bitnami.com"
    resources: ["sealedsecrets"]
```

**Secret Rotation**:
- Rotate secrets in response to security incidents
- Re-seal all secrets after certificate rotation
- Test unsealing after rotation to verify backward compatibility

## Open Questions

### Q1: How do we handle secret rotation without downtime?

**Answer**:
1. Create new sealed secret with updated values
2. Apply sealed secret (controller updates unsealed Secret)
3. Kubernetes mounts updated Secret to pods automatically
4. For pods requiring restart: use `kubectl rollout restart deployment/NAME`

**No downtime**: Rolling updates ensure availability during secret changes.

### Q2: What happens if controller is down during deployment?

**Answer**:
- SealedSecret resources are created but not unsealed
- Application pods fail to start if they depend on the Secret
- Controller processes backlog when it comes back online
- **Mitigation**: Monitor controller health, use PodDisruptionBudget for high availability

### Q3: How do we manage secrets across multiple clusters (DR cluster)?

**Answer**:
- **Option 1**: Use same sealing keys across clusters (sync kube-system secrets)
- **Option 2**: Separate keys per cluster, seal separately per environment
- **Recommendation**: Separate keys per cluster for security isolation

### Q4: Can we use sealed-secrets with external secret stores (1Password)?

**Answer**:
Yes, hybrid approach:
1. Store plaintext secrets in 1Password (source of truth)
2. CI/CD fetches from 1Password and seals into SealedSecret
3. Commit sealed secret to git
4. Best of both worlds: centralized management + GitOps

**Workflow**:
```bash
# CI/CD job
op read "op://Infrastructure/Database/production/url" | \
kubectl create secret generic db-secret --from-literal=url=/dev/stdin --dry-run=client -o yaml | \
kubeseal --cert production-cert.pem --format yaml > sealed-secret.yaml

git commit -m "Update database URL from 1Password"
```

### Q5: How do we handle emergency secret updates?

**Answer**:
1. Update plaintext secret in 1Password (if using hybrid approach)
2. CI/CD pipeline re-seals and commits to git
3. Apply sealed secret to cluster: `kubectl apply -f sealed-secrets.yaml`
4. Restart pods if needed: `kubectl rollout restart deployment/NAME`

**Time to apply**: ~30 seconds from commit to pod restart.

## References

- [Bitnami Sealed Secrets GitHub](https://github.com/bitnami-labs/sealed-secrets)
- [Sealed Secrets Helm Chart](https://github.com/bitnami-labs/sealed-secrets/tree/main/helm/sealed-secrets)
- [Bring Your Own Certificates](https://github.com/bitnami-labs/sealed-secrets/blob/main/docs/bring-your-own-certificates.md)
- [RSOLV DEPLOYMENT.md](../RSOLV-infrastructure/DEPLOYMENT.md) - Current secret management challenges
- [Incident: 2025-11-05 Secret Loss](../INCIDENT-2025-11-05-SECRET-LOSS.md) - Motivation for this RFC

## Success Metrics

**Operational Metrics**:
- Zero secret-related production incidents in 90 days post-deployment
- 100% of secrets managed via sealed-secrets (no manual patching)
- Certificate backups automated and verified monthly
- Disaster recovery procedure tested quarterly

**Developer Experience**:
- Deployment time reduced by eliminating manual secret patching (~5-10 minutes saved per deployment)
- Secret changes tracked in git with full audit trail
- Team confidence in infrastructure deployments increased (measured via survey)

**Security Metrics**:
- All secrets encrypted at rest in git (0 plaintext secrets committed)
- Certificate access limited to infra team (RBAC enforced)
- Secret rotation time reduced from hours to minutes
- Audit trail available for all secret changes (git history)

## Timeline

- **Week 1** (Nov 5-11): Phase 1 - Install controller to staging, backup certificates
- **Week 2** (Nov 12-18): Phase 2 - Migrate staging secrets, test workflows
- **Week 3** (Nov 19-25): Phase 3 - Production deployment during change window
- **Week 4** (Nov 26-Dec 2): Phase 4 - Documentation, training, runbook updates
- **Ongoing**: Monthly certificate backups, quarterly DR tests

**Total Duration**: 4 weeks to full production deployment.

## Conclusion

Sealed Secrets provides a robust, Kubernetes-native solution to our secret management challenges. By encrypting secrets that can be safely committed to version control, we eliminate the root cause of our secret loss incidents while maintaining security and enabling GitOps workflows.

The implementation plan ensures zero-downtime migration with clear rollback procedures. Certificate backup and disaster recovery procedures provide peace of mind for production operations.

**Recommendation**: Approve and proceed with Phase 1 implementation.
