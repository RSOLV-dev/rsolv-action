# RSOLV API Deployment Guide

## Prerequisites

1. Access to the Kubernetes cluster
2. Docker registry access (GitHub Container Registry)
3. Database (PostgreSQL) provisioned
4. API keys for AI providers

## Deployment Steps

### 1. Set up secrets

Copy the secrets template and fill in real values:

```bash
cp k8s/secrets-template.yaml k8s/secrets.yaml
# Edit k8s/secrets.yaml with real values
```

Required secrets:
- `database-url`: PostgreSQL connection string
- `secret-key-base`: Generate with `mix phx.gen.secret`
- `anthropic-api-key`: Your Anthropic API key
- `openai-api-key`: Your OpenAI API key
- `openrouter-api-key`: Your OpenRouter API key
- `sendgrid-api-key`: For email notifications
- `sentry-dsn`: For error tracking (optional)

### 2. Apply secrets to cluster

```bash
kubectl apply -f k8s/secrets.yaml
```

### 3. Deploy the API

```bash
./deploy.sh
```

This will:
1. Build the Docker image
2. Push to GitHub Container Registry
3. Deploy to Kubernetes
4. Set up the ingress for api.rsolv.ai

### 4. Verify deployment

```bash
# Check pods
kubectl get pods -l app=rsolv-api

# Check logs
kubectl logs -l app=rsolv-api --tail=50

# Test health endpoint
curl https://api.rsolv.ai/health
```

### 5. Test credential exchange

```bash
# Test with curl
curl -X POST https://api.rsolv.ai/api/v1/credentials/exchange \
  -H 'Content-Type: application/json' \
  -d '{"api_key": "rsolv_test_key", "providers": ["anthropic"]}'
```

## Database Setup

Run migrations on first deployment:

```bash
kubectl exec -it deployment/rsolv-api -- bin/rsolv_api eval "RSOLV.Release.migrate"
```

## Monitoring

- Application logs: `kubectl logs -l app=rsolv-api -f`
- Metrics: Available at `/metrics` endpoint
- Health check: `/health` endpoint

## Rollback

If needed, rollback to previous version:

```bash
kubectl rollout undo deployment/rsolv-api
```

## SSL Certificate

SSL certificates are automatically managed by cert-manager for api.rsolv.ai domain.