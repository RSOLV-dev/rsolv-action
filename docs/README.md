# RSOLV API Documentation

## 📚 Documentation Structure

### 🔒 Security Pattern API
- **[API-PATTERNS.md](API-PATTERNS.md)** - Complete Pattern API documentation with examples
- **[openapi-patterns.yaml](openapi-patterns.yaml)** - OpenAPI 3.0 specification for machine consumption

### 📡 Integrations
- **[SLACK_INTEGRATION_SETUP.md](slack/SLACK_INTEGRATION_SETUP.md)** - Comprehensive Slack integration guide
- **[SLACK_WEBHOOK_SETUP_QUICK.md](slack/SLACK_WEBHOOK_SETUP_QUICK.md)** - Quick setup reference

### 📚 Educational Framework
- **[EDUCATIONAL_FRAMEWORK_STATUS.md](../EDUCATIONAL_FRAMEWORK_STATUS.md)** - Implementation status and roadmap

### 🚀 Deployment
- **[DEPLOYMENT.md](../DEPLOYMENT.md)** - Production deployment guide
- **[QUICK-DEPLOY.md](../QUICK-DEPLOY.md)** - Quick deployment reference

## 🧪 Testing

Test scripts are located in `/test/scripts/`:
- End-to-end testing
- Throttling verification
- Slack integration tests

See [test/scripts/README.md](../test/scripts/README.md) for details.

## 🔧 Development

### Running Locally
```bash
mix deps.get
mix phx.server
```

### Environment Variables
```bash
# Required
export SLACK_WEBHOOK_URL="https://hooks.slack.com/services/..."

# Optional
export MAX_DAILY_ALERTS=3
export DASHBOARD_URL="https://dashboard.rsolv.dev"
```