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

### Setup
- **[DEV_SETUP.md](DEV_SETUP.md)** - Complete development environment setup guide
  - Quick start with `mix setup`
  - Environment configuration
  - Troubleshooting common issues
  - Test credentials and next steps

### Testing
- **[STRIPE-WEBHOOK-TESTING.md](STRIPE-WEBHOOK-TESTING.md)** - Local Stripe webhook testing
  - Stripe CLI method (quick, verified)
  - Tailscale Funnel method (realistic, pending verification)
  - Docker Compose options

### Running Locally
```bash
# Quick start (recommended)
mix setup

# Or manual setup
mix deps.get
mix phx.server
```

### Environment Variables
See [`.env.example`](../.env.example) for complete configuration options.

Key variables:
```bash
# Required
DATABASE_URL=postgresql://postgres:postgres@localhost/rsolv_dev
SECRET_KEY_BASE=<generated-by-mix-phx.gen.secret>

# Optional
ANTHROPIC_API_KEY=<your-key>
SLACK_WEBHOOK_URL="https://hooks.slack.com/services/..."
```