# RSOLV API Service

Backend API service for the RSOLV automated issue fixing platform.

## Overview

This API service handles:

- **Security Pattern Serving**: 181 vulnerability detection patterns across 8 languages
- **Authentication and authorization**: API key management and credential vending
- **Usage tracking and metrics**: Billing and usage analytics
- **Expert review request management**: Human-in-the-loop workflows
- **Customer dashboard data**: Analytics and reporting

## Architecture

The RSOLV API is built with Phoenix/Elixir for reliability and scalability. It provides the central coordination point between GitHub Actions, expert reviewers, and customer dashboards.

## Security

The API is designed with security as a top priority, ensuring:

- No customer source code is ever stored or processed by the API
- Only metadata about issues and fixes is transmitted
- All communication is encrypted with TLS
- API keys are required for all requests

## Development Setup

```bash
# Install dependencies
mix deps.get

# Setup the database
mix ecto.setup

# Start the Phoenix server
mix phx.server
```

### 🤖 AI-Assisted Development with Tidewave

We've integrated [Tidewave](https://tidewave.ai) for AI-powered development assistance. Tidewave provides real-time AI support directly in your browser while developing.

#### Quick Start
```bash
# Instant start with our convenience script
./start-tidewave.sh
```

#### Access Points
- **Local Development**: http://localhost:4000/tidewave
- **Docker Development**: http://localhost:4001/tidewave
- **Network Access**: Available from 10.x.x.x addresses

#### Features
- 🔍 AST debugging and pattern analysis
- 🛡️ Vulnerability detection testing
- 🔧 Code generation and refactoring
- 📚 Phoenix/Elixir development support
- 🔄 Hot code reloading
- 🐳 Docker Compose support

#### Documentation
- [Quick Start Guide](TIDEWAVE-QUICKSTART.md) - Get started in seconds
- [Docker Setup](TIDEWAVE-DOCKER.md) - Container-based development
- [Security Guide](TIDEWAVE-SECURITY.md) - Security considerations

**Note**: Tidewave is configured for development only and will never deploy to staging/production.

## API Documentation

### 📋 Pattern API
Comprehensive security pattern serving with tiered access:
- **[Pattern API Documentation](docs/API-PATTERNS.md)** - Complete API reference
- **[OpenAPI Specification](docs/openapi-patterns.yaml)** - Machine-readable API spec

### 🔑 Quick Access
```bash
# Public patterns (no auth)
curl https://api.rsolv.dev/api/v1/patterns/public/javascript

# Protected patterns (API key required)
curl -H "Authorization: Bearer YOUR_API_KEY" \
  https://api.rsolv.dev/api/v1/patterns/protected/python
```

## API Endpoints

### Security Patterns
- `GET /api/v1/patterns/public/:language` - Public security patterns
- `GET /api/v1/patterns/protected/:language` - Protected patterns (auth required)
- `GET /api/v1/patterns/ai/:language` - AI-enhanced patterns (feature flag required)
- `GET /api/v1/patterns/cve` - CVE-based patterns
- `GET /api/v1/patterns/type/:vulnerability_type` - Patterns by vulnerability type
- `GET /api/v1/patterns/health` - API health and statistics

### Authentication & Billing
- `POST /api/v1/credentials/exchange` - Exchange API key for temporary credentials
- `POST /api/v1/fix-attempts` - Record billable fix attempts

### Usage
- `POST /api/usage` - Report usage metrics
- `GET /api/usage/:customer_id` - Get usage statistics

### Expert Review

- `POST /api/review/request` - Request expert review
- `GET /api/review/:review_id` - Get review status
- `POST /api/review/:review_id/comment` - Post expert comment

## Deployment

The API service is deployed using Docker and Kubernetes for high availability and scalability.