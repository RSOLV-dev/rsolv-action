# RSOLV API Service

[![Elixir CI](https://github.com/RSOLV-dev/rsolv/actions/workflows/elixir-ci.yml/badge.svg)](https://github.com/RSOLV-dev/rsolv/actions/workflows/elixir-ci.yml)

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

### Architecture Documentation

We maintain comprehensive architecture documentation using:

- **[RFCs (Request for Comments)](RFCs/RFC-INDEX.md)**: Proposals for new features and architectural changes (53+ RFCs)
- **[ADRs (Architecture Decision Records)](ADRs/ADR-INDEX.md)**: Documented decisions that have been implemented (24+ ADRs)

Key architectural decisions include:
- Credential vending architecture for secure API key management
- Three-phase security architecture (SCAN → VALIDATE → MITIGATE)
- AST-based validation reducing false positives by 70-90%
- Service consolidation for 50% infrastructure cost reduction

## Security

The API is designed with security as a top priority, ensuring:

- No customer source code is ever stored or processed by the API
- Only metadata about issues and fixes is transmitted
- All communication is encrypted with TLS
- API keys are required for all requests

## Development Setup

### Quick Start (Recommended)

```bash
# Clone the repository
git clone https://github.com/rsolv/platform
cd platform

# Run the interactive environment setup wizard
mix dev.env.setup

# Complete the project setup (dependencies, database, assets)
mix setup

# Start the Phoenix server
mix phx.server
```

The wizard will guide you through:
- ✅ Generating secure secrets
- 🤖 Configuring AI providers (optional)
- 🗄️ Testing database connection
- 📧 Setting up email (optional)

### Manual Setup

If you prefer manual configuration:

1. **Copy environment template:**
   ```bash
   cp .env.example .env
   ```

2. **Generate secret key:**
   ```bash
   mix phx.gen.secret
   # Copy the output to SECRET_KEY_BASE in .env
   ```

3. **Configure database** (edit `.env`):
   ```bash
   DATABASE_URL=postgresql://postgres:postgres@localhost/rsolv_dev
   DATABASE_SSL=false
   ```

4. **(Optional) Add AI provider keys** to `.env`:
   - **Anthropic**: Get key at [console.anthropic.com](https://console.anthropic.com/)
   - **OpenAI**: Get key at [platform.openai.com](https://platform.openai.com/api-keys)
   - **OpenRouter**: Get key at [openrouter.ai](https://openrouter.ai/keys)

5. **Run setup:**
   ```bash
   mix setup
   ```

### Environment Variables

See [`.env.example`](.env.example) for a complete list of configuration options.

**Required:**
- `DATABASE_URL` - PostgreSQL connection string
- `SECRET_KEY_BASE` - Phoenix secret (64+ characters)

**Optional:**
- `ANTHROPIC_API_KEY` - For Claude AI features
- `OPENAI_API_KEY` - For OpenAI features
- `POSTMARK_API_KEY` - For transactional emails
- `KIT_API_KEY` - For ConvertKit integration

**Note:** The application will run with minimal configuration, but some features require API keys.

### Running Tests

```bash
# Run the full test suite
mix test

# Run tests with detailed output
mix test --trace

# Run a specific test file
mix test test/rsolv_web/controllers/pattern_controller_test.exs

# Run tests with coverage (if configured)
mix test --cover
```

### Continuous Integration

This project uses GitHub Actions for continuous integration. The CI pipeline runs automatically on:
- Push to `main` or `develop` branches
- Pull requests targeting `main` or `develop`
- Manual workflow dispatch

#### CI Jobs

1. **Test Suite** - Runs the full Elixir test suite with PostgreSQL
2. **OpenAPI Spec Validation** - Generates and validates the OpenAPI specification
3. **Code Quality** - Checks code formatting and compilation warnings
4. **Migration Integrity** - Verifies database migrations are reversible (up/down/up)
5. **Asset Compilation** - Builds frontend assets (Tailwind CSS, esbuild)

#### Status Checks

**Note:** Some checks (tests, asset compilation, migration rollback, formatting, and warnings enforcement) are presently non-fatal or disabled in the CI workflow. The guarantees below reflect intended coverage, but not all failures will block merges until the workflow is tightened.

The CI pipeline currently runs:
- ✅ All tests (non-fatal; failures do not block merges)
- ✅ OpenAPI spec generation (fatal; failures block merges)
- ✅ Code formatting (`mix format --check-formatted`) (non-fatal)
- ✅ Compilation warnings (non-fatal)
- ✅ Migration reversibility (non-fatal)
- ✅ Database seeds
- ✅ Asset compilation (non-fatal)
#### Running CI Checks Locally

Before pushing, you can run the same checks locally:

```bash
# Run tests
mix test

# Check code formatting
mix format --check-formatted

# Fix formatting issues
mix format

# Compile with warnings as errors
mix compile --warnings-as-errors

# Generate OpenAPI spec
mix rsolv.openapi priv/static/openapi.json

# Verify migrations
mix ecto.migrate
mix ecto.rollback --all
mix ecto.migrate
mix run priv/repo/seeds.exs

# Build assets
mix assets.build
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
