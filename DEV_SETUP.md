# Development Environment Setup

## Quick Start

For new developers, run one command:

```bash
mix setup
```

This will:
- ✅ Check for `.env` file (offers to run wizard if missing)
- ✅ Validate environment configuration
- ✅ Check system requirements (Elixir, PostgreSQL, etc.)
- ✅ Install dependencies
- ✅ Set up and compile assets
- ✅ Create and migrate database
- ✅ Load test data
- ✅ Generate OpenAPI spec
- ✅ Verify everything works
- ✅ Display test credentials and next steps

**Note:** If you don't have a `.env` file, the setup will prompt you to run the environment setup wizard (`mix dev.env.setup`) first.

## What You Get

After running `mix setup`, you'll see:

### Test Credentials

| User        | Email                      | Password                 |
|-------------|----------------------------|--------------------------|
| Admin       | admin@rsolv.dev           | AdminP@ssw0rd2025!      |
| Staff       | staff@rsolv.dev           | StaffP@ssw0rd2025!      |
| Test User   | test@example.com          | TestP@ssw0rd2025!       |
| Demo        | demo@example.com          | DemoP@ssw0rd2025!       |
| Enterprise  | enterprise@bigcorp.com    | EnterpriseP@ssw0rd2025! |

### Test API Keys

- `rsolv_test_key_123` (test@example.com)
- `rsolv_demo_key_456` (demo@example.com)

## Pre-flight Checks

Before setup begins, the system validates:

### Required
- **Elixir** >= 1.18.0
- **Erlang/OTP** >= 26.0
- **PostgreSQL** installed and running
- **Port 4000** available

### Recommended
- **Node.js** for asset compilation

### Optional
- `DATABASE_URL` (uses config defaults if not set)
- `SECRET_KEY_BASE` (auto-generated for dev)
- `ANTHROPIC_API_KEY` or `OPENAI_API_KEY` (for AI features)

## Common Issues

### PostgreSQL Not Running

**Error:**
```
❌ PostgreSQL installed but may not be running
```

**Fix:**
```bash
# macOS
brew services start postgresql@16

# Linux
sudo systemctl start postgresql

# Docker
docker-compose up -d postgres
```

### Port 4000 Already in Use

**Error:**
```
⚠️  Port 4000 in use
```

**Fix:**
```bash
# Find the process
lsof -ti:4000

# Kill it
kill $(lsof -ti:4000)
```

### Elixir/OTP Version Too Old

**Error:**
```
❌ Elixir version too old (1.14.0)
```

**Fix:**
```bash
# Using asdf
asdf install elixir 1.18.4
asdf install erlang 26.0

# Or upgrade your package manager version
brew upgrade elixir
```

## Manual Setup Steps

If you need to run individual steps:

```bash
# Create/configure .env file interactively
mix dev.env.setup

# Run just the pre-flight checks
mix dev.preflight

# Run just the verification
mix dev.verify

# Display the summary again
mix dev.summary

# Run the basic setup (without checks/verification)
mix setup.basic
```

## Options

```bash
# Skip pre-flight checks (not recommended)
mix setup --skip-preflight

# Skip verification (faster, but less safe)
mix setup --skip-verify

# Quiet mode (minimal output)
mix setup --quiet
```

## Next Steps After Setup

1. **Start the server:**
   ```bash
   mix phx.server
   ```

2. **View API docs:**
   ```
   http://localhost:4000/api/docs
   ```

3. **Access LiveView dashboard:**
   ```
   http://localhost:4000/dev/dashboard
   ```

4. **View feature flags:**
   ```
   http://localhost:4000/dev/feature-flags
   ```

## Development Workflow

```bash
# First time setup
mix setup

# Daily development
mix dev  # Runs setup + starts server

# Reset database
mix ecto.reset

# Run tests
mix test

# Generate OpenAPI spec after API changes
mix rsolv.openapi
```

## Architecture

The enhanced setup system consists of:

- **`Mix.Tasks.Setup`** (`lib/mix/tasks/setup.ex`) - Standard entry point, delegates to `dev.setup`
- **`dev.env.setup`** - Interactive wizard for creating/configuring `.env` file
- **`dev.setup`** - Main orchestrator that runs all setup steps with progress tracking
- **`dev.preflight`** - Pre-flight system checks (includes .env validation)
- **`dev.verify`** - Post-setup verification
- **`dev.summary`** - Display credentials and next steps

### Files

```
lib/mix/tasks/
├── setup.ex           # Entry point (delegates to dev.setup)
└── dev/
    ├── env_setup.ex   # .env wizard
    ├── setup.ex       # Main orchestrator
    ├── preflight.ex   # Pre-flight checks + .env validation
    ├── verify.ex      # Post-setup verification
    └── summary.ex     # Summary display
```

### Flow

```
mix setup
  └─> Mix.Tasks.Setup
       └─> dev.setup
            ├─> dev.preflight (includes .env checking)
            ├─> deps.get
            ├─> assets.setup
            ├─> assets.build
            ├─> ecto.setup
            ├─> rsolv.openapi
            ├─> dev.verify
            └─> dev.summary
```

## Success Criteria

Setup is complete when you see:

```
🎉 Setup Complete!
═══════════════════════════════════════════════════════════

📋 Test Credentials:
[table of credentials]

🔑 Test API Keys:
[list of API keys]

🚀 Next Steps:
[helpful commands]

⏱️  Setup completed in ~2m 34s
```

## Troubleshooting

### Compilation Errors

If you see Elixir compilation errors:

```bash
# Clean and recompile
mix deps.clean --all
mix deps.get
mix compile
```

### Database Connection Issues

Check your database configuration:

```bash
# Test connection
psql -U postgres -h localhost -d rsolv_api_dev

# Check config
cat config/dev.exs | grep -A 10 "Rsolv.Repo"
```

### Asset Compilation Issues

If assets don't compile:

```bash
# Reinstall asset tools
mix assets.setup

# Rebuild assets
mix assets.build
```

## Environment Variables

Optional environment variables for development:

```bash
# Database (overrides config/dev.exs)
export DATABASE_URL="postgres://user:pass@localhost:5432/rsolv_api_dev"

# Security (auto-generated for dev)
export SECRET_KEY_BASE="$(mix phx.gen.secret)"

# AI Features (optional)
export ANTHROPIC_API_KEY="sk-ant-..."
export OPENAI_API_KEY="sk-..."
```

## Docker Development

If using Docker:

```bash
# Start all services
docker-compose up -d

# Run setup inside container
docker-compose exec app mix setup

# View logs
docker-compose logs -f app
```

## Contributing

When modifying the setup system:

1. Test on a fresh clone (or fresh Docker container)
2. Ensure all checks are idempotent (safe to run multiple times)
3. Add helpful error messages with actionable suggestions
4. Update this documentation if adding new checks or steps

## Support

For issues or questions:

- Open an issue on GitHub
- Check existing RFCs/ADRs for architectural context
- Review `CLAUDE.md` for development guidelines
