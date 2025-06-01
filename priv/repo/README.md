# RSOLV API Database Management Scripts

This directory contains scripts for managing customers and API keys in the RSOLV database.

## Prerequisites

1. Ensure you have the database URL configured:
   ```bash
   export DATABASE_URL="postgresql://user:pass@host:port/database"
   ```

2. Make sure migrations are run:
   ```bash
   mix ecto.migrate
   ```

## Available Scripts

### 1. Add API Key (`add_api_key.exs`)

Creates a new customer with an API key.

```bash
# Basic usage with auto-generated API key
mix run priv/repo/add_api_key.exs --name "Acme Corp" --email "tech@acme.com"

# With custom API key and limit
mix run priv/repo/add_api_key.exs --name "Beta User" --email "beta@example.com" \
  --api-key "rsolv_beta_xyz123" --limit 50

# With metadata
mix run priv/repo/add_api_key.exs --name "Enterprise" --email "ent@corp.com" \
  --metadata '{"plan":"enterprise","contact":"John Doe"}'
```

**Options:**
- `--name` (required): Customer name
- `--email` (required): Customer email address
- `--api-key`: Custom API key (default: auto-generated)
- `--limit`: Monthly fix limit (default: 100)
- `--metadata`: JSON metadata (default: {})

### 2. List Customers (`list_customers.exs`)

Shows all customers and their details.

```bash
# List all customers
mix run priv/repo/list_customers.exs

# Show only active customers
mix run priv/repo/list_customers.exs --active-only

# Include usage statistics
mix run priv/repo/list_customers.exs --show-usage
```

**Options:**
- `--active-only`: Show only active customers
- `--show-usage`: Display current usage statistics

### 3. Update Customer (`update_customer.exs`)

Updates existing customer details.

```bash
# Update monthly limit
mix run priv/repo/update_customer.exs --email "customer@example.com" --limit 200

# Deactivate a customer
mix run priv/repo/update_customer.exs --api-key "rsolv_live_xyz" --deactivate

# Reset usage counter
mix run priv/repo/update_customer.exs --email "customer@example.com" --reset-usage

# Multiple updates at once
mix run priv/repo/update_customer.exs --email "customer@example.com" \
  --limit 500 --name "Premium Customer"
```

**Identifiers (one required):**
- `--email`: Customer email address
- `--api-key`: Customer API key

**Options:**
- `--limit`: Update monthly fix limit
- `--deactivate`: Deactivate the customer
- `--activate`: Activate the customer
- `--reset-usage`: Reset current usage to 0
- `--name`: Update customer name
- `--metadata`: Update metadata (JSON)

### 4. Seed Data (`seeds.exs`)

Populates the database with initial test data.

```bash
mix run priv/repo/seeds.exs
```

Creates:
- Internal dogfooding account (`rsolv_dogfood_key`)
- Demo account (`rsolv_demo_key_123`)

## Security Notes

1. **API keys are shown in plain text** - save them securely as they cannot be retrieved later
2. **Database access required** - these scripts need direct database connectivity
3. **No validation on API key format** - ensure you follow naming conventions

## API Key Naming Conventions

- Production keys: `rsolv_live_[random]`
- Internal keys: `rsolv_internal_[purpose]`
- Demo keys: `rsolv_demo_[identifier]`
- Test keys: `rsolv_test_[identifier]`

## Testing an API Key

After creating a key, test it with:

```bash
curl -X POST https://api.rsolv.dev/api/v1/credentials/exchange \
  -H "Content-Type: application/json" \
  -d '{"api_key": "YOUR_API_KEY", "providers": ["anthropic"]}'
```

## Common Tasks

### Onboard a New Customer
```bash
# 1. Create their account
mix run priv/repo/add_api_key.exs --name "New Customer" --email "customer@company.com" --limit 100

# 2. Test the API key (copy from output)
# 3. Send the API key securely to the customer
```

### Handle Quota Exceeded
```bash
# Check current usage
mix run priv/repo/list_customers.exs --show-usage

# Increase limit if needed
mix run priv/repo/update_customer.exs --email "customer@company.com" --limit 200

# Or reset usage if it's a special case
mix run priv/repo/update_customer.exs --email "customer@company.com" --reset-usage
```

### Deactivate a Customer
```bash
# Deactivate
mix run priv/repo/update_customer.exs --email "customer@company.com" --deactivate

# Reactivate later if needed
mix run priv/repo/update_customer.exs --email "customer@company.com" --activate
```