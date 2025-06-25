# Test environment seeds
# This file seeds the test database with data needed for E2E tests

# Import Ecto.Query
import Ecto.Query

# Get the repo
repo = RsolvApi.Repo

# Check if customer already exists
existing = repo.one(from c in "customers", where: c.email == "test@example.com", select: c.id)

if existing do
  IO.puts("Test customer already exists")
else
  # Create a test customer with API key using direct SQL
  {:ok, _} = repo.query("""
    INSERT INTO customers (name, email, api_key, active, trial_fixes_used, trial_fixes_limit, trial_expired, subscription_plan, rollover_fixes, inserted_at, updated_at)
    VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
  """, [
    "Test Customer",
    "test@example.com", 
    "test-api-key",
    true,
    0,
    10,
    false,
    "pay_as_you_go",
    0,
    NaiveDateTime.utc_now(),
    NaiveDateTime.utc_now()
  ])
  
  IO.puts("Created test customer: test@example.com with API key: test-api-key")
end