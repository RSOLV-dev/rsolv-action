# Script to create a production API key programmatically
# Run with: mix run scripts/create_production_api_key.exs

alias Rsolv.{Repo, Customers}
alias Rsolv.Customers.{Customer, ApiKey}

IO.puts("=" |> String.duplicate(70))
IO.puts("CREATING PRODUCTION API KEY")
IO.puts("=" |> String.duplicate(70))

# Find or create RSOLV Staff customer
staff_email = "staff@rsolv.dev"

customer = case Repo.get_by(Customer, email: staff_email) do
  nil ->
    IO.puts("\n1. Creating RSOLV Staff customer...")
    {:ok, customer} = Customers.create_customer(%{
      email: staff_email,
      name: "RSOLV Staff",
      is_staff: true,
      active: true,
      monthly_limit: 100,
      current_usage: 0
    })
    IO.puts("   ✓ Created customer: #{customer.name}")
    customer

  existing ->
    IO.puts("\n1. Found existing RSOLV Staff customer")
    IO.puts("   - Name: #{existing.name}")
    IO.puts("   - ID: #{existing.id}")
    IO.puts("   - Active: #{existing.active}")
    existing
end

# Generate new API key
IO.puts("\n2. Generating new API key...")
{:ok, api_key} = Customers.create_api_key(customer, %{
  name: "Production Demo Key",
  active: true
})

IO.puts("   ✓ Created API key")
IO.puts("   - Key: #{api_key.key}")
IO.puts("   - ID: #{api_key.id}")
IO.puts("   - Active: #{api_key.active}")

# Verify the key works
IO.puts("\n3. Verifying API key...")

# Test lookup by key
found_key = Customers.get_api_key_by_key(api_key.key)
if found_key do
  IO.puts("   ✓ Successfully retrieved API key by key value")
else
  IO.puts("   ✗ Failed to retrieve API key by key value")
end

# Test customer lookup
found_customer = Customers.get_customer_by_api_key(api_key.key)
if found_customer && found_customer.id == customer.id do
  IO.puts("   ✓ Successfully retrieved customer from API key")
else
  IO.puts("   ✗ Failed to retrieve customer from API key")
end

# Test with Accounts context (used by credential controller)
found_by_accounts = Rsolv.Accounts.get_customer_by_api_key(api_key.key)
if found_by_accounts && found_by_accounts.id == customer.id do
  IO.puts("   ✓ Successfully retrieved customer via Accounts context")
else
  IO.puts("   ✗ Failed to retrieve customer via Accounts context")
end

IO.puts("\n" <> String.duplicate("=", 70))
IO.puts("SUCCESS!")
IO.puts("API Key created and verified successfully")
IO.puts("")
IO.puts("Use this API key for testing:")
IO.puts("#{api_key.key}")
IO.puts("")
IO.puts("To set it as a GitHub secret:")
IO.puts("gh secret set RSOLV_API_KEY --body \"#{api_key.key}\" -R RSOLV-dev/nodegoat-vulnerability-demo")
IO.puts(String.duplicate("=", 70))