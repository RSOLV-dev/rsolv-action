# Create test API key and customer for phase storage testing
alias Rsolv.Repo
alias Rsolv.Accounts.User
alias Rsolv.Customers.{Customer, ApiKey}
alias Rsolv.Phases.ForgeAccount

# Create a user first (required for customer)
user = case Repo.get_by(User, email: "phase-test@rsolv.dev") do
  nil ->
    %User{}
    |> User.registration_changeset(%{
      email: "phase-test@rsolv.dev",
      password: "PhaseTest123456!"
    })
    |> Repo.insert!()
  existing -> existing
end

IO.puts("✅ User ready: #{user.email}")

# Create or get customer
customer = case Repo.get_by(Customer, email: "phase-test@rsolv.dev") do
  nil ->
    %Customer{}
    |> Customer.changeset(%{
      user_id: user.id,
      name: "Phase Storage Test",
      email: "phase-test@rsolv.dev",
      active: true,
      monthly_limit: 1000,
      subscription_tier: "enterprise"
    })
    |> Repo.insert!()
  existing -> existing
end

IO.puts("✅ Customer ready: #{customer.name}")

# Create or get forge account for RSOLV-dev namespace
forge_account = case Repo.get_by(ForgeAccount, 
  customer_id: customer.id,
  namespace: "RSOLV-dev"
) do
  nil ->
    %ForgeAccount{}
    |> ForgeAccount.changeset(%{
      customer_id: customer.id,
      forge_type: :github,
      namespace: "RSOLV-dev",
      verified_at: DateTime.utc_now()
    })
    |> Repo.insert!()
  existing -> existing
end

IO.puts("✅ Forge account ready: #{forge_account.namespace}")

# Create API key
api_key_value = "rsolv_phase_test_" <> Base.encode16(:crypto.strong_rand_bytes(16), case: :lower)

api_key = %ApiKey{}
|> ApiKey.changeset(%{
  customer_id: customer.id,
  name: "Phase Storage Test Key",
  key: api_key_value,
  active: true
})
|> Repo.insert!()

IO.puts("✅ API Key created!")
IO.puts("")
IO.puts("=" <> String.duplicate("=", 60))
IO.puts("API Key for testing: #{api_key.key}")
IO.puts("=" <> String.duplicate("=", 60))
IO.puts("")
IO.puts("Test with:")
IO.puts("curl -X POST http://localhost:4000/api/v1/phases/store \\")
IO.puts("  -H 'Content-Type: application/json' \\")
IO.puts("  -H 'x-api-key: #{api_key.key}' \\")
IO.puts("  -d '{")
IO.puts("    \"phase\": \"scan\",")
IO.puts("    \"repo\": \"RSOLV-dev/nodegoat-demo\",")
IO.puts("    \"commitSha\": \"test-abc123\",")
IO.puts("    \"branch\": \"main\",")
IO.puts("    \"data\": {")
IO.puts("      \"scan\": {")
IO.puts("        \"vulnerabilities\": [")
IO.puts("          {")
IO.puts("            \"type\": \"xss\",")
IO.puts("            \"file\": \"app.js\",")
IO.puts("            \"line\": 42,")
IO.puts("            \"severity\": \"high\"")
IO.puts("          }")
IO.puts("        ]")
IO.puts("      }")
IO.puts("    }")
IO.puts("  }'")