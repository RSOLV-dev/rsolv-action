# Script to create a demo API key in production for testing
# Run with: MIX_ENV=prod mix run scripts/create_production_demo_key.exs

alias Rsolv.Customers
alias Rsolv.Repo

# Create or get demo customer
demo_customer =
  case Repo.get_by(Customers.Customer, email: "demo@nodegoat.test") do
    nil ->
      {:ok, customer} = Customers.create_customer(%{
        name: "NodeGoat Demo",
        email: "demo@nodegoat.test",
        company: "RSOLV Demo",
        subscription_tier: "professional",
        monthly_limit: 100,
        current_usage: 0,
        billing_email: "demo@nodegoat.test",
        active: true
      })
      IO.puts("Created new demo customer: #{customer.name}")
      customer

    existing ->
      IO.puts("Using existing demo customer: #{existing.name}")
      existing
  end

# Generate a new API key
key_value = "rsolv_nodegoat_demo_" <> Base.encode32(:crypto.strong_rand_bytes(20), padding: false)
key_hash = :crypto.hash(:sha256, key_value) |> Base.encode64()

{:ok, api_key} = Customers.create_api_key(%{
  customer_id: demo_customer.id,
  name: "NodeGoat Demo Key - #{DateTime.utc_now() |> DateTime.to_iso8601()}",
  key_hash: key_hash,
  key_prefix: String.slice(key_value, 0, 20),
  active: true,
  permissions: %{
    "scan" => true,
    "validate" => true,
    "mitigate" => true
  }
})

IO.puts("\n" <> String.duplicate("=", 70))
IO.puts("NODEGOAT DEMO API KEY CREATED")
IO.puts(String.duplicate("=", 70))
IO.puts("Customer ID: #{demo_customer.id}")
IO.puts("Customer: #{demo_customer.name} (#{demo_customer.email})")
IO.puts("Monthly Limit: #{demo_customer.monthly_limit}")
IO.puts("\nAPI Key Name: #{api_key.name}")
IO.puts("API Key ID: #{api_key.id}")
IO.puts("\nFull API Key (SAVE THIS):")
IO.puts(key_value)
IO.puts("\nTo update GitHub secret:")
IO.puts("echo \"#{key_value}\" | gh secret set RSOLV_API_KEY --repo RSOLV-dev/nodegoat-vulnerability-demo")
IO.puts(String.duplicate("=", 70))