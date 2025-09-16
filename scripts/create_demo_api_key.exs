# Script to create a demo API key for testing
# Run with: mix run scripts/create_demo_api_key.exs

alias Rsolv.Customers
alias Rsolv.Customers.{Customer, ApiKey}
alias Rsolv.Repo

# First, create or find a demo customer
demo_customer =
  case Repo.get_by(Customer, email: "demo@rsolv.dev") do
    nil ->
      {:ok, customer} = Customers.create_customer(%{
        name: "Demo Customer",
        email: "demo@rsolv.dev",
        company: "RSOLV Demo",
        subscription_tier: "professional",
        monthly_limit: 1000,
        current_usage: 0,
        billing_email: "demo@rsolv.dev",
        active: true
      })
      IO.puts("Created new demo customer: #{customer.name}")
      customer

    existing ->
      IO.puts("Using existing demo customer: #{existing.name}")
      existing
  end

# Generate a new API key for the demo customer
key_value = "rsolv_demo_" <> :crypto.strong_rand_bytes(32) |> Base.encode64(padding: false)
key_prefix = String.slice(key_value, 0, 15)
key_hash = :crypto.hash(:sha256, key_value) |> Base.encode64()

{:ok, api_key} = Customers.create_api_key(%{
  customer_id: demo_customer.id,
  name: "Demo API Key - #{DateTime.utc_now() |> DateTime.to_iso8601()}",
  key_hash: key_hash,
  key_prefix: key_prefix,
  active: true,
  permissions: %{
    "scan" => true,
    "validate" => true,
    "mitigate" => true
  }
})

IO.puts("\n" <> String.duplicate("=", 60))
IO.puts("DEMO API KEY CREATED SUCCESSFULLY")
IO.puts(String.duplicate("=", 60))
IO.puts("Customer: #{demo_customer.name} (#{demo_customer.email})")
IO.puts("API Key Name: #{api_key.name}")
IO.puts("API Key ID: #{api_key.id}")
IO.puts("\nFull API Key (save this - it won't be shown again):")
IO.puts(key_value)
IO.puts("\nKey Prefix (for identification): #{key_prefix}")
IO.puts(String.duplicate("=", 60))
IO.puts("\nTo use this key:")
IO.puts("export RSOLV_API_KEY=\"#{key_value}\"")
IO.puts("\nOr add to GitHub repository secrets as RSOLV_API_KEY")
IO.puts(String.duplicate("=", 60))