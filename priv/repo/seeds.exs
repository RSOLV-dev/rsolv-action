# Script for populating the database. You can run it as:
#
#     mix run priv/repo/seeds.exs

alias RsolvApi.Repo
alias RsolvApi.Billing.Customer

# Create test customer for dogfooding
dogfood_customer = %Customer{
  name: "RSOLV Internal",
  email: "team@rsolv.dev",
  api_key: "rsolv_dogfood_key",
  active: true,
  metadata: %{
    "type" => "internal",
    "purpose" => "dogfooding"
  }
}

Repo.insert!(dogfood_customer, on_conflict: :nothing, conflict_target: :api_key)

# Create demo customer
demo_customer = %Customer{
  name: "Demo Customer",
  email: "demo@example.com",
  api_key: "rsolv_demo_key_123",
  active: true,
  metadata: %{
    "type" => "demo"
  }
}

Repo.insert!(demo_customer, on_conflict: :nothing, conflict_target: :api_key)

IO.puts("Seeds complete!")
IO.puts("Created customers with API keys:")
IO.puts("  - rsolv_dogfood_key (internal use)")
IO.puts("  - rsolv_demo_key_123 (demos)")