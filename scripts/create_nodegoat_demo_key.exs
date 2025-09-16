# Script to create NodeGoat demo API key
# Run with: mix run scripts/create_nodegoat_demo_key.exs

alias Rsolv.Customers
alias Rsolv.Repo
import Ecto.Query

# First check if we can use the admin user credentials to create via context
admin_email = "admin@rsolv.dev"
admin_password = "AdminP@ssw0rd2025!"

IO.puts("Creating NodeGoat Demo customer and API key...")
IO.puts("=" |> String.duplicate(60))

# Check if customer already exists
existing_customer = Repo.get_by(Customers.Customer, email: "nodegoat@demo.test")

demo_customer = if existing_customer do
  IO.puts("Found existing NodeGoat Demo customer (ID: #{existing_customer.id})")
  existing_customer
else
  # Create new customer
  attrs = %{
    name: "NodeGoat Demo",
    email: "nodegoat@demo.test",
    company: "RSOLV Demo Test",
    subscription_tier: "professional",
    monthly_limit: 100,
    current_usage: 0,
    billing_email: "nodegoat@demo.test",
    active: true
  }

  case Customers.create_customer(attrs) do
    {:ok, customer} ->
      IO.puts("✓ Created new NodeGoat Demo customer (ID: #{customer.id})")
      customer
    {:error, changeset} ->
      IO.puts("✗ Failed to create customer:")
      IO.inspect(changeset.errors)
      nil
  end
end

if demo_customer do
  # Generate a unique API key
  timestamp = DateTime.utc_now() |> DateTime.to_unix()
  random_part = :crypto.strong_rand_bytes(16) |> Base.encode16(case: :lower)
  key_value = "rsolv_nodegoat_#{timestamp}_#{random_part}"

  # Create hashed version for storage
  key_hash = :crypto.hash(:sha256, key_value) |> Base.encode64()
  key_prefix = String.slice(key_value, 0, 20)

  # Create API key
  api_key_attrs = %{
    customer_id: demo_customer.id,
    name: "NodeGoat Demo Key - #{DateTime.utc_now() |> DateTime.to_iso8601()}",
    key_hash: key_hash,
    key_prefix: key_prefix,
    active: true,
    permissions: %{
      "scan" => true,
      "validate" => true,
      "mitigate" => true,
      "all" => true
    }
  }

  case Customers.create_api_key(api_key_attrs) do
    {:ok, api_key} ->
      IO.puts("✓ Created API key (ID: #{api_key.id})")
      IO.puts("\n" <> String.duplicate("=", 70))
      IO.puts("SUCCESS! NodeGoat Demo API Key Created")
      IO.puts(String.duplicate("=", 70))
      IO.puts("Customer: #{demo_customer.name}")
      IO.puts("Email: #{demo_customer.email}")
      IO.puts("Monthly Limit: #{demo_customer.monthly_limit} fixes")
      IO.puts("\nAPI Key (COPY THIS - IT WON'T BE SHOWN AGAIN):")
      IO.puts(key_value)
      IO.puts("\nTo update GitHub secret, run:")
      IO.puts("echo \"#{key_value}\" | gh secret set RSOLV_API_KEY --repo RSOLV-dev/nodegoat-vulnerability-demo")
      IO.puts(String.duplicate("=", 70))

      # Also save to file for easy access
      File.write!("/tmp/nodegoat_api_key.txt", key_value)
      IO.puts("\nKey also saved to: /tmp/nodegoat_api_key.txt")

    {:error, changeset} ->
      IO.puts("✗ Failed to create API key:")
      IO.inspect(changeset.errors)
  end
else
  IO.puts("✗ Could not create or find customer")
end