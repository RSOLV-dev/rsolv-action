# Script to properly fix metadata storage in database
# Run with: mix run scripts/fix_metadata_properly.exs

alias Rsolv.Repo

IO.puts("Fixing metadata storage for API key customers...\n")

# Delete and recreate the customers with proper metadata
customers_data = [
  %{id: 1, name: "Demo Account", email: "demo@rsolv.dev", api_key: "demo_69b3158556cf1717c14bfcd8a1186a42", monthly_limit: 10, plan: "demo", type: "demo"},
  %{id: 2, name: "Internal Testing", email: "internal@rsolv.dev", api_key: "internal_c9d0a3569b45597be41a44ca007abd5c", monthly_limit: 1000, plan: "internal", type: "internal"},
  %{id: 3, name: "RSOLV Dogfooding", email: "dogfood@rsolv.dev", api_key: "dogfood_3132182ffed1ab7fbe4e9abbd54d8309", monthly_limit: 10000, plan: "unlimited", type: "rsolv"},
  %{id: 4, name: "Master Account", email: "master@rsolv.dev", api_key: "master_58d4c71fcbf98327b088b21dd24f6c4327e87b4f4e080f7f81ebbc2f0e0aef32", monthly_limit: 100000, plan: "unlimited", type: "master"}
]

# Update each customer with proper metadata
Enum.each(customers_data, fn data ->
  # Use a simpler approach - update with raw SQL
  {:ok, _} = Repo.query(
    """
    UPDATE customers 
    SET metadata = $1::jsonb
    WHERE id = $2
    """,
    [%{type: data.type}, data.id]
  )
  IO.puts("✓ Fixed metadata for #{data.name}")
end)

# Verify the fix
IO.puts("\nVerifying fixed metadata:")
{:ok, result} = Repo.query("""
  SELECT id, email, metadata, jsonb_typeof(metadata) as type
  FROM customers 
  WHERE email LIKE '%rsolv.dev%'
  ORDER BY id
""")

Enum.each(result.rows, fn [id, email, metadata, type] ->
  IO.puts("ID: #{id}, Email: #{email}")
  IO.puts("  Type: #{type}")
  IO.puts("  Metadata: #{inspect(metadata)}")
end)

# Test loading through Ecto
IO.puts("\nTesting Ecto loading:")
import Ecto.Query

try do
  customers = Repo.all(
    from c in Rsolv.Customers.Customer,
    where: like(c.email, "%rsolv.dev%"),
    order_by: c.id
  )
  
  Enum.each(customers, fn customer ->
    IO.puts("✓ Loaded customer: #{customer.name}")
    IO.puts("  Metadata: #{inspect(customer.metadata)}")
    IO.puts("  API Key: #{String.slice(customer.api_key, 0..20)}...")
  end)
  
  IO.puts("\nSuccess! All customers loaded properly.")
rescue
  e ->
    IO.puts("✗ Error loading through Ecto: #{inspect(e)}")
    IO.inspect(e, pretty: true)
end