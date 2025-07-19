# Script to fix metadata storage in database
# Run with: mix run scripts/fix_metadata.exs

alias Rsolv.Repo

IO.puts("Fixing metadata storage for API key customers...\n")

# First, check current state
{:ok, result} = Repo.query("""
  SELECT id, email, metadata
  FROM customers 
  WHERE email LIKE '%rsolv.dev%'
  ORDER BY id
""")

IO.puts("Current metadata values:")
Enum.each(result.rows, fn [id, email, metadata] ->
  IO.puts("ID: #{id}, Email: #{email}, Metadata: #{inspect(metadata)}")
end)

# Fix the metadata by converting JSON string to proper JSONB
IO.puts("\nFixing metadata...")

{:ok, _} = Repo.query("""
  UPDATE customers 
  SET metadata = metadata::jsonb
  WHERE email LIKE '%rsolv.dev%'
  AND jsonb_typeof(metadata::jsonb) = 'string'
""")

IO.puts("Metadata fixed!")

# Verify the fix
{:ok, result} = Repo.query("""
  SELECT id, email, metadata, jsonb_typeof(metadata) as type
  FROM customers 
  WHERE email LIKE '%rsolv.dev%'
  ORDER BY id
""")

IO.puts("\nVerifying fixed metadata:")
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
    limit: 2
  )
  
  Enum.each(customers, fn customer ->
    IO.puts("✓ Loaded customer: #{customer.name}")
    IO.puts("  Metadata: #{inspect(customer.metadata)}")
  end)
rescue
  e ->
    IO.puts("✗ Error loading through Ecto: #{inspect(e)}")
end