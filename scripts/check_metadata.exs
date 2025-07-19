# Script to check metadata storage in database
# Run with: mix run scripts/check_metadata.exs

alias Rsolv.Repo

IO.puts("Checking metadata column type and values...\n")

# Check column type
{:ok, result} = Repo.query("""
  SELECT column_name, data_type, udt_name 
  FROM information_schema.columns 
  WHERE table_name = 'customers' 
  AND column_name = 'metadata'
""")

IO.puts("Column information:")
Enum.each(result.rows, fn row ->
  IO.inspect(row)
end)

# Check actual values
{:ok, result} = Repo.query("""
  SELECT id, email, metadata, pg_typeof(metadata)::text as type
  FROM customers 
  WHERE email LIKE '%rsolv.dev%'
  ORDER BY id DESC
  LIMIT 5
""")

IO.puts("\nCustomer metadata values:")
Enum.each(result.rows, fn [id, email, metadata, type] ->
  IO.puts("ID: #{id}, Email: #{email}")
  IO.puts("  Type: #{type}")
  IO.puts("  Value: #{inspect(metadata)}")
  IO.puts("")
end)

# Test loading through Ecto
IO.puts("\nTrying to load through Ecto:")
import Ecto.Query

try do
  customers = Repo.all(
    from c in Rsolv.Customers.Customer,
    where: like(c.email, "%rsolv.dev%"),
    limit: 1
  )
  
  Enum.each(customers, fn customer ->
    IO.puts("Loaded customer: #{customer.name}")
    IO.puts("  Metadata: #{inspect(customer.metadata)}")
  end)
rescue
  e ->
    IO.puts("Error loading through Ecto: #{inspect(e)}")
end