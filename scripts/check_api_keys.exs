# Script to check API keys in the database
# Run with: mix run scripts/check_api_keys.exs

alias Rsolv.Repo

IO.puts("Checking API keys in database...\n")

# Query customers
{:ok, result} = Repo.query("""
  SELECT id, name, email, api_key, plan, monthly_limit 
  FROM customers 
  WHERE email LIKE '%rsolv.dev' 
  ORDER BY id DESC 
  LIMIT 10
""")

IO.puts("Customers found:")
IO.puts("================")
Enum.each(result.rows, fn [id, name, email, api_key, plan, monthly_limit] ->
  key_preview = if api_key, do: String.slice(api_key, 0..20) <> "...", else: "null"
  IO.puts("ID: #{id}, Name: #{name}, Email: #{email}")
  IO.puts("  API Key: #{key_preview}")
  IO.puts("  Plan: #{plan}, Limit: #{monthly_limit}")
  IO.puts("")
end)

# Query API keys table
{:ok, api_result} = Repo.query("""
  SELECT ak.id, ak.key, ak.name, ak.customer_id, c.name as customer_name
  FROM api_keys ak
  JOIN customers c ON c.id = ak.customer_id
  WHERE c.email LIKE '%rsolv.dev'
  ORDER BY ak.id DESC
  LIMIT 10
""")

IO.puts("\nAPI Keys table:")
IO.puts("===============")
Enum.each(api_result.rows, fn [id, key, name, customer_id, customer_name] ->
  key_preview = if key, do: String.slice(key, 0..20) <> "...", else: "null"
  IO.puts("ID: #{id}, Name: #{name}, Customer: #{customer_name} (#{customer_id})")
  IO.puts("  Key: #{key_preview}")
  IO.puts("")
end)