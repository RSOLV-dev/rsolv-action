# Script to debug API key issues
# Run with: mix run scripts/debug_api_key_simple.exs

alias Rsolv.{Repo, Customers}
alias Rsolv.Customers.{Customer, ApiKey}
import Ecto.Query

IO.puts("=" |> String.duplicate(70))
IO.puts("API KEY DEBUGGING - SIMPLIFIED")
IO.puts("=" |> String.duplicate(70))

# The production key we generated
test_key = "rsolv_xud6j-kCuMwsQ371QNBkQvTi5gmfZQ98FPXbmNmhMio"

IO.puts("\n1. Looking for API key in database:")
IO.puts("   Searching for: #{test_key}")

# Direct lookup
found_key = Repo.get_by(ApiKey, key: test_key)

if found_key do
  IO.puts("   ✓ FOUND THE KEY!")
  IO.puts("   - ID: #{found_key.id}")
  IO.puts("   - Name: #{found_key.name}")
  IO.puts("   - Customer ID: #{found_key.customer_id}")
  IO.puts("   - Active: #{found_key.active}")
  IO.puts("   - Permissions: #{inspect(found_key.permissions)}")

  # Get the customer
  customer = Repo.get(Customer, found_key.customer_id)
  if customer do
    IO.puts("\n2. Customer details:")
    IO.puts("   - Name: #{customer.name}")
    IO.puts("   - Email: #{customer.email}")
    IO.puts("   - Active: #{customer.active}")
    IO.puts("   - Monthly Limit: #{customer.monthly_limit}")
    IO.puts("   - Current Usage: #{customer.current_usage}")
  end
else
  IO.puts("   ✗ KEY NOT FOUND IN DATABASE")

  # List all keys to debug
  IO.puts("\n   All API keys in database:")
  all_keys = Repo.all(ApiKey)
  Enum.each(all_keys, fn k ->
    IO.puts("   - #{String.slice(k.key || "nil", 0, 30)}... (Customer: #{k.customer_id})")
  end)
end

# Test via the Customers context
IO.puts("\n3. Testing via Customers context:")
case Customers.get_api_key_by_key(test_key) do
  nil ->
    IO.puts("   ✗ Customers.get_api_key_by_key returned nil")
  key ->
    IO.puts("   ✓ Customers.get_api_key_by_key found the key")
end

# Check if there's an issue with the key format
IO.puts("\n4. Checking for similar keys:")
prefix = String.slice(test_key, 0, 10)
similar = Repo.all(from k in ApiKey, where: like(k.key, ^"#{prefix}%"))
IO.puts("   Found #{length(similar)} keys starting with '#{prefix}'")
Enum.each(similar, fn k ->
  IO.puts("   - #{k.key}")
end)

IO.puts("\n" <> String.duplicate("=", 70))
IO.puts("DIAGNOSIS:")
if found_key && found_key.active do
  IO.puts("✓ Key exists and is active in database")
  IO.puts("→ The issue is likely in the API endpoint validation logic")
else
  IO.puts("✗ Key not found or inactive")
  IO.puts("→ Need to ensure key was properly saved to database")
end
IO.puts(String.duplicate("=", 70))