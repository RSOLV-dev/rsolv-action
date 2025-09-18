# Script to debug API key issues
# Run with: mix run scripts/debug_api_key.exs

alias Rsolv.{Repo, Customers}
alias Rsolv.Customers.{Customer, ApiKey}
import Ecto.Query

IO.puts("=" |> String.duplicate(70))
IO.puts("API KEY DEBUGGING")
IO.puts("=" |> String.duplicate(70))

# The production key we generated
test_key = "rsolv_xud6j-kCuMwsQ371QNBkQvTi5gmfZQ98FPXbmNmhMio"

IO.puts("\n1. Testing key format:")
IO.puts("   Key: #{test_key}")
IO.puts("   Length: #{String.length(test_key)}")
IO.puts("   Prefix: #{String.slice(test_key, 0, 20)}")

# Check if we can find this key in the database
IO.puts("\n2. Checking database for API keys:")

# First, let's see all API keys
all_keys = Repo.all(from k in ApiKey,
  select: %{
    id: k.id,
    name: k.name,
    key_prefix: k.key_prefix,
    active: k.active,
    customer_id: k.customer_id
  })

IO.puts("   Found #{length(all_keys)} total API keys")
Enum.each(all_keys, fn key ->
  IO.puts("   - ID: #{key.id}, Prefix: #{key.key_prefix || "nil"}, Active: #{key.active}")
end)

# Check if the key_hash matches
IO.puts("\n3. Testing key hash validation:")
key_hash = :crypto.hash(:sha256, test_key) |> Base.encode64()
IO.puts("   Generated hash: #{String.slice(key_hash, 0, 20)}...")

# Look for a key with matching prefix
prefix_to_find = String.slice(test_key, 0, 20)
matching_key = Repo.one(from k in ApiKey,
  where: k.key_prefix == ^prefix_to_find,
  limit: 1)

if matching_key do
  IO.puts("   Found matching key in DB!")
  IO.puts("   - Name: #{matching_key.name}")
  IO.puts("   - Active: #{matching_key.active}")
  IO.puts("   - Customer ID: #{matching_key.customer_id}")

  # Check if the hash matches
  if matching_key.key_hash == key_hash do
    IO.puts("   ✓ Hash matches!")
  else
    IO.puts("   ✗ Hash mismatch!")
    IO.puts("   - Expected: #{String.slice(matching_key.key_hash || "nil", 0, 20)}...")
    IO.puts("   - Got: #{String.slice(key_hash, 0, 20)}...")
  end
else
  IO.puts("   ✗ No matching key found in database with prefix: #{prefix_to_find}")
end

# Check customers
IO.puts("\n4. Checking customers:")
customers = Repo.all(from c in Customer,
  where: c.active == true,
  select: %{
    id: c.id,
    name: c.name,
    email: c.email,
    subscription_tier: c.subscription_tier,
    monthly_limit: c.monthly_limit
  })

Enum.each(customers, fn c ->
  IO.puts("   - #{c.name} (#{c.email}): Tier=#{c.subscription_tier}, Limit=#{c.monthly_limit}")
end)

# Test the API key lookup function directly
IO.puts("\n5. Testing API key lookup function:")
result = Customers.get_api_key_by_key(test_key)
case result do
  nil ->
    IO.puts("   ✗ get_api_key_by_key returned nil")
  key ->
    IO.puts("   ✓ Found key: #{key.name}")
end

# Alternative lookup method
IO.puts("\n6. Testing alternative lookup:")
# Try to find by just the key value (in case it's stored differently)
alt_result = Repo.one(from k in ApiKey,
  where: k.key_hash == ^key_hash and k.active == true,
  limit: 1)

if alt_result do
  IO.puts("   ✓ Found by hash lookup")
else
  IO.puts("   ✗ Not found by hash lookup")
end

IO.puts("\n" <> String.duplicate("=", 70))
IO.puts("DIAGNOSIS:")
if matching_key && matching_key.active && matching_key.key_hash == key_hash do
  IO.puts("✓ Key exists and is valid - issue is likely in the API endpoint")
else
  IO.puts("✗ Key validation issue - check database storage")
end
IO.puts(String.duplicate("=", 70))