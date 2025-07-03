# Script to update customer details
# 
# Usage:
#   mix run priv/repo/update_customer.exs --email "customer@example.com" --limit 200
#   mix run priv/repo/update_customer.exs --api-key "rsolv_live_abc123" --deactivate
#   mix run priv/repo/update_customer.exs --email "customer@example.com" --reset-usage

alias Rsolv.Repo
import Ecto.Query

# Parse command line arguments
args = System.argv()
|> Enum.chunk_every(2)
|> Enum.map(fn 
  [key, value] -> {String.trim_leading(key, "--"), value}
  [key] -> {String.trim_leading(key, "--"), true}  # For flags like --deactivate
  _ -> nil
end)
|> Enum.filter(&(&1 != nil))
|> Map.new()

# Check if we have an identifier
unless Map.has_key?(args, "email") or Map.has_key?(args, "api-key") do
  IO.puts("""
  Error: Must specify either --email or --api-key!
  
  Usage:
    mix run priv/repo/update_customer.exs [IDENTIFIER] [OPTIONS]
  
  Identifiers (one required):
    --email      Customer email address
    --api-key    Customer API key
  
  Options:
    --limit          Update monthly fix limit
    --deactivate     Deactivate the customer
    --activate       Activate the customer
    --reset-usage    Reset current usage to 0
    --name           Update customer name
    --metadata       Update metadata (JSON)
  
  Examples:
    # Update limit
    mix run priv/repo/update_customer.exs --email "customer@example.com" --limit 200
    
    # Deactivate customer
    mix run priv/repo/update_customer.exs --api-key "rsolv_live_xyz" --deactivate
    
    # Reset usage counter
    mix run priv/repo/update_customer.exs --email "customer@example.com" --reset-usage
    
    # Multiple updates
    mix run priv/repo/update_customer.exs --email "customer@example.com" --limit 500 --name "Premium Customer"
  """)
  System.halt(1)
end

# Find the customer
query = from c in "customers",
  select: %{
    id: c.id,
    name: c.name,
    email: c.email,
    api_key: c.api_key,
    monthly_limit: c.monthly_limit,
    current_usage: c.current_usage,
    active: c.active
  }

query = cond do
  Map.has_key?(args, "email") ->
    from c in query, where: c.email == ^args["email"]
  Map.has_key?(args, "api-key") ->
    from c in query, where: c.api_key == ^args["api-key"]
  true ->
    query
end

customer = Repo.one(query)

unless customer do
  identifier = args["email"] || args["api-key"]
  IO.puts("Error: Customer not found with identifier: #{identifier}")
  System.halt(1)
end

# Build updates
updates = %{updated_at: DateTime.utc_now()}

updates = if Map.has_key?(args, "limit") do
  Map.put(updates, :monthly_limit, String.to_integer(args["limit"]))
else
  updates
end

updates = if Map.has_key?(args, "deactivate") do
  Map.put(updates, :active, false)
else
  updates
end

updates = if Map.has_key?(args, "activate") do
  Map.put(updates, :active, true)
else
  updates
end

updates = if Map.has_key?(args, "reset-usage") do
  Map.put(updates, :current_usage, 0)
else
  updates
end

updates = if Map.has_key?(args, "name") do
  Map.put(updates, :name, args["name"])
else
  updates
end

updates = if Map.has_key?(args, "metadata") do
  case Jason.decode(args["metadata"]) do
    {:ok, data} -> Map.put(updates, :metadata, data)
    {:error, _} -> 
      IO.puts("Warning: Invalid JSON metadata, skipping metadata update")
      updates
  end
else
  updates
end

# Check if any updates were specified
if map_size(updates) == 1 do  # Only updated_at
  IO.puts("Error: No updates specified!")
  System.halt(1)
end

# Perform the update
{count, _} = Repo.update_all(
  from(c in "customers", where: c.id == ^customer.id),
  set: Keyword.new(updates)
)

if count == 1 do
  IO.puts("✅ Successfully updated customer!")
  IO.puts("\nCustomer: #{customer.name} (#{customer.email})")
  IO.puts("API Key: #{customer.api_key}")
  
  # Show what was updated
  IO.puts("\nChanges:")
  
  if Map.has_key?(updates, :name) do
    IO.puts("  Name: #{customer.name} → #{updates.name}")
  end
  
  if Map.has_key?(updates, :monthly_limit) do
    IO.puts("  Limit: #{customer.monthly_limit} → #{updates.monthly_limit} fixes/month")
  end
  
  if Map.has_key?(updates, :active) do
    status_before = if customer.active, do: "Active", else: "Inactive"
    status_after = if updates.active, do: "Active", else: "Inactive"
    IO.puts("  Status: #{status_before} → #{status_after}")
  end
  
  if Map.has_key?(updates, :current_usage) do
    IO.puts("  Usage: #{customer.current_usage} → #{updates.current_usage} fixes")
  end
  
  if Map.has_key?(updates, :metadata) do
    IO.puts("  Metadata updated")
  end
else
  IO.puts("Error: Failed to update customer!")
  System.halt(1)
end