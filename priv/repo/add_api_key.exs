# Script to manually add API keys to the RSOLV database
# 
# Usage:
#   mix run priv/repo/add_api_key.exs --name "Customer Name" --email "customer@example.com" --api-key "custom_api_key" --limit 100
#
# Or with defaults:
#   mix run priv/repo/add_api_key.exs --name "Customer Name" --email "customer@example.com"
#
# This will generate a random API key if not provided

alias RSOLV.Repo
import Ecto.Query

# Parse command line arguments
args = System.argv()
|> Enum.chunk_every(2)
|> Enum.map(fn 
  [key, value] -> {String.trim_leading(key, "--"), value}
  _ -> nil
end)
|> Enum.filter(&(&1 != nil))
|> Map.new()

# Validate required arguments
unless Map.has_key?(args, "name") and Map.has_key?(args, "email") do
  IO.puts("""
  Error: Missing required arguments!
  
  Usage:
    mix run priv/repo/add_api_key.exs --name "Customer Name" --email "customer@example.com" [OPTIONS]
  
  Required:
    --name       Customer name
    --email      Customer email address
  
  Optional:
    --api-key    Custom API key (default: auto-generated)
    --limit      Monthly fix limit (default: 100)
    --metadata   JSON metadata (default: {})
  
  Examples:
    # Generate random API key with defaults
    mix run priv/repo/add_api_key.exs --name "Acme Corp" --email "tech@acme.com"
    
    # Custom API key and limit
    mix run priv/repo/add_api_key.exs --name "Beta User" --email "beta@example.com" --api-key "rsolv_beta_xyz123" --limit 50
    
    # With metadata
    mix run priv/repo/add_api_key.exs --name "Enterprise" --email "ent@corp.com" --metadata '{"plan":"enterprise","contact":"John"}'
  """)
  System.halt(1)
end

# Generate API key if not provided
api_key = Map.get(args, "api-key") || generate_api_key()

# Parse optional parameters
monthly_limit = case Map.get(args, "limit") do
  nil -> 100
  limit_str -> String.to_integer(limit_str)
end

metadata = case Map.get(args, "metadata") do
  nil -> %{}
  json_str -> 
    case Jason.decode(json_str) do
      {:ok, data} -> data
      {:error, _} -> 
        IO.puts("Warning: Invalid JSON metadata, using empty metadata")
        %{}
    end
end

# Check if customer already exists
existing_customer = Repo.one(
  from c in "customers",
  where: c.email == ^args["email"],
  select: %{id: c.id, name: c.name, api_key: c.api_key}
)

if existing_customer do
  IO.puts("""
  Error: Customer with email #{args["email"]} already exists!
  
  Customer: #{existing_customer.name}
  API Key: #{existing_customer.api_key}
  
  To update this customer, please use the database directly or create a separate update script.
  """)
  System.halt(1)
end

# Check if API key already exists
existing_key = Repo.one(
  from c in "customers",
  where: c.api_key == ^api_key,
  select: %{id: c.id, name: c.name, email: c.email}
)

if existing_key do
  IO.puts("""
  Error: API key already exists for another customer!
  
  Customer: #{existing_key.name} (#{existing_key.email})
  
  Please choose a different API key.
  """)
  System.halt(1)
end

# Insert the new customer
{:ok, result} = Repo.insert_all("customers",
  [
    %{
      name: args["name"],
      email: args["email"],
      api_key: api_key,
      monthly_limit: monthly_limit,
      current_usage: 0,
      active: true,
      metadata: metadata,
      inserted_at: DateTime.utc_now(),
      updated_at: DateTime.utc_now()
    }
  ],
  returning: [:id, :name, :email, :api_key, :monthly_limit]
)

[customer] = result

IO.puts("""
✅ Successfully created customer!

Customer Details:
  Name: #{customer.name}
  Email: #{customer.email}
  API Key: #{customer.api_key}
  Monthly Limit: #{customer.monthly_limit} fixes

Save this API key securely! It cannot be retrieved later.

To test the API key:
  curl -X POST https://api.rsolv.dev/api/v1/credentials/exchange \\
    -H "Content-Type: application/json" \\
    -d '{"api_key": "#{customer.api_key}", "providers": ["anthropic"]}'
""")

# Helper function to generate random API key
defp generate_api_key do
  prefix = "rsolv_live_"
  random_part = :crypto.strong_rand_bytes(16) |> Base.url_encode64(padding: false)
  prefix <> random_part
end