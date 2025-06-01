# Script to list all customers and their API keys
# 
# Usage:
#   mix run priv/repo/list_customers.exs
#   mix run priv/repo/list_customers.exs --active-only
#   mix run priv/repo/list_customers.exs --show-usage

alias RSOLV.Repo
import Ecto.Query

# Parse command line arguments
args = System.argv()
active_only = "--active-only" in args
show_usage = "--show-usage" in args

# Build query
query = from c in "customers",
  select: %{
    id: c.id,
    name: c.name,
    email: c.email,
    api_key: c.api_key,
    monthly_limit: c.monthly_limit,
    current_usage: c.current_usage,
    active: c.active,
    metadata: c.metadata,
    inserted_at: c.inserted_at,
    updated_at: c.updated_at
  },
  order_by: [desc: c.inserted_at]

# Apply active filter if requested
query = if active_only do
  from c in query, where: c.active == true
else
  query
end

# Execute query
customers = Repo.all(query)

# Display results
IO.puts("\n=== RSOLV Customers ===\n")

if customers == [] do
  IO.puts("No customers found.")
else
  customers
  |> Enum.with_index(1)
  |> Enum.each(fn {customer, index} ->
    status = if customer.active, do: "✅ Active", else: "❌ Inactive"
    
    IO.puts("#{index}. #{customer.name} #{status}")
    IO.puts("   Email: #{customer.email}")
    IO.puts("   API Key: #{customer.api_key}")
    
    if show_usage do
      usage_percent = if customer.monthly_limit > 0 do
        Float.round(customer.current_usage / customer.monthly_limit * 100, 1)
      else
        0.0
      end
      
      IO.puts("   Usage: #{customer.current_usage}/#{customer.monthly_limit} fixes (#{usage_percent}%)")
    else
      IO.puts("   Limit: #{customer.monthly_limit} fixes/month")
    end
    
    if customer.metadata && map_size(customer.metadata) > 0 do
      IO.puts("   Metadata: #{inspect(customer.metadata)}")
    end
    
    IO.puts("   Created: #{format_datetime(customer.inserted_at)}")
    IO.puts("")
  end)
  
  IO.puts("Total: #{length(customers)} customers")
  
  if active_only do
    total_count = Repo.one(from c in "customers", select: count(c.id))
    inactive_count = total_count - length(customers)
    if inactive_count > 0 do
      IO.puts("(#{inactive_count} inactive customers hidden)")
    end
  end
end

IO.puts("\nOptions:")
IO.puts("  --active-only  Show only active customers")
IO.puts("  --show-usage   Show current usage statistics")

# Helper function to format datetime
defp format_datetime(nil), do: "Unknown"
defp format_datetime(datetime) do
  datetime
  |> DateTime.to_string()
  |> String.replace("Z", " UTC")
end