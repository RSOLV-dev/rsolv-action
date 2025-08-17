#!/usr/bin/env elixir

# Clear the FunWithFlags ETS cache

IO.puts("Attempting to clear FunWithFlags cache...")

# Check if the ETS table exists
tables = :ets.all()
IO.puts("Current ETS tables: #{inspect(tables)}")

if :fun_with_flags_cache in tables do
  :ets.delete_all_objects(:fun_with_flags_cache)
  IO.puts("✅ Cleared FunWithFlags cache")
else
  IO.puts("⚠️  FunWithFlags cache table not found")
end

# Try to broadcast cache bust via PubSub
try do
  Phoenix.PubSub.broadcast(
    Rsolv.PubSub,
    "fun_with_flags_cache_bust",
    {:cache_bust, :false_positive_caching, [:all]}
  )
  IO.puts("✅ Broadcast cache bust notification")
rescue
  error ->
    IO.puts("Could not broadcast: #{inspect(error)}")
end