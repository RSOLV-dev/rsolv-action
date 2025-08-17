#!/usr/bin/env elixir

# Script to toggle the false positive caching feature flag
# Usage: mix run scripts/toggle_cache_feature.exs [enable|disable|status]

alias FunWithFlags, as: Flags

action = System.argv() |> List.first() || "status"

case action do
  "enable" ->
    case Flags.enable(:false_positive_caching) do
      {:ok, true} ->
        IO.puts("✅ False positive caching ENABLED")
        IO.puts("The new caching system is now active for all validation requests")
      error ->
        IO.puts("❌ Failed to enable caching: #{inspect(error)}")
    end
    
  "disable" ->
    case Flags.disable(:false_positive_caching) do
      {:ok, false} ->
        IO.puts("🚫 False positive caching DISABLED")
        IO.puts("Using the standard validation controller without caching")
      error ->
        IO.puts("❌ Failed to disable caching: #{inspect(error)}")
    end
    
  "status" ->
    case Flags.enabled?(:false_positive_caching) do
      {:ok, true} ->
        IO.puts("📊 False positive caching is currently ENABLED")
        
        # Get cache statistics
        query = """
        SELECT 
          COUNT(*) as total_entries,
          COUNT(CASE WHEN invalidated_at IS NULL THEN 1 END) as active_entries,
          COUNT(CASE WHEN invalidated_at IS NOT NULL THEN 1 END) as invalidated_entries,
          AVG(EXTRACT(EPOCH FROM (ttl_expires_at - cached_at)) / 86400)::int as avg_ttl_days
        FROM cached_validations
        """
        
        case Rsolv.Repo.query(query) do
          {:ok, result} ->
            [[total, active, invalidated, avg_ttl]] = result.rows
            IO.puts("")
            IO.puts("Cache Statistics:")
            IO.puts("  Total entries: #{total}")
            IO.puts("  Active entries: #{active}")
            IO.puts("  Invalidated entries: #{invalidated}")
            IO.puts("  Average TTL: #{avg_ttl || 90} days")
          _ ->
            IO.puts("Unable to fetch cache statistics")
        end
        
      {:ok, false} ->
        IO.puts("🚫 False positive caching is currently DISABLED")
        
      error ->
        IO.puts("❓ Unable to determine caching status: #{inspect(error)}")
    end
    
  _ ->
    IO.puts("Usage: mix run scripts/toggle_cache_feature.exs [enable|disable|status]")
    IO.puts("")
    IO.puts("Commands:")
    IO.puts("  enable  - Enable the false positive caching feature")
    IO.puts("  disable - Disable the false positive caching feature")
    IO.puts("  status  - Show current status and cache statistics")
end