# Script to enable display_draft_blog_posts feature flag for local development
# Run with: docker compose exec rsolv-api mix run scripts/enable_draft_blog_posts.exs

IO.puts("Enabling display_draft_blog_posts feature flag...")

# Enable the flag
case FunWithFlags.enable(:display_draft_blog_posts) do
  {:ok, true} ->
    IO.puts("✓ Successfully enabled display_draft_blog_posts flag")
  {:ok, false} ->
    IO.puts("Flag was already enabled")
  error ->
    IO.puts("Error enabling flag: #{inspect(error)}")
end

# Verify it's enabled
enabled = FunWithFlags.enabled?(:display_draft_blog_posts)
IO.puts("\nCurrent state - display_draft_blog_posts enabled: #{enabled}")

# Also ensure blog flag is enabled
blog_enabled = FunWithFlags.enabled?(:blog)
if not blog_enabled do
  IO.puts("\nEnabling blog feature flag as well...")
  FunWithFlags.enable(:blog)
  IO.puts("✓ Blog feature enabled")
end

IO.puts("\nDraft blog posts should now be visible at http://localhost:4001/blog")