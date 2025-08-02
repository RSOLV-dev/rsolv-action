# Enable draft blog posts feature flag
# This script connects to the running application
require Logger

# Since we're in dev mode, just set the flag directly
try do
  # Enable the flag
  result = FunWithFlags.enable(:display_draft_blog_posts)
  Logger.info("Flag enable result: #{inspect(result)}")
  
  # Also ensure blog flag is enabled
  FunWithFlags.enable(:blog)
  Logger.info("Blog flag enabled")
  
  # Verify
  draft_enabled = FunWithFlags.enabled?(:display_draft_blog_posts)
  blog_enabled = FunWithFlags.enabled?(:blog)
  
  Logger.info("Draft posts enabled: #{draft_enabled}")
  Logger.info("Blog enabled: #{blog_enabled}")
rescue
  e ->
    Logger.error("Error enabling flags: #{inspect(e)}")
end