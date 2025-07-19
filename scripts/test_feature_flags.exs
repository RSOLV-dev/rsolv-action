# Script to test feature flag cache invalidation
# Run with: mix run scripts/test_feature_flags.exs

flag_name = :metrics_dashboard

IO.puts("Testing feature flag cache invalidation for: #{flag_name}")
IO.puts("=====================================")

# Get current state
current = FunWithFlags.enabled?(flag_name)
IO.puts("Current state: #{current}")

# Get flag details
{:ok, flag} = FunWithFlags.get_flag(flag_name)
IO.puts("Current flag details:")
IO.inspect(flag)

# Change it
new_state = not current
IO.puts("\nChanging flag to: #{new_state}")

if new_state do
  FunWithFlags.enable(flag_name)
else
  FunWithFlags.disable(flag_name)
end

# Give it a moment to propagate
Process.sleep(100)

# Check the state
after_change = FunWithFlags.enabled?(flag_name)
IO.puts("\nAfter change: #{after_change}")
IO.puts("Change successful: #{after_change == new_state}")

# Get updated flag details
{:ok, updated_flag} = FunWithFlags.get_flag(flag_name)
IO.puts("\nUpdated flag details:")
IO.inspect(updated_flag)

# Test clearing cache manually
IO.puts("\nTesting cache clearing...")
FunWithFlags.Cache.flush()
after_flush = FunWithFlags.enabled?(flag_name)
IO.puts("After cache flush: #{after_flush}")

# Restore original state
IO.puts("\nRestoring original state: #{current}")
if current do
  FunWithFlags.enable(flag_name)
else
  FunWithFlags.disable(flag_name)
end

Process.sleep(100)
final_state = FunWithFlags.enabled?(flag_name)
IO.puts("Final state: #{final_state}")