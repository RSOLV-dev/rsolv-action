# Script to test feature flag persistence across pods
# Run with: mix run scripts/test_flag_persistence.exs

node_name = node()
IO.puts("Testing on node: #{node_name}")
IO.puts("=========================")

# Get current state
current = FunWithFlags.enabled?(:metrics_dashboard)
IO.puts("Current state: #{current}")

# Toggle it
new_state = not current
IO.puts("Changing to: #{new_state}")

if new_state do
  FunWithFlags.enable(:metrics_dashboard)
else
  FunWithFlags.disable(:metrics_dashboard)
end

# Wait for propagation
Process.sleep(200)

# Check if change persisted
after_change = FunWithFlags.enabled?(:metrics_dashboard)
IO.puts("After change: #{after_change}")
IO.puts("Change successful: #{after_change == new_state}")

# Check connected nodes
connected_nodes = Node.list()
IO.puts("\nConnected nodes: #{inspect(connected_nodes)}")

# Test by checking from different context
IO.puts("\nChecking persistence...")
# Force a fresh lookup by checking in a new process
final_state = Task.async(fn ->
  FunWithFlags.enabled?(:metrics_dashboard)
end) |> Task.await()
IO.puts("Final state check: #{final_state}")
IO.puts("Persistence confirmed: #{final_state == new_state}")