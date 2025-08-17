#!/bin/bash

echo "Enabling false positive caching feature flag in staging..."

# Get a pod name
POD=$(kubectl get pods -n rsolv-staging -l app.kubernetes.io/name=staging-rsolv-platform -o jsonpath='{.items[0].metadata.name}')

if [ -z "$POD" ]; then
    echo "Error: No staging pod found"
    exit 1
fi

echo "Using pod: $POD"

# Enable the feature flag using remote console
kubectl exec -n rsolv-staging $POD -- /app/bin/rsolv remote << 'EOF'
# Enable the feature flag
{:ok, _} = FunWithFlags.enable(:false_positive_caching)

# Verify it's enabled
case FunWithFlags.enabled?(:false_positive_caching) do
  {:ok, true} -> 
    IO.puts("✅ Feature flag enabled successfully")
  _ -> 
    IO.puts("❌ Failed to enable feature flag")
end

# Check cache table exists
tables = :ets.all()
if :cached_validations in tables do
  IO.puts("✅ Cache table exists")
else
  IO.puts("ℹ️  Cache table will be created on first use")
end

# Exit remote console
:ok
EOF

echo ""
echo "Feature flag status check:"
kubectl exec -n rsolv-staging $POD -- /app/bin/rsolv eval 'case Rsolv.Repo.query("SELECT enabled FROM fun_with_flags_toggles WHERE flag_name = '"'"'false_positive_caching'"'"'") do {:ok, %{rows: [[true]]}} -> IO.puts("✅ Flag is ENABLED in database"); {:ok, %{rows: [[false]]}} -> IO.puts("❌ Flag is DISABLED in database"); _ -> IO.puts("⚠️  Flag not found in database") end'