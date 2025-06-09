#!/bin/bash

# Direct pattern loading script
POD=$(kubectl get pods -l app=rsolv-api -o jsonpath='{.items[0].metadata.name}')

echo "🔄 Loading all security patterns into production..."

# Copy the seed file to the pod first
echo "📤 Copying seed file to pod..."
kubectl cp /Users/dylan/dev/rsolv/RSOLV-api/priv/repo/seeds/load_security_patterns.exs $POD:/tmp/load_security_patterns.exs

# Run the seed file
echo -e "\n📥 Loading patterns from seed file..."
kubectl exec $POD -- /app/bin/rsolv_api rpc "File.read!('/tmp/load_security_patterns.exs') |> Code.eval_string()"

# Check final count
echo -e "\n✅ Checking final pattern count..."
kubectl exec $POD -- /app/bin/rsolv_api rpc "RsolvApi.Repo.aggregate(RsolvApi.Security.SecurityPattern, :count) |> IO.inspect(label: 'Total patterns')"