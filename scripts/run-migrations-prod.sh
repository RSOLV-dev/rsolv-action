#!/bin/bash
set -e

echo "🔄 Running database migrations in production..."

# The most idiomatic way - run migrations directly on a running pod
POD=$(kubectl get pod -l app=rsolv-api -o jsonpath="{.items[0].metadata.name}")

if [ -z "$POD" ]; then
  echo "❌ No RSOLV API pod found!"
  exit 1
fi

echo "📦 Using pod: $POD"
echo "⏳ Running migrations..."

# Run the migration command
kubectl exec $POD -- bin/rsolv_api eval "RsolvApi.Release.migrate()"

if [ $? -eq 0 ]; then
  echo "✅ Migrations completed successfully!"
else
  echo "❌ Migrations failed!"
  exit 1
fi