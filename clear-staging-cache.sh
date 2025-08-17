#!/bin/bash

echo "Clearing all cached validations in staging..."

kubectl exec deployment/staging-rsolv-platform -n rsolv-staging -- /app/bin/rsolv rpc '
alias Rsolv.Repo
alias Rsolv.ValidationCache.CachedValidation

{deleted, _} = Repo.delete_all(CachedValidation)
IO.puts("Deleted #{deleted} cached validations")
deleted
'

echo "Cache cleared!"