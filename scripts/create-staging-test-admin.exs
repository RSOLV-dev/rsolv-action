# Script to create a test admin user in staging
# Run with: kubectl exec -n rsolv-staging deployment/staging-rsolv-platform -- bin/rsolv eval "$(cat scripts/create-staging-test-admin.exs)"

alias Rsolv.Customers

# Create the admin user
case Customers.create_customer(%{
  email: "dylan@rsolv.dev",
  name: "Dylan Test Admin",
  is_staff: true,
  password: "testpassword123"
}) do
  {:ok, customer} ->
    IO.puts("Successfully created admin user:")
    IO.puts("  ID: #{customer.id}")
    IO.puts("  Email: #{customer.email}")
    IO.puts("  Name: #{customer.name}")
    IO.puts("  Is Staff: #{customer.is_staff}")
    
  {:error, changeset} ->
    IO.puts("Failed to create admin user:")
    IO.inspect(changeset.errors)
end