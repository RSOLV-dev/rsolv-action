#!/usr/bin/env elixir
# Script to create test admin user for admin functionality testing
# Run via: kubectl exec -n rsolv-staging deployment/staging-rsolv-platform -- bin/rsolv eval "$(cat scripts/create-test-admin.exs)"

alias Rsolv.Repo
alias Rsolv.Customers
alias Rsolv.Customers.Customer

IO.puts("Creating test admin user for admin functionality testing...")

# Create admin@rsolv.com with the password from the test
admin_result = 
  case Repo.get_by(Customer, email: "admin@rsolv.com") do
    nil ->
      Customers.register_customer(%{
        name: "Test Admin",
        email: "admin@rsolv.com",
        password: "AdminP@ss123!",
        is_staff: true,
        admin_level: "full",
        active: true,
        metadata: %{
          "type" => "internal",
          "purpose" => "admin_testing"
        }
      })
    existing ->
      IO.puts("  Admin user already exists, updating...")
      Customers.update_customer(existing, %{
        is_staff: true,
        admin_level: "full",
        active: true
      })
  end

case admin_result do
  {:ok, admin} ->
    IO.puts("  ✓ Admin user created/updated: admin@rsolv.com")
    IO.puts("  ✓ Password: AdminP@ss123!")
    IO.puts("  ✓ is_staff: #{admin.is_staff}")
    IO.puts("  ✓ active: #{admin.active}")
    
  {:error, changeset} ->
    IO.puts("  ✗ Failed to create/update admin user:")
    IO.inspect(changeset.errors)
end