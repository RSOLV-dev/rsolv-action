#!/usr/bin/env elixir
# Script to create admin users directly in staging
# Can be run via: kubectl exec -n rsolv-staging deployment/staging-rsolv-platform -- bin/rsolv eval "File.read!(\"/app/scripts/create-staging-admin-users.exs\") |> Code.eval_string()"

alias Rsolv.Repo
alias Rsolv.Customers
alias Rsolv.Customers.{Customer, ApiKey}

IO.puts("Creating admin users for staging environment...")

# Create admin user
admin_result = 
  case Repo.get_by(Customer, email: "admin@rsolv.dev") do
    nil ->
      Customers.register_customer(%{
        name: "RSOLV Admin",
        email: "admin@rsolv.dev",
        password: "AdminP@ssw0rd2025!",
        is_staff: true,
        admin_level: "full",
        metadata: %{
          "type" => "internal",
          "purpose" => "administration"
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
    IO.puts("  ✓ Admin user created/updated: admin@rsolv.dev")
    
    # Create API key if it doesn't exist
    unless Repo.get_by(ApiKey, customer_id: admin.id, name: "Admin API Key") do
      {:ok, key} = Customers.create_api_key(admin, %{
        name: "Admin API Key",
        key: "rsolv_admin_key_staging_2025",
        active: true
      })
      IO.puts("    API Key: #{key.key}")
    end
    
  {:error, changeset} ->
    IO.puts("  ✗ Failed to create/update admin user:")
    IO.inspect(changeset.errors)
end

# Create staff user
staff_result = 
  case Repo.get_by(Customer, email: "staff@rsolv.dev") do
    nil ->
      Customers.register_customer(%{
        name: "RSOLV Staff",
        email: "staff@rsolv.dev", 
        password: "StaffP@ssw0rd2025!",
        is_staff: true,
        admin_level: "limited",
        metadata: %{
          "type" => "internal",
          "purpose" => "support"
        }
      })
    existing ->
      IO.puts("  Staff user already exists, updating...")
      Customers.update_customer(existing, %{
        is_staff: true,
        admin_level: "limited",
        active: true
      })
  end

case staff_result do
  {:ok, staff} ->
    IO.puts("  ✓ Staff user created/updated: staff@rsolv.dev")
    
    unless Repo.get_by(ApiKey, customer_id: staff.id, name: "Staff API Key") do
      {:ok, key} = Customers.create_api_key(staff, %{
        name: "Staff API Key",
        key: "rsolv_staff_key_staging_2025",
        active: true
      })
      IO.puts("    API Key: #{key.key}")
    end
    
  {:error, changeset} ->
    IO.puts("  ✗ Failed to create/update staff user:")
    IO.inspect(changeset.errors)
end

# Create test customer
test_result = 
  case Repo.get_by(Customer, email: "test@example.com") do
    nil ->
      Customers.register_customer(%{
        name: "Test Customer",
        email: "test@example.com",
        password: "TestP@ssw0rd2025!",
        trial_fixes_limit: 100,
        subscription_plan: "trial",
        metadata: %{
          "type" => "test",
          "purpose" => "integration_testing"
        }
      })
    existing ->
      IO.puts("  Test customer already exists, updating...")
      Customers.update_customer(existing, %{
        active: true,
        trial_fixes_limit: 100
      })
  end

case test_result do
  {:ok, test_customer} ->
    IO.puts("  ✓ Test customer created/updated: test@example.com")
    
    unless Repo.get_by(ApiKey, customer_id: test_customer.id, key: "rsolv_test_key_123") do
      {:ok, key} = Customers.create_api_key(test_customer, %{
        name: "Test API Key",
        key: "rsolv_test_key_123",
        active: true
      })
      IO.puts("    API Key: #{key.key}")
    end
    
  {:error, changeset} ->
    IO.puts("  ✗ Failed to create/update test customer:")
    IO.inspect(changeset.errors)
end

IO.puts("\nQuick reference:")
IO.puts("  Admin:      admin@rsolv.dev / AdminP@ssw0rd2025!")
IO.puts("  Staff:      staff@rsolv.dev / StaffP@ssw0rd2025!")
IO.puts("  Test:       test@example.com / TestP@ssw0rd2025!")
IO.puts("\nAll passwords follow RFC-049 security requirements")