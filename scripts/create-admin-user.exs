#!/usr/bin/env elixir

# Script to create or update admin user for staging/production
# Usage: bin/rsolv eval scripts/create-admin-user.exs

alias Rsolv.Repo
alias Rsolv.Customers.Customer

email = "admin@rsolv.dev"
password = "AdminP@ss123!"

# Generate a proper bcrypt hash
password_hash = Bcrypt.hash_pwd_salt(password)

# Check if user exists
case Repo.get_by(Customer, email: email) do
  nil ->
    # Create new admin user
    %Customer{}
    |> Customer.changeset(%{
      name: "Admin User",
      email: email,
      password_hash: password_hash,
      is_staff: true,
      active: true,
      monthly_limit: 10000,
      current_usage: 0
    })
    |> Repo.insert!()
    
    IO.puts("Created admin user: #{email}")
    
  customer ->
    # Update existing user
    customer
    |> Customer.changeset(%{
      password_hash: password_hash,
      is_staff: true,
      active: true
    })
    |> Repo.update!()
    
    IO.puts("Updated admin user: #{email}")
end

# Verify the user
admin = Repo.get_by!(Customer, email: email)
IO.puts("Admin user verified:")
IO.puts("  ID: #{admin.id}")
IO.puts("  Email: #{admin.email}")
IO.puts("  Name: #{admin.name}")
IO.puts("  Is Staff: #{admin.is_staff}")
IO.puts("  Active: #{admin.active}")
IO.puts("  Has Password: #{admin.password_hash != nil}")

# Test password verification
if Bcrypt.verify_pass(password, admin.password_hash) do
  IO.puts("  Password verification: ✓ SUCCESS")
else
  IO.puts("  Password verification: ✗ FAILED")
end