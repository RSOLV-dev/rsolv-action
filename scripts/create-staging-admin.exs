#!/usr/bin/env elixir
# Create admin user in staging database
# Run this script with: kubectl exec -n rsolv-staging deployment/staging-rsolv-platform -- /app/bin/rsolv rpc 'File.read!("/tmp/create-admin.exs") |> Code.eval_string()'

alias Rsolv.Customers

# Check if admin user already exists
case Customers.get_customer_by_email("admin@rsolv.dev") do
  nil ->
    # Create the admin user
    attrs = %{
      name: "Admin User",
      email: "admin@rsolv.dev", 
      password: "AdminP@ss123!",
      is_staff: true,
      admin_level: "full",
      active: true,
      monthly_limit: 1000000
    }
    
    case Customers.register_customer(attrs) do
      {:ok, customer} ->
        IO.puts("Successfully created admin user:")
        IO.inspect(customer, label: "Admin User")
        IO.puts("\nCredentials:")
        IO.puts("Email: admin@rsolv.dev")
        IO.puts("Password: AdminP@ss123!")
      
      {:error, changeset} ->
        IO.puts("Failed to create admin user:")
        IO.inspect(changeset.errors)
    end
    
  customer ->
    IO.puts("Admin user already exists:")
    IO.inspect(customer, label: "Existing Admin")
    
    # Update password to ensure it's correct
    case Customers.update_customer_password(customer, %{password: "AdminP@ss123!"}) do
      {:ok, updated} ->
        IO.puts("\nPassword updated successfully for admin@rsolv.dev")
        IO.puts("Use password: AdminP@ss123!")
      
      {:error, changeset} ->
        IO.puts("Failed to update password:")
        IO.inspect(changeset.errors)
    end
end