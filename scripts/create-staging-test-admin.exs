# Script to create a test admin user in staging
# Run with: kubectl exec -n rsolv-staging deployment/staging-rsolv-platform -- bin/rsolv eval "$(cat scripts/create-staging-test-admin.exs)"

alias Rsolv.Customers

# First try to get existing customer
existing = Customers.get_customer_by_email("dylan@rsolv.dev")

case existing do
  nil ->
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
    
  customer ->
    IO.puts("Admin user already exists:")
    IO.puts("  ID: #{customer.id}")
    IO.puts("  Email: #{customer.email}")
    IO.puts("  Name: #{customer.name}")
    IO.puts("  Is Staff: #{customer.is_staff}")
    
    # Update to ensure is_staff is true
    if not customer.is_staff do
      case Customers.update_customer(customer, %{is_staff: true}) do
        {:ok, updated} ->
          IO.puts("Updated user to be staff")
        {:error, _} ->
          IO.puts("Failed to update user to staff")
      end
    end
end