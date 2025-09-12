# Simple script to create test admin user in staging
# Run with: kubectl exec -n rsolv-staging deployment/staging-rsolv-platform -- bin/rsolv rpc "File.read!(\"/app/scripts/create-staging-test-admin-simple.exs\") |> Code.eval_string()"

alias Rsolv.Customers

email = "dylan@rsolv.dev"

# Check if user already exists
case Customers.get_customer_by_email(email) do
  nil ->
    # Create new admin user with password
    attrs = %{
      email: email,
      name: "Dylan Test Admin",
      is_staff: true,
      password: "testpassword123"
    }
    
    case Customers.create_customer(attrs) do
      {:ok, customer} ->
        IO.puts("Created admin user: #{customer.email} (ID: #{customer.id})")
        {:ok, customer}
        
      {:error, changeset} ->
        IO.puts("Failed to create admin user:")
        IO.inspect(changeset.errors)
        {:error, changeset}
    end
    
  customer ->
    IO.puts("Admin user already exists: #{customer.email} (ID: #{customer.id})")
    
    # Ensure is_staff is true
    if not customer.is_staff do
      case Customers.update_customer(customer, %{is_staff: true}) do
        {:ok, updated} ->
          IO.puts("Updated user to staff status")
          {:ok, updated}
        {:error, changeset} ->
          IO.puts("Failed to update staff status")
          {:error, changeset}
      end
    else
      {:ok, customer}
    end
end