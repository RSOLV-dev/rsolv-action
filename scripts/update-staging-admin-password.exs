# Script to update admin user password on staging
# Run with: kubectl exec -n rsolv-staging deployment/staging-rsolv-platform -- bin/rsolv rpc "File.read!(\"/app/scripts/update-staging-admin-password.exs\") |> Code.eval_string()"

alias Rsolv.Customers
alias Rsolv.Customers.Customer

email = "dylan@rsolv.dev"

case Customers.get_customer_by_email(email) do
  nil ->
    IO.puts("Customer not found: #{email}")
    {:error, :not_found}
    
  customer ->
    IO.puts("Found customer: #{customer.email} (ID: #{customer.id})")
    IO.puts("Current is_staff: #{customer.is_staff}")
    
    # Update the password using registration changeset
    changeset = Customer.registration_changeset(customer, %{password: "TestPassword123!"})
    
    case Rsolv.Repo.update(changeset) do
      {:ok, updated} ->
        IO.puts("Successfully updated password for #{updated.email}")
        
        # Verify authentication works
        case Customers.authenticate_customer_by_email_and_password(email, "TestPassword123!") do
          {:ok, _} ->
            IO.puts("Authentication test successful!")
            {:ok, updated}
          {:error, reason} ->
            IO.puts("Authentication test failed: #{inspect(reason)}")
            {:error, reason}
        end
        
      {:error, changeset} ->
        IO.puts("Failed to update password:")
        IO.inspect(changeset.errors)
        {:error, changeset}
    end
end