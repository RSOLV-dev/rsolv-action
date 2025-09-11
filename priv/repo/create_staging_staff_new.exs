# Create a staff user for staging admin UI testing
alias Rsolv.Customers

# Create the staff user using the new register_customer function
case Customers.register_customer(%{
  email: "admin@rsolv.dev",
  password: "AdminPass123!",
  name: "Admin User",
  is_staff: true,
  admin_level: "full",
  monthly_limit: 1000
}) do
  {:ok, customer} ->
    IO.puts("✅ Staff user created successfully!")
    IO.puts("Email: #{customer.email}")
    IO.puts("Name: #{customer.name}")
    IO.puts("Staff: #{customer.is_staff}")
    IO.puts("Admin Level: #{customer.admin_level}")
    IO.puts("ID: #{customer.id}")
  
  {:error, changeset} ->
    IO.puts("❌ Failed to create staff user:")
    IO.inspect(changeset.errors)
    
    # If email is taken, that's okay for our purposes
    if Keyword.has_key?(changeset.errors, :email) do
      IO.puts("Note: Email already exists - user may already be created")
    end
end