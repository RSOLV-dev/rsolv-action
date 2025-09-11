# Create a staff user for staging admin UI testing
alias Rsolv.Customers

# First check if the user already exists
case Customers.get_customer_by_email("admin@rsolv.dev") do
  nil ->
    # Create the staff user
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
      
      {:error, changeset} ->
        IO.puts("❌ Failed to create staff user:")
        IO.inspect(changeset.errors)
    end
    
  existing ->
    # Update existing user to be staff
    case Customers.update_customer(existing, %{
      is_staff: true,
      admin_level: "full",
      name: "Admin User"
    }) do
      {:ok, customer} ->
        IO.puts("✅ Existing user updated to staff!")
        IO.puts("Email: #{customer.email}")
        IO.puts("Name: #{customer.name}")
        IO.puts("Staff: #{customer.is_staff}")
        IO.puts("Admin Level: #{customer.admin_level}")
      
      {:error, changeset} ->
        IO.puts("❌ Failed to update user to staff:")
        IO.inspect(changeset.errors)
    end
end