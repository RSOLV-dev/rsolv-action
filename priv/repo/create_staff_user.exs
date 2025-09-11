# Create a staff user for admin UI access
# Usage: mix run priv/repo/create_staff_user.exs [email] [password] [name]
#
# Default values:
#   email: admin@rsolv.dev
#   password: AdminPass123!
#   name: Admin User
#
# Example:
#   mix run priv/repo/create_staff_user.exs
#   mix run priv/repo/create_staff_user.exs john@rsolv.dev MyPass123! "John Doe"

alias Rsolv.Customers

# Parse command line arguments
[email, password, name] = case System.argv() do
  [] -> 
    ["admin@rsolv.dev", "AdminPass123!", "Admin User"]
  [email] -> 
    [email, "AdminPass123!", "Admin User"]
  [email, password] -> 
    [email, password, "Admin User"]
  [email, password, name | _rest] -> 
    [email, password, name]
end

IO.puts("Creating staff user with:")
IO.puts("  Email: #{email}")
IO.puts("  Name: #{name}")
IO.puts("")

# First check if the user already exists
case Customers.get_customer_by_email(email) do
  nil ->
    # Create the staff user using register_customer
    case Customers.register_customer(%{
      email: email,
      password: password,
      name: name,
      is_staff: true,
      admin_level: "full",
      monthly_limit: 1000
    }) do
      {:ok, customer} ->
        IO.puts("✅ Staff user created successfully!")
        IO.puts("")
        IO.puts("Details:")
        IO.puts("  ID: #{customer.id}")
        IO.puts("  Email: #{customer.email}")
        IO.puts("  Name: #{customer.name}")
        IO.puts("  Staff: #{customer.is_staff}")
        IO.puts("  Admin Level: #{customer.admin_level}")
        IO.puts("")
        IO.puts("You can now login at: /admin/login")
      
      {:error, changeset} ->
        IO.puts("❌ Failed to create staff user:")
        IO.inspect(changeset.errors, pretty: true)
    end
    
  existing ->
    IO.puts("User with email #{email} already exists.")
    IO.puts("")
    
    # Check if it's already a staff user
    if existing.is_staff do
      IO.puts("✅ User is already a staff member!")
      IO.puts("")
      IO.puts("Current details:")
      IO.puts("  ID: #{existing.id}")
      IO.puts("  Email: #{existing.email}")
      IO.puts("  Name: #{existing.name}")
      IO.puts("  Staff: #{existing.is_staff}")
      IO.puts("  Admin Level: #{existing.admin_level}")
    else
      IO.puts("Updating existing user to staff member...")
      
      # Update existing user to be staff
      case Customers.update_customer(existing, %{
        is_staff: true,
        admin_level: "full",
        name: name
      }) do
        {:ok, customer} ->
          IO.puts("✅ User upgraded to staff successfully!")
          IO.puts("")
          IO.puts("Updated details:")
          IO.puts("  ID: #{customer.id}")
          IO.puts("  Email: #{customer.email}")
          IO.puts("  Name: #{customer.name}")
          IO.puts("  Staff: #{customer.is_staff}")
          IO.puts("  Admin Level: #{customer.admin_level}")
          IO.puts("")
          IO.puts("You can now login at: /admin/login")
        
        {:error, changeset} ->
          IO.puts("❌ Failed to update user to staff:")
          IO.inspect(changeset.errors, pretty: true)
      end
    end
end