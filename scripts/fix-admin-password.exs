alias Rsolv.Repo
alias Rsolv.Customers.Customer

email = "admin@rsolv.dev"
password = "AdminP@ss123!"

# Generate new password hash
password_hash = Bcrypt.hash_pwd_salt(password)

# Update the admin user
case Repo.get_by(Customer, email: email) do
  nil ->
    IO.puts("Admin user not found")
  
  customer ->
    customer
    |> Ecto.Changeset.change(%{
      password_hash: password_hash,
      is_staff: true,
      active: true
    })
    |> Repo.update!()
    
    IO.puts("Admin user updated successfully")
    IO.puts("Email: #{email}")
    IO.puts("Password: #{password}")
    
    # Verify the password works
    if Bcrypt.verify_pass(password, password_hash) do
      IO.puts("Password verification: PASSED")
    else
      IO.puts("Password verification: FAILED")
    end
end