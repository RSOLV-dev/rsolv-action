#!/usr/bin/env elixir

# Script to create a test customer with API key in staging

IO.puts("Creating test customer for staging...")

# Start the repo
{:ok, _} = Application.ensure_all_started(:postgrex)
{:ok, _} = Application.ensure_all_started(:ecto_sql)
{:ok, _} = Application.ensure_all_started(:bcrypt_elixir)

case Rsolv.Repo.start_link() do
  {:ok, _pid} -> IO.puts("Started Repo")
  {:error, {:already_started, _pid}} -> IO.puts("Repo already started")
  error -> IO.puts("Failed to start repo: #{inspect(error)}")
end

# Generate a unique test API key
api_key = "staging_test_#{:crypto.strong_rand_bytes(16) |> Base.encode16()}"

# Create a test user first
user_params = %{
  email: "staging-test-#{System.unique_integer([:positive])}@example.com",
  hashed_password: Bcrypt.hash_pwd_salt("password123")
}

case Rsolv.Repo.insert(%Rsolv.Accounts.User{} |> Map.merge(user_params)) do
  {:ok, user} ->
    IO.puts("Created user: #{user.email}")
    
    # Create customer with the API key
    customer_params = %{
      name: "Staging Test Customer",
      email: user.email,
      api_key: api_key,
      plan: "standard",
      monthly_limit: 1000,
      current_usage: 0,
      active: true,
      user_id: user.id
    }
    
    case Rsolv.Repo.insert(%Rsolv.Customers.Customer{} |> Map.merge(customer_params)) do
      {:ok, customer} ->
        IO.puts("✅ Created customer: #{customer.name}")
        IO.puts("📋 API Key: #{api_key}")
        IO.puts("")
        IO.puts("Use this API key for testing:")
        IO.puts("export STAGING_API_KEY=\"#{api_key}\"")
        
        # Create a forge account for the customer
        forge_params = %{
          customer_id: customer.id,
          forge_type: :github,
          namespace: "staging-test-org",
          verified_at: DateTime.utc_now()
        }
        
        case Rsolv.Repo.insert(%Rsolv.Phases.ForgeAccount{} |> Map.merge(forge_params)) do
          {:ok, forge} ->
            IO.puts("✅ Created forge account: #{forge.namespace}")
          error ->
            IO.puts("Warning: Could not create forge account: #{inspect(error)}")
        end
        
      error ->
        IO.puts("❌ Failed to create customer: #{inspect(error)}")
    end
    
  error ->
    IO.puts("❌ Failed to create user: #{inspect(error)}")
end