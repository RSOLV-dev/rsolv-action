# Script to create an API key for the audit tool
# Run with: mix run scripts/create_audit_tool_key.exs

defmodule CreateAuditToolKey do
  alias Rsolv.Repo
  require Logger
  
  def run do
    IO.puts("Creating API key for audit tool...")
    
    # Generate a unique API key
    api_key = generate_api_key("audit")
    
    # First, create or get a system user using direct SQL
    {:ok, result} = Repo.query("SELECT id FROM users WHERE email = $1", ["system@rsolv.dev"])
    
    system_user_id = if result.num_rows == 0 do
      # Create system user
      {:ok, result} = Repo.query(
        """
        INSERT INTO users (email, hashed_password, confirmed_at, inserted_at, updated_at)
        VALUES ($1, $2, $3, $4, $5)
        RETURNING id
        """,
        [
          "system@rsolv.dev",
          Bcrypt.hash_pwd_salt("system_password_#{:rand.uniform(999999)}"),
          DateTime.utc_now(),
          DateTime.utc_now(),
          DateTime.utc_now()
        ]
      )
      [[id]] = result.rows
      IO.puts("Created system user with ID: #{id}")
      id
    else
      [[id]] = result.rows
      IO.puts("Using existing system user ID: #{id}")
      id
    end
    
    # Create the audit tool customer
    key_data = %{
      name: "RSOLV Audit Tool",
      email: "audit@rsolv.dev",
      api_key: api_key,
      monthly_limit: 100000,
      plan: "internal"
    }
    
    # Check if already exists
    {:ok, result} = Repo.query(
      "SELECT id FROM customers WHERE api_key = $1",
      [key_data.api_key]
    )
    
    if result.num_rows == 0 do
      # Insert new customer
      {:ok, _} = Repo.query(
        """
        INSERT INTO customers (name, email, api_key, monthly_limit, current_usage, active, 
                               metadata, plan, user_id, inserted_at, updated_at)
        VALUES ($1, $2, $3, $4, $5, $6, $7::jsonb, $8, $9, $10, $11)
        """,
        [
          key_data.name,
          key_data.email,
          key_data.api_key,
          key_data.monthly_limit,
          0,  # current_usage
          true,  # active
          Jason.encode!(%{type: "audit", purpose: "internal security auditing"}),  # metadata as JSON
          key_data.plan,
          system_user_id,
          DateTime.utc_now(),
          DateTime.utc_now()
        ]
      )
      IO.puts("✓ Created customer: #{key_data.name}")
      
      # Get the customer ID
      {:ok, result} = Repo.query("SELECT id FROM customers WHERE api_key = $1", [key_data.api_key])
      [[customer_id]] = result.rows
      
      # Also create an API key record
      {:ok, _} = Repo.query(
        """
        INSERT INTO api_keys (key, name, customer_id, permissions, active, inserted_at, updated_at)
        VALUES ($1, $2, $3, $4, $5, $6, $7)
        """,
        [
          key_data.api_key,
          "Audit Tool API Key",
          customer_id,
          ["all"],
          true,
          DateTime.utc_now(),
          DateTime.utc_now()
        ]
      )
      IO.puts("  ✓ Created API key record")
      
      IO.puts("\n=== API Key Created Successfully ===")
      IO.puts("API Key: #{api_key}")
      IO.puts("Name: #{key_data.name}")
      IO.puts("Email: #{key_data.email}")
      IO.puts("Monthly Limit: #{key_data.monthly_limit}")
      IO.puts("Plan: #{key_data.plan}")
      IO.puts("\nStore this API key securely!")
      
    else
      IO.puts("⚠ Customer already exists for this API key")
    end
    
    IO.puts("\nTesting API key...")
    test_api_key(api_key)
  end
  
  defp generate_api_key(prefix) do
    random_string = :crypto.strong_rand_bytes(32) |> Base.encode16(case: :lower)
    "#{prefix}_#{random_string}"
  end
  
  defp test_api_key(api_key) do
    customer = Rsolv.Accounts.get_customer_by_api_key(api_key)
    if customer do
      IO.puts("✓ API key is valid and working!")
      IO.puts("  Customer: #{inspect(Map.get(customer, :name))}")
    else
      IO.puts("✗ API key validation failed!")
    end
  end
end

CreateAuditToolKey.run()