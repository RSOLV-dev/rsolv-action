# Script to create an API key for phase data testing
# Run with: mix run scripts/create_phase_test_key.exs

defmodule CreatePhaseTestKey do
  alias Rsolv.Repo
  require Logger
  
  def run do
    IO.puts("Creating API key for phase data testing...")
    
    # Generate a unique API key
    api_key = generate_api_key("phase_test")
    
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
    
    # Create the phase test customer
    key_data = %{
      name: "Phase Data Test Account",
      email: "phase-test@rsolv.dev",
      api_key: api_key,
      monthly_limit: 100000,
      plan: "internal"
    }
    
    # Check if already exists
    {:ok, result} = Repo.query(
      "SELECT id FROM customers WHERE email = $1",
      [key_data.email]
    )
    
    customer_id = if result.num_rows == 0 do
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
          Jason.encode!(%{type: "phase_test", purpose: "phase data persistence testing"}),
          key_data.plan,
          system_user_id,
          DateTime.utc_now(),
          DateTime.utc_now()
        ]
      )
      IO.puts("✓ Created customer: #{key_data.name}")
      
      # Get the customer ID
      {:ok, result} = Repo.query("SELECT id FROM customers WHERE api_key = $1", [key_data.api_key])
      [[id]] = result.rows
      id
    else
      [[id]] = result.rows
      IO.puts("Using existing customer ID: #{id}")
      id
    end
    
    # Create an API key record
    {:ok, result} = Repo.query(
      "SELECT id FROM api_keys WHERE key = $1",
      [key_data.api_key]
    )
    
    if result.num_rows == 0 do
      {:ok, _} = Repo.query(
        """
        INSERT INTO api_keys (key, name, customer_id, permissions, active, inserted_at, updated_at)
        VALUES ($1, $2, $3, $4, $5, $6, $7)
        """,
        [
          key_data.api_key,
          "Phase Test API Key",
          customer_id,
          ["all"],
          true,
          DateTime.utc_now(),
          DateTime.utc_now()
        ]
      )
      IO.puts("✓ Created API key record")
    else
      IO.puts("API key record already exists")
    end
    
    # Create forge_account for RSOLV-dev namespace
    {:ok, result} = Repo.query(
      "SELECT id FROM forge_accounts WHERE customer_id = $1 AND namespace = $2",
      [customer_id, "RSOLV-dev"]
    )
    
    if result.num_rows == 0 do
      {:ok, _} = Repo.query(
        """
        INSERT INTO forge_accounts (customer_id, forge_type, namespace, verified_at, metadata, inserted_at, updated_at)
        VALUES ($1, $2, $3, $4, $5::jsonb, $6, $7)
        """,
        [
          customer_id,
          "github",
          "RSOLV-dev",
          DateTime.utc_now(),  # Pre-verified for testing
          Jason.encode!(%{type: "test", purpose: "phase data testing"}),
          DateTime.utc_now(),
          DateTime.utc_now()
        ]
      )
      IO.puts("✓ Created forge_account for RSOLV-dev namespace")
    else
      IO.puts("Forge account already exists for RSOLV-dev namespace")
    end
    
    IO.puts("\n=== API Key Created Successfully ===")
    IO.puts("API Key: #{api_key}")
    IO.puts("Name: #{key_data.name}")
    IO.puts("Email: #{key_data.email}")
    IO.puts("Monthly Limit: #{key_data.monthly_limit}")
    IO.puts("Plan: #{key_data.plan}")
    IO.puts("Namespace Access: RSOLV-dev")
    IO.puts("\nStore this API key securely!")
    IO.puts("\nExport it for testing:")
    IO.puts("export RSOLV_PHASE_TEST_API_KEY=\"#{api_key}\"")
    
    IO.puts("\nTesting API key...")
    test_api_key(api_key)
  end
  
  defp generate_api_key(prefix) do
    random_string = :crypto.strong_rand_bytes(32) |> Base.encode16(case: :lower)
    "#{prefix}_#{random_string}"
  end
  
  defp test_api_key(api_key) do
    api_key_record = Rsolv.Customers.get_api_key_by_key(api_key)
    if api_key_record do
      IO.puts("✓ API key is valid and working!")
      IO.puts("  Customer: #{inspect(api_key_record.customer.name)}")
      
      # Test forge account access using raw SQL
      {:ok, result} = Repo.query(
        "SELECT forge_type, namespace FROM forge_accounts WHERE customer_id = $1",
        [api_key_record.customer_id]
      )
      
      IO.puts("  Forge Accounts: #{result.num_rows}")
      Enum.each(result.rows, fn [forge_type, namespace] ->
        IO.puts("    - #{forge_type}/#{namespace}")
      end)
    else
      IO.puts("✗ API key validation failed!")
    end
  end
end

CreatePhaseTestKey.run()