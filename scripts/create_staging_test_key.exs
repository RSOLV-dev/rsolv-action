# Script to create an API key for staging phase data testing
# Run with: MIX_ENV=staging mix run scripts/create_staging_test_key.exs

defmodule CreateStagingTestKey do
  alias Rsolv.Repo
  require Logger
  
  def run do
    IO.puts("Creating API key for STAGING phase data testing...")
    IO.puts("Environment: #{Mix.env()}")
    IO.puts("Database: #{inspect(Application.get_env(:rsolv, Rsolv.Repo)[:database])}")
    
    # Generate a unique API key for staging
    timestamp = DateTime.utc_now() |> DateTime.to_unix()
    api_key = generate_api_key("staging_phase_test_#{timestamp}")
    
    # First, create or get a system user using direct SQL
    {:ok, result} = Repo.query("SELECT id FROM users WHERE email = $1", ["staging-system@rsolv.dev"])
    
    system_user_id = if result.num_rows == 0 do
      # Create system user
      {:ok, result} = Repo.query(
        """
        INSERT INTO users (email, hashed_password, confirmed_at, inserted_at, updated_at)
        VALUES ($1, $2, $3, $4, $5)
        RETURNING id
        """,
        [
          "staging-system@rsolv.dev",
          Bcrypt.hash_pwd_salt("staging_system_#{:rand.uniform(999999)}"),
          DateTime.utc_now(),
          DateTime.utc_now(),
          DateTime.utc_now()
        ]
      )
      [[id]] = result.rows
      IO.puts("Created staging system user with ID: #{id}")
      id
    else
      [[id]] = result.rows
      IO.puts("Using existing staging system user ID: #{id}")
      id
    end
    
    # Create the staging phase test customer
    key_data = %{
      name: "Staging Phase Data Test #{timestamp}",
      email: "staging-phase-test-#{timestamp}@rsolv.dev",
      api_key: api_key,
      monthly_limit: 100000,
      plan: "internal"
    }
    
    # Always create a new customer for staging tests
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
        Jason.encode!(%{
          type: "staging_phase_test", 
          purpose: "phase data persistence testing on staging",
          created_at: DateTime.utc_now()
        }),
        key_data.plan,
        system_user_id,
        DateTime.utc_now(),
        DateTime.utc_now()
      ]
    )
    IO.puts("✓ Created staging customer: #{key_data.name}")
    
    # Get the customer ID
    {:ok, result} = Repo.query("SELECT id FROM customers WHERE api_key = $1", [key_data.api_key])
    [[customer_id]] = result.rows
    
    # Create an API key record
    {:ok, _} = Repo.query(
      """
      INSERT INTO api_keys (key, name, customer_id, permissions, active, inserted_at, updated_at)
      VALUES ($1, $2, $3, $4, $5, $6, $7)
      """,
      [
        key_data.api_key,
        "Staging Phase Test API Key #{timestamp}",
        customer_id,
        ["all"],
        true,
        DateTime.utc_now(),
        DateTime.utc_now()
      ]
    )
    IO.puts("✓ Created API key record")
    
    # Create forge_account for RSOLV-dev namespace (testing)
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
        Jason.encode!(%{
          type: "staging_test", 
          purpose: "phase data testing",
          environment: "staging"
        }),
        DateTime.utc_now(),
        DateTime.utc_now()
      ]
    )
    IO.puts("✓ Created forge_account for RSOLV-dev namespace")
    
    # Also create forge_account for test-org namespace  
    {:ok, _} = Repo.query(
      """
      INSERT INTO forge_accounts (customer_id, forge_type, namespace, verified_at, metadata, inserted_at, updated_at)
      VALUES ($1, $2, $3, $4, $5::jsonb, $6, $7)
      """,
      [
        customer_id,
        "github",
        "test-org",
        DateTime.utc_now(),
        Jason.encode!(%{
          type: "staging_test",
          purpose: "additional test namespace",
          environment: "staging"
        }),
        DateTime.utc_now(),
        DateTime.utc_now()
      ]
    )
    IO.puts("✓ Created forge_account for test-org namespace")
    
    IO.puts("\n" <> String.duplicate("=", 60))
    IO.puts("STAGING API KEY CREATED SUCCESSFULLY")
    IO.puts(String.duplicate("=", 60))
    IO.puts("API Key: #{api_key}")
    IO.puts("Customer: #{key_data.name}")
    IO.puts("Email: #{key_data.email}")
    IO.puts("Namespaces: RSOLV-dev, test-org")
    IO.puts(String.duplicate("=", 60))
    
    IO.puts("\n📋 Export for testing:")
    IO.puts("export STAGING_API_KEY=\"#{api_key}\"")
    IO.puts("export RSOLV_API_URL=\"https://api.rsolv-staging.com\"")
    
    IO.puts("\n🧪 Test commands:")
    IO.puts("""
    # Test store endpoint
    curl -X POST https://api.rsolv-staging.com/api/v1/phases/store \\
      -H "X-API-Key: #{api_key}" \\
      -H "Content-Type: application/json" \\
      -d '{
        "phase": "scan",
        "repo": "RSOLV-dev/test-repo",
        "commit_sha": "test123",
        "branch": "main",
        "data": {
          "vulnerabilities": [
            {"type": "xss", "file": "app.js", "line": 42}
          ],
          "timestamp": "#{DateTime.utc_now() |> DateTime.to_iso8601()}",
          "commitHash": "test123"
        }
      }'
    
    # Test retrieve endpoint
    curl https://api.rsolv-staging.com/api/v1/phases/retrieve?repo=RSOLV-dev/test-repo&issue=1&commit=test123 \\
      -H "X-API-Key: #{api_key}"
    """)
    
    IO.puts("\nVerifying API key...")
    test_api_key(api_key)
  end
  
  defp generate_api_key(prefix) do
    random_string = :crypto.strong_rand_bytes(32) |> Base.encode16(case: :lower)
    "#{prefix}_#{random_string}"
  end
  
  defp test_api_key(api_key) do
    api_key_record = Rsolv.Customers.get_api_key_by_key(api_key)
    if api_key_record do
      IO.puts("✅ API key is valid and active!")
      IO.puts("  Customer ID: #{api_key_record.customer_id}")
      IO.puts("  Customer Name: #{inspect(api_key_record.customer.name)}")
      
      # Test forge account access
      {:ok, result} = Repo.query(
        "SELECT forge_type, namespace, verified_at FROM forge_accounts WHERE customer_id = $1",
        [api_key_record.customer_id]
      )
      
      IO.puts("  Forge Accounts: #{result.num_rows}")
      Enum.each(result.rows, fn [forge_type, namespace, verified_at] ->
        verified = if verified_at, do: "✓", else: "✗"
        IO.puts("    #{verified} #{forge_type}/#{namespace}")
      end)
      
      IO.puts("\n✅ Ready for testing on staging!")
    else
      IO.puts("❌ API key validation failed!")
    end
  end
end

CreateStagingTestKey.run()