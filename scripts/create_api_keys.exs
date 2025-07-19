# Script to create API keys in the database
# Run with: mix run scripts/create_api_keys.exs

defmodule CreateApiKeys do
  alias Rsolv.Repo
  
  def run do
    IO.puts("Creating API key records...")
    
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
    
    # Define API keys to create
    api_keys = [
      %{
        name: "Demo Account",
        email: "demo@rsolv.dev",
        api_key: "demo_69b3158556cf1717c14bfcd8a1186a42",
        monthly_limit: 10,
        plan: "demo"
      },
      %{
        name: "Internal Testing",
        email: "internal@rsolv.dev",
        api_key: "internal_c9d0a3569b45597be41a44ca007abd5c",
        monthly_limit: 1000,
        plan: "internal"
      },
      %{
        name: "RSOLV Dogfooding",
        email: "dogfood@rsolv.dev",
        api_key: "dogfood_3132182ffed1ab7fbe4e9abbd54d8309",
        monthly_limit: 10000,
        plan: "unlimited"
      },
      %{
        name: "Master Account",
        email: "master@rsolv.dev",
        api_key: "master_58d4c71fcbf98327b088b21dd24f6c4327e87b4f4e080f7f81ebbc2f0e0aef32",
        monthly_limit: 100000,
        plan: "unlimited"
      }
    ]
    
    # Create customers using direct SQL
    Enum.each(api_keys, fn key_data ->
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
            Jason.encode!(%{type: String.downcase(String.split(key_data.name, " ") |> List.first())}),  # metadata as JSON
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
            "Primary API Key",
            customer_id,
            ["all"],
            true,
            DateTime.utc_now(),
            DateTime.utc_now()
          ]
        )
        IO.puts("  ✓ Created API key record")
      else
        IO.puts("⚠ Customer already exists: #{key_data.name}")
      end
    end)
    
    IO.puts("\nVerifying API keys...")
    
    # Test each key
    ["demo_69b3158556cf1717c14bfcd8a1186a42", 
     "internal_c9d0a3569b45597be41a44ca007abd5c",
     "dogfood_3132182ffed1ab7fbe4e9abbd54d8309",
     "master_58d4c71fcbf98327b088b21dd24f6c4327e87b4f4e080f7f81ebbc2f0e0aef32"]
    |> Enum.each(fn key ->
      customer = Rsolv.Accounts.get_customer_by_api_key(key)
      if customer do
        key_preview = String.slice(key, 0..20)
        IO.puts("✓ #{key_preview}... -> #{inspect(Map.get(customer, :name) || Map.get(customer, :id))}")
      else
        key_preview = String.slice(key, 0..20)
        IO.puts("✗ #{key_preview}... -> NOT FOUND")
      end
    end)
    
    IO.puts("\nTesting API endpoints locally...")
    
    # Test with local endpoint
    test_url = "http://localhost:4000/api/v1/vulnerabilities/validate"
    test_key = "demo_69b3158556cf1717c14bfcd8a1186a42"
    
    IO.puts("Testing #{test_url} with demo key...")
    case HTTPoison.post(
      test_url,
      Jason.encode!(%{vulnerabilities: []}),
      [
        {"x-api-key", test_key},
        {"Content-Type", "application/json"}
      ]
    ) do
      {:ok, %{status_code: 200}} ->
        IO.puts("✓ API key works!")
      {:ok, %{status_code: status, body: body}} ->
        IO.puts("✗ Failed with status #{status}: #{body}")
      {:error, reason} ->
        IO.puts("✗ Error: #{inspect(reason)}")
    end
  end
end

CreateApiKeys.run()