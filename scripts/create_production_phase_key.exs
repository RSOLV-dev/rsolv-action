# Script to create a production API key for phase data
# Run with: MIX_ENV=prod mix run scripts/create_production_phase_key.exs

defmodule CreateProductionPhaseKey do
  alias Rsolv.Repo
  require Logger
  
  def run do
    IO.puts("Creating production API key for phase data...")
    
    # Generate a unique API key
    timestamp = :os.system_time(:second)
    rand_hex = :crypto.strong_rand_bytes(16) |> Base.encode16(case: :lower)
    api_key = "prod_phase_#{timestamp}_#{rand_hex}"
    
    # First, create or get a system user
    {:ok, result} = Repo.query("SELECT id FROM users WHERE email = $1", ["phase-system@rsolv.dev"])
    
    system_user_id = if result.num_rows == 0 do
      # Create system user
      {:ok, result} = Repo.query(
        """
        INSERT INTO users (email, hashed_password, confirmed_at, inserted_at, updated_at)
        VALUES ($1, $2, $3, $4, $5)
        RETURNING id
        """,
        [
          "phase-system@rsolv.dev",
          Bcrypt.hash_pwd_salt("phase_system_#{:rand.uniform(999999)}"),
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
    
    # Create customer
    {:ok, result} = Repo.query(
      """
      INSERT INTO customers (name, email, api_key, monthly_limit, current_usage, active, plan, user_id, inserted_at, updated_at)
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
      RETURNING id
      """,
      [
        "Production Phase Data Account",
        "phase-production@rsolv.dev",
        api_key,
        100000,
        0,
        true,
        "internal",
        system_user_id,
        NaiveDateTime.utc_now(),
        NaiveDateTime.utc_now()
      ]
    )
    
    [[customer_id]] = result.rows
    IO.puts("Created customer with ID: #{customer_id}")
    
    # Create API key record
    {:ok, result} = Repo.query(
      """
      INSERT INTO api_keys (key, name, customer_id, active, permissions, inserted_at, updated_at)
      VALUES ($1, $2, $3, $4, $5, $6, $7)
      RETURNING id
      """,
      [
        api_key,
        "Production Phase Data Key",
        customer_id,
        true,
        [],
        DateTime.utc_now(),
        DateTime.utc_now()
      ]
    )
    
    [[api_key_id]] = result.rows
    IO.puts("Created API key with ID: #{api_key_id}")
    
    # Create forge_account for RSOLV-dev namespace
    {:ok, result} = Repo.query(
      """
      INSERT INTO forge_accounts (customer_id, forge_type, namespace, verified_at, metadata, inserted_at, updated_at)
      VALUES ($1, $2, $3, $4, $5, $6, $7)
      RETURNING id
      """,
      [
        customer_id,
        "github",
        "RSOLV-dev",
        DateTime.utc_now(),
        %{},
        DateTime.utc_now(),
        DateTime.utc_now()
      ]
    )
    
    [[forge_account_id]] = result.rows
    IO.puts("Created forge_account with ID: #{forge_account_id}")
    
    IO.puts("\n===========================================")
    IO.puts("Production API Key Created Successfully!")
    IO.puts("===========================================")
    IO.puts("API Key: #{api_key}")
    IO.puts("Customer ID: #{customer_id}")
    IO.puts("Forge Account: RSOLV-dev (GitHub)")
    IO.puts("===========================================")
    IO.puts("\nSet this in your GitHub Secrets as RSOLV_API_KEY")
    IO.puts("\nTest with:")
    IO.puts("  export RSOLV_API_KEY=#{api_key}")
    IO.puts("  export RSOLV_API_URL=https://api.rsolv.dev")
  end
  
  def generate_api_key(prefix) do
    timestamp = :os.system_time(:second)
    rand_hex = :crypto.strong_rand_bytes(16) |> Base.encode16(case: :lower)
    "#{prefix}_#{timestamp}_#{rand_hex}"
  end
end

CreateProductionPhaseKey.run()