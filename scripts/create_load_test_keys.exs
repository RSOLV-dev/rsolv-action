#!/usr/bin/env elixir
# Script to create 5 API keys for load testing credential vending
# Run with: MIX_ENV=staging mix run scripts/create_load_test_keys.exs

defmodule CreateLoadTestKeys do
  alias Rsolv.Repo
  require Logger

  def run do
    IO.puts("Creating 5 API keys for load testing credential vending...")
    IO.puts("")

    # Get or create system user
    {:ok, result} = Repo.query("SELECT id FROM users WHERE email = $1", ["loadtest-system@rsolv.dev"])

    system_user_id = if result.num_rows == 0 do
      {:ok, result} = Repo.query(
        """
        INSERT INTO users (email, hashed_password, confirmed_at, inserted_at, updated_at)
        VALUES ($1, $2, $3, $4, $5)
        RETURNING id
        """,
        [
          "loadtest-system@rsolv.dev",
          Bcrypt.hash_pwd_salt("loadtest_system_#{:rand.uniform(999999)}"),
          DateTime.utc_now(),
          DateTime.utc_now(),
          DateTime.utc_now()
        ]
      )
      [[id]] = result.rows
      IO.puts("Created loadtest system user with ID: #{id}")
      id
    else
      [[id]] = result.rows
      IO.puts("Using existing loadtest system user ID: #{id}")
      id
    end

    # Create 5 API keys
    keys = Enum.map(1..5, fn i ->
      timestamp = DateTime.utc_now() |> DateTime.to_unix()
      api_key = generate_api_key("rsolv_loadtest_#{i}_#{timestamp}")

      # Create customer
      {:ok, _} = Repo.query(
        """
        INSERT INTO customers (name, email, api_key, monthly_limit, current_usage, active,
                               metadata, plan, user_id, inserted_at, updated_at)
        VALUES ($1, $2, $3, $4, $5, $6, $7::jsonb, $8, $9, $10, $11)
        """,
        [
          "Load Test Customer #{i}",
          "loadtest-#{i}-#{timestamp}@example.com",
          api_key,
          100000,  # monthly_limit
          0,       # current_usage
          true,    # active
          Jason.encode!(%{
            type: "load_test",
            purpose: "RFC-068 credential vending load test",
            test_number: i,
            created_at: DateTime.utc_now()
          }),
          "pro",   # plan
          system_user_id,
          DateTime.utc_now(),
          DateTime.utc_now()
        ]
      )

      # Get customer ID
      {:ok, result} = Repo.query("SELECT id FROM customers WHERE api_key = $1", [api_key])
      [[customer_id]] = result.rows

      # Create API key record
      {:ok, _} = Repo.query(
        """
        INSERT INTO api_keys (key, name, customer_id, permissions, active, inserted_at, updated_at)
        VALUES ($1, $2, $3, $4, $5, $6, $7)
        """,
        [
          api_key,
          "Load Test API Key #{i}",
          customer_id,
          ["all"],
          true,
          DateTime.utc_now(),
          DateTime.utc_now()
        ]
      )

      IO.puts("✓ Created API key #{i}: #{api_key}")

      {i, api_key}
    end)

    IO.puts("\n" <> String.duplicate("=", 70))
    IO.puts("5 LOAD TEST API KEYS CREATED SUCCESSFULLY")
    IO.puts(String.duplicate("=", 70))

    IO.puts("\n📋 Export for k6 load testing:\n")
    Enum.each(keys, fn {i, key} ->
      IO.puts("export TEST_API_KEY_#{i}=\"#{key}\"")
    end)

    IO.puts("\n🧪 Run load test:")
    IO.puts("""
    # Set all keys
    #{Enum.map(keys, fn {i, key} -> "export TEST_API_KEY_#{i}=\"#{key}\"" end) |> Enum.join("\n")}

    # Run credential vending load test
    API_URL=https://api.rsolv-staging.com k6 run scripts/load-tests/credential-vending-load-test.k6.js
    """)

    IO.puts(String.duplicate("=", 70))
  end

  defp generate_api_key(prefix) do
    random_string = :crypto.strong_rand_bytes(32) |> Base.encode16(case: :lower)
    "#{prefix}_#{random_string}"
  end
end

CreateLoadTestKeys.run()
