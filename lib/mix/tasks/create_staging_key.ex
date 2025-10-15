defmodule Mix.Tasks.CreateStagingKey do
  use Mix.Task
  alias Rsolv.Repo

  @shortdoc "Creates a staging API key with forge_account access"

  def run(_) do
    Mix.Task.run("app.start")

    timestamp = System.os_time(:second)

    api_key =
      "staging_phase_test_#{timestamp}_" <>
        Base.encode16(:crypto.strong_rand_bytes(16), case: :lower)

    # Create customer
    {:ok, _} =
      Repo.query(
        """
        INSERT INTO customers (name, email, api_key, monthly_limit, current_usage, active, plan, inserted_at, updated_at)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
        """,
        [
          "Staging Phase Test #{timestamp}",
          "staging-test-#{timestamp}@rsolv.dev",
          api_key,
          100_000,
          0,
          true,
          "internal",
          DateTime.utc_now(),
          DateTime.utc_now()
        ]
      )

    # Get customer ID
    {:ok, result} = Repo.query("SELECT id FROM customers WHERE api_key = $1", [api_key])
    [[customer_id]] = result.rows

    # Create API key record
    {:ok, _} =
      Repo.query(
        """
        INSERT INTO api_keys (key, name, customer_id, permissions, active, inserted_at, updated_at)
        VALUES ($1, $2, $3, $4, $5, $6, $7)
        """,
        [
          api_key,
          "Staging Phase Test Key",
          customer_id,
          ["all"],
          true,
          DateTime.utc_now(),
          DateTime.utc_now()
        ]
      )

    # Create forge_accounts
    metadata = %{type: "staging_test", created_at: DateTime.utc_now()}

    {:ok, _} =
      Repo.query(
        """
        INSERT INTO forge_accounts (customer_id, forge_type, namespace, verified_at, metadata, inserted_at, updated_at)
        VALUES ($1, $2, $3, $4, $5::jsonb, $6, $7)
        """,
        [
          customer_id,
          "github",
          "RSOLV-dev",
          DateTime.utc_now(),
          Jason.encode!(metadata),
          DateTime.utc_now(),
          DateTime.utc_now()
        ]
      )

    # Also add test-org namespace
    {:ok, _} =
      Repo.query(
        """
        INSERT INTO forge_accounts (customer_id, forge_type, namespace, verified_at, metadata, inserted_at, updated_at)
        VALUES ($1, $2, $3, $4, $5::jsonb, $6, $7)
        """,
        [
          customer_id,
          "github",
          "test-org",
          DateTime.utc_now(),
          Jason.encode!(metadata),
          DateTime.utc_now(),
          DateTime.utc_now()
        ]
      )

    IO.puts("\n" <> String.duplicate("=", 60))
    IO.puts("STAGING API KEY CREATED SUCCESSFULLY")
    IO.puts(String.duplicate("=", 60))
    IO.puts("API Key: #{api_key}")
    IO.puts("Customer ID: #{customer_id}")
    IO.puts("Namespaces: RSOLV-dev, test-org")
    IO.puts(String.duplicate("=", 60))
    IO.puts("\nExport for testing:")
    IO.puts("export STAGING_API_KEY=\"#{api_key}\"")
    IO.puts("export RSOLV_API_URL=\"https://api.rsolv-staging.com\"")
    IO.puts(String.duplicate("=", 60))

    # Verify it works
    api_key_record = Rsolv.Customers.get_api_key_by_key(api_key)

    if api_key_record do
      IO.puts("\n✅ API key verified and active!")
      IO.puts("  Customer: #{api_key_record.customer.name}")
    else
      IO.puts("\n❌ API key verification failed!")
    end
  end
end
