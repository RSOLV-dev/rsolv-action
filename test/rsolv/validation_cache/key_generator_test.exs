defmodule Rsolv.ValidationCache.KeyGeneratorTest do
  use Rsolv.DataCase
  alias Rsolv.ValidationCache.KeyGenerator
  alias Rsolv.Customers.ForgeAccount
  alias Rsolv.Customers.Customer

  # Helper to create test data
  defp create_forge_account do
    unique_id = System.unique_integer([:positive])

    # Create a customer directly
    customer =
      %Customer{
        name: "Test Customer #{unique_id}",
        email: "test#{unique_id}@example.com"
      }
      |> Repo.insert!()

    # Create forge account
    %ForgeAccount{
      forge_type: :github,
      namespace: "test-org",
      customer_id: customer.id,
      verified_at: DateTime.utc_now()
    }
    |> Repo.insert!()
  end

  describe "generate_key/4" do
    test "generates key for single-file vulnerability" do
      forge_account = create_forge_account()
      locations = [%{file_path: "app/routes/profile.js", line: 42}]

      key =
        KeyGenerator.generate_key(
          forge_account.id,
          "RSOLV-dev/nodegoat",
          locations,
          "sql-injection"
        )

      assert key ==
               "#{forge_account.id}/RSOLV-dev/nodegoat/[app/routes/profile.js:42]:sql-injection"
    end

    test "sorts multiple locations alphabetically" do
      forge_account = create_forge_account()

      locations = [
        %{file_path: "lib/db.js", line: 10},
        %{file_path: "api/endpoint.js", line: 30}
      ]

      key =
        KeyGenerator.generate_key(
          forge_account.id,
          "RSOLV-dev/nodegoat",
          locations,
          "sql-injection"
        )

      # Should be sorted alphabetically
      assert key ==
               "#{forge_account.id}/RSOLV-dev/nodegoat/[api/endpoint.js:30,lib/db.js:10]:sql-injection"
    end

    test "handles special characters in repository names" do
      forge_account = create_forge_account()
      locations = [%{file_path: "index.js", line: 1}]

      key =
        KeyGenerator.generate_key(
          forge_account.id,
          "user-name/repo.with.dots",
          locations,
          "xss"
        )

      assert key == "#{forge_account.id}/user-name/repo.with.dots/[index.js:1]:xss"
    end

    test "raises on empty locations" do
      forge_account = create_forge_account()

      assert_raise ArgumentError, fn ->
        KeyGenerator.generate_key(
          forge_account.id,
          "RSOLV-dev/nodegoat",
          [],
          "sql-injection"
        )
      end
    end

    test "produces deterministic keys for same input" do
      forge_account = create_forge_account()

      locations = [
        %{file_path: "app.js", line: 5},
        %{file_path: "lib.js", line: 10}
      ]

      key1 =
        KeyGenerator.generate_key(
          forge_account.id,
          "org/repo",
          locations,
          "xss"
        )

      key2 =
        KeyGenerator.generate_key(
          forge_account.id,
          "org/repo",
          locations,
          "xss"
        )

      assert key1 == key2
    end

    test "different forge accounts produce different keys" do
      forge1 = create_forge_account()
      forge2 = create_forge_account()
      locations = [%{file_path: "app.js", line: 42}]

      key1 =
        KeyGenerator.generate_key(
          forge1.id,
          "org/repo",
          locations,
          "xss"
        )

      key2 =
        KeyGenerator.generate_key(
          forge2.id,
          "org/repo",
          locations,
          "xss"
        )

      assert key1 != key2
    end

    test "handles string forge_account_id for test accounts" do
      # This can happen when using test forge accounts
      locations = [%{file_path: "app.js", line: 6}]

      key =
        KeyGenerator.generate_key(
          "test-forge-14",
          "unknown/repo",
          locations,
          "sql_injection"
        )

      assert key == "test-forge-14/unknown/repo/[app.js:6]:sql_injection"
    end
  end
end
