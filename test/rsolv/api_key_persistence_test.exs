defmodule Rsolv.ApiKeyPersistenceTest do
  use Rsolv.DataCase
  import Rsolv.TestHelpers, only: [unique_email: 0]

  alias Rsolv.Customers
  alias Rsolv.Repo

  describe "create_api_key/2 persistence" do
    setup do
      # Create a customer for testing
      {:ok, customer} =
        Customers.register_customer(%{
          email: unique_email(),
          password: "TestP@ssw0rd123!",
          name: "Test Customer"
        })

      %{customer: customer}
    end

    test "api key persists to database after creation", %{customer: customer} do
      # Create API key
      assert {:ok, result} = Customers.create_api_key(customer, %{name: "Test Key"})

      # Should return both record and raw key
      assert result.record
      assert result.raw_key

      api_key = result.record
      raw_key = result.raw_key

      # Raw key should be generated with correct format
      assert raw_key
      assert String.starts_with?(raw_key, "rsolv_")

      # Key hash should be stored
      assert api_key.key_hash
      assert String.length(api_key.key_hash) == 64

      # Key should have correct associations
      assert api_key.customer_id == customer.id
      assert api_key.name == "Test Key"

      # CRITICAL TEST: Verify key actually exists in database
      # This simulates what happens when authentication tries to use the key
      persisted_key = Repo.get(Rsolv.Customers.ApiKey, api_key.id)

      assert persisted_key != nil, "API key was not persisted to database!"
      assert persisted_key.id == api_key.id
      assert persisted_key.customer_id == customer.id
      assert persisted_key.active == true
      assert persisted_key.key_hash == api_key.key_hash
    end

    test "api key can be retrieved by key value", %{customer: customer} do
      # Create API key
      {:ok, result} = Customers.create_api_key(customer, %{name: "Test Key 2"})

      api_key = result.record
      raw_key = result.raw_key

      # Should be retrievable by raw key
      found_key = Customers.get_api_key_by_key(raw_key)

      assert found_key != nil, "API key could not be retrieved!"
      assert found_key.id == api_key.id
      assert found_key.customer.id == customer.id
    end

    test "multiple api keys persist correctly", %{customer: customer} do
      # Create multiple keys
      {:ok, result1} = Customers.create_api_key(customer, %{name: "Key 1"})
      {:ok, result2} = Customers.create_api_key(customer, %{name: "Key 2"})
      {:ok, result3} = Customers.create_api_key(customer, %{name: "Key 3"})

      # All should be in the list
      keys = Customers.list_api_keys(customer)
      assert length(keys) == 3

      # All should be retrievable by their hashes
      assert Repo.get_by(Rsolv.Customers.ApiKey, key_hash: result1.record.key_hash)
      assert Repo.get_by(Rsolv.Customers.ApiKey, key_hash: result2.record.key_hash)
      assert Repo.get_by(Rsolv.Customers.ApiKey, key_hash: result3.record.key_hash)
    end

    test "changeset validation errors are returned", %{customer: customer} do
      # Create a key
      {:ok, result} = Customers.create_api_key(customer, %{name: "Original"})

      _existing_key = result.record
      raw_key = result.raw_key

      # Try to create a duplicate key (should fail unique constraint on key_hash)
      duplicate_result =
        %Rsolv.Customers.ApiKey{}
        |> Rsolv.Customers.ApiKey.changeset(%{
          raw_key: raw_key,
          name: "Duplicate",
          customer_id: customer.id
        })
        |> Repo.insert()

      assert {:error, changeset} = duplicate_result
      assert changeset.errors[:key_hash]
    end
  end
end
