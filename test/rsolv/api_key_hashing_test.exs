defmodule Rsolv.ApiKeyHashingTest do
  use Rsolv.DataCase
  import Rsolv.TestHelpers, only: [unique_email: 0]

  alias Rsolv.Customers
  alias Rsolv.Customers.ApiKey
  alias Rsolv.Repo

  describe "RED: API key generation and hashing" do
    setup do
      {:ok, customer} =
        Customers.register_customer(%{
          email: unique_email(),
          password: "TestP@ssw0rd123!",
          name: "Test Customer"
        })

      %{customer: customer}
    end

    test "generates unique secure API keys", %{customer: customer} do
      # Create multiple API keys
      raw_keys =
        ["Key 1", "Key 2", "Key 3"]
        |> Enum.map(fn name ->
          {:ok, result} = Customers.create_api_key(customer, %{name: name})
          result.raw_key
        end)

      # All keys should be unique
      assert Enum.uniq(raw_keys) == raw_keys

      # All keys should have the rsolv_ prefix and be sufficiently long
      assert Enum.all?(raw_keys, fn key ->
               String.starts_with?(key, "rsolv_") and String.length(key) >= 40
             end)
    end

    test "stores hashed API key in database (SHA256)", %{customer: customer} do
      # Create an API key
      {:ok, %{record: api_key, raw_key: raw_key}} =
        Customers.create_api_key(customer, %{name: "Test Key"})

      # Database should store the hash, not the raw key
      persisted_key = Repo.get!(ApiKey, api_key.id)

      # The hash should be exactly 64 characters (SHA256 hex)
      assert String.length(persisted_key.key_hash) == 64

      # The hash should match SHA256 of the raw key using our hash_key function
      assert ApiKey.verify_key(raw_key, persisted_key.key_hash)

      # The raw key should NOT be stored in the database
      refute Map.get(persisted_key, :key)
    end

    test "returns raw API key only once on creation", %{customer: customer} do
      # Create an API key
      {:ok, %{record: api_key, raw_key: raw_key}} =
        Customers.create_api_key(customer, %{name: "One Time Key"})

      assert is_binary(raw_key)

      # Retrieve the key from the database - should NOT have the raw key
      refetched_key = Repo.get!(ApiKey, api_key.id)
      assert refetched_key.key_hash
      refute Map.get(refetched_key, :raw_key)

      # Listing API keys should also not expose raw keys
      found_key =
        customer
        |> Customers.list_api_keys()
        |> Enum.find(&(&1.id == api_key.id))

      assert found_key
      refute Map.get(found_key, :raw_key)
    end

    test "can authenticate with raw API key against hash", %{customer: customer} do
      {:ok, %{record: api_key, raw_key: raw_key}} =
        Customers.create_api_key(customer, %{name: "Auth Test Key"})

      # Should authenticate with raw key
      authenticated_customer = Customers.get_customer_by_api_key(raw_key)
      assert authenticated_customer.id == customer.id
      assert authenticated_customer.email == customer.email

      # Should NOT authenticate with hash
      persisted_key = Repo.get!(ApiKey, api_key.id)
      assert is_nil(Customers.get_customer_by_api_key(persisted_key.key_hash))

      # Should NOT authenticate with wrong key
      assert is_nil(Customers.get_customer_by_api_key("rsolv_wrongkeywrongkeywrongkey"))
    end

    test "hash is deterministic for the same raw key" do
      raw_key = "rsolv_test_deterministic_key_123"

      # Hash the same key multiple times
      hashes = Enum.map(1..3, fn _ -> ApiKey.hash_key(raw_key) end)

      # All hashes should be identical
      assert Enum.uniq(hashes) == [hd(hashes)]
    end

    test "different keys produce different hashes", %{customer: customer} do
      # Create two different API keys and get their hashes
      key_hashes =
        ["Key A", "Key B"]
        |> Enum.map(fn name ->
          {:ok, %{record: api_key}} = Customers.create_api_key(customer, %{name: name})
          api_key.key_hash
        end)

      # Hashes should be unique
      assert Enum.uniq(key_hashes) == key_hashes
    end
  end
end
