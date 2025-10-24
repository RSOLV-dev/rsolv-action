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
      assert {:ok, api_key} = Customers.create_api_key(customer, %{name: "Test Key"})

      # Key should be generated
      assert api_key.key
      assert String.starts_with?(api_key.key, "rsolv_")

      # Key should have correct associations
      assert api_key.customer_id == customer.id
      assert api_key.name == "Test Key"

      # CRITICAL TEST: Verify key actually exists in database
      # This simulates what happens when authentication tries to use the key
      persisted_key = Repo.get_by(Rsolv.Customers.ApiKey, key: api_key.key)

      assert persisted_key != nil, "API key was not persisted to database!"
      assert persisted_key.id == api_key.id
      assert persisted_key.customer_id == customer.id
      assert persisted_key.active == true
    end

    test "api key can be retrieved by key value", %{customer: customer} do
      # Create API key
      {:ok, api_key} = Customers.create_api_key(customer, %{name: "Test Key 2"})

      # Should be retrievable by key
      found_key = Customers.get_api_key_by_key(api_key.key)

      assert found_key != nil, "API key could not be retrieved!"
      assert found_key.id == api_key.id
      assert found_key.customer.id == customer.id
    end

    test "multiple api keys persist correctly", %{customer: customer} do
      # Create multiple keys
      {:ok, key1} = Customers.create_api_key(customer, %{name: "Key 1"})
      {:ok, key2} = Customers.create_api_key(customer, %{name: "Key 2"})
      {:ok, key3} = Customers.create_api_key(customer, %{name: "Key 3"})

      # All should be in the list
      keys = Customers.list_api_keys(customer)
      assert length(keys) == 3

      # All should be retrievable
      assert Repo.get_by(Rsolv.Customers.ApiKey, key: key1.key)
      assert Repo.get_by(Rsolv.Customers.ApiKey, key: key2.key)
      assert Repo.get_by(Rsolv.Customers.ApiKey, key: key3.key)
    end

    test "changeset validation errors are returned", %{customer: customer} do
      # Create a key
      {:ok, existing_key} = Customers.create_api_key(customer, %{name: "Original"})

      # Try to create a duplicate key (should fail unique constraint)
      result =
        %Rsolv.Customers.ApiKey{}
        |> Rsolv.Customers.ApiKey.changeset(%{
          key: existing_key.key,
          name: "Duplicate",
          customer_id: customer.id
        })
        |> Repo.insert()

      assert {:error, changeset} = result
      assert changeset.errors[:key]
    end
  end
end
