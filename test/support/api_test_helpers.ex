defmodule Rsolv.APITestHelpers do
  @moduledoc """
  Helper functions for API tests requiring authentication.
  Provides consistent customer and API key setup across test files.
  """

  alias Rsolv.Customers
  alias Rsolv.Customers.ApiKey
  alias Rsolv.Repo

  @doc """
  Creates an API key for testing with a known raw key value.

  This is useful for tests that need predictable API keys.

  ## Examples

      iex> customer = insert(:customer)
      iex> {:ok, result} = create_api_key_with_raw_key(customer, "test_my_known_key_123")
      iex> result.raw_key
      "test_my_known_key_123"

  """
  def create_api_key_with_raw_key(customer, raw_key, attrs \\ %{}) do
    attrs =
      attrs
      |> Map.put(:raw_key, raw_key)
      |> Map.put_new(:name, "Test Key")

    Customers.create_api_key(customer, attrs)
  end

  def setup_api_auth(_context \\ %{}) do
    # Clear rate limit data for test customer
    if :ets.whereis(:rsolv_rate_limiter) != :undefined do
      :ets.delete_all_objects(:rsolv_rate_limiter)
    end

    # Create a unique customer for this test
    unique_id = System.unique_integer([:positive])

    # Create customer directly
    {:ok, customer_record} =
      Rsolv.Customers.create_customer(%{
        name: "Test Customer #{unique_id}",
        email: "test#{unique_id}@example.com",
        monthly_limit: 100,
        current_usage: 15
      })

    # Create an API key for this customer
    {:ok, api_key_result} =
      Rsolv.Customers.create_api_key(customer_record, %{
        name: "Test Key",
        permissions: ["full_access"]
      })

    # Extract the raw key and API key record from the result
    raw_api_key = api_key_result.raw_key
    api_key_record = api_key_result.record

    # Build a customer map with the API key for backward compatibility
    # This allows tests to use customer.api_key syntax
    customer = %{
      id: customer_record.id,
      name: customer_record.name,
      email: customer_record.email,
      api_key: raw_api_key,
      tier: "enterprise",
      flags: ["ai_access", "enterprise_access"],
      monthly_limit: customer_record.monthly_limit,
      current_usage: customer_record.current_usage,
      active: true,
      trial: true,
      created_at: customer_record.inserted_at
    }

    {:ok, customer: customer, api_key: api_key_record, raw_api_key: raw_api_key}
  end
end
