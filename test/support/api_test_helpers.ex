defmodule Rsolv.APITestHelpers do
  @moduledoc """
  Helper functions for API tests requiring authentication.
  Provides consistent customer and API key setup across test files.
  """

  def setup_api_auth(_context \\ %{}) do
    # Clear rate limit data for test customer
    if :ets.whereis(:rsolv_rate_limiter) != :undefined do
      :ets.delete_all_objects(:rsolv_rate_limiter)
    end
    
    # Create a unique customer for this test
    unique_id = System.unique_integer([:positive])
    
    # Create customer directly
    {:ok, customer_record} = Rsolv.Customers.create_customer(%{
      name: "Test Customer #{unique_id}",
      email: "test#{unique_id}@example.com",
      monthly_limit: 100,
      current_usage: 15
    })
    
    # Create an API key for this customer
    {:ok, api_key} = Rsolv.Customers.create_api_key(customer_record, %{
      name: "Test Key",
      permissions: ["full_access"]
    })
    
    # Build a customer map with the API key for backward compatibility
    # This allows tests to use customer.api_key syntax
    customer = %{
      id: customer_record.id,
      name: customer_record.name,
      email: customer_record.email,
      api_key: api_key.key,
      tier: "enterprise",
      flags: ["ai_access", "enterprise_access"],
      monthly_limit: customer_record.monthly_limit,
      current_usage: customer_record.current_usage,
      active: true,
      trial: true,
      created_at: customer_record.inserted_at
    }
    
    {:ok, customer: customer, api_key: api_key}
  end
end