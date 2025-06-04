defmodule RSOLV.Accounts do
  @moduledoc """
  The Accounts context for managing customers and API keys.
  """

  alias RSOLV.Repo
  alias RSOLV.Accounts.Customer
  
  @doc """
  Gets a customer by their API key.
  
  Returns nil if no customer found.
  """
  def get_customer_by_api_key(api_key) when is_binary(api_key) do
    # For now, return a mock customer for our internal API key
    # In production, this would query the database
    case api_key do
      "rsolv_internal_a08e4f8ffb58ba44b2cb4d3b30f28e99" ->
        %{
          id: "internal",
          name: "Internal Testing",
          api_key: api_key,
          monthly_limit: 1000,
          current_usage: 0,
          active: true,
          trial: true,
          created_at: DateTime.utc_now()
        }
      
      "rsolv_dogfood_key" ->
        %{
          id: "dogfood",
          name: "RSOLV Dogfooding",
          api_key: api_key,
          monthly_limit: 100,
          current_usage: 0,
          active: true,
          trial: false,
          created_at: DateTime.utc_now()
        }
        
      _ ->
        nil
    end
  end
  
  def get_customer_by_api_key(_), do: nil
end