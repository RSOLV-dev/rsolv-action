defmodule RSOLV.Accounts do
  @moduledoc """
  The Accounts context for managing customers and API keys.
  """
  
  @doc """
  Gets a customer by their API key.
  
  Returns nil if no customer found.
  """
  def get_customer_by_api_key(api_key) when is_binary(api_key) do
    # Check environment variables for valid API keys
    # This prevents hardcoding keys in source control
    cond do
      # Internal API key from environment
      api_key == System.get_env("INTERNAL_API_KEY") ->
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
      
      # Demo API key from environment
      api_key == System.get_env("DEMO_API_KEY") ->
        %{
          id: "demo",
          name: "Demo Account",
          api_key: api_key,
          monthly_limit: 10,
          current_usage: 0,
          active: true,
          trial: true,
          created_at: DateTime.utc_now()
        }
      
      # Master API key from environment
      api_key == System.get_env("MASTER_API_KEY") ->
        %{
          id: "master",
          name: "Master Admin",
          api_key: api_key,
          monthly_limit: 10000,
          current_usage: 0,
          active: true,
          trial: false,
          created_at: DateTime.utc_now()
        }
      
      # Dogfood API key from environment
      api_key == System.get_env("DOGFOOD_API_KEY") ->
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
        
      # In production, this would query the database for customer-specific keys
      true ->
        nil
    end
  end
  
  def get_customer_by_api_key(_), do: nil
end