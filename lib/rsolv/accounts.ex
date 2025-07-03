defmodule Rsolv.Accounts do
  @moduledoc """
  The Accounts context for managing customers and API keys.
  Updated: #{DateTime.utc_now()}
  """
  
  # Storage for test customer updates
  @table_key {__MODULE__, :test_customers}
  
  @doc """
  Gets a customer by their API key.
  
  Returns nil if no customer found.
  """
  def get_customer_by_api_key(api_key) when is_binary(api_key) do
    # First check for test customer updates
    test_customers = :persistent_term.get(@table_key, %{})
    case Map.get(test_customers, api_key) do
      nil -> 
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
        
      # Test API key for main test customer (has enterprise/AI access)
      api_key == "rsolv_test_abc123" ->
        %{
          id: "test_customer_1",
          name: "Test Customer",
          email: "test@example.com",
          api_key: api_key,
          tier: "enterprise",
          flags: ["ai_access", "enterprise_access"],
          monthly_limit: 100,
          current_usage: 15,
          active: true,
          trial: true,
          created_at: DateTime.utc_now()
        }
      
      # Test API key for regular customers (no enterprise/AI access)
      api_key == "rsolv_test_regular_def456" ->
        %{
          id: "test_customer_regular",
          name: "Test Regular Customer",
          email: "regular@example.com",
          api_key: api_key,
          tier: "standard",
          flags: [],
          monthly_limit: 100,
          current_usage: 15,
          active: true,
          trial: true,
          created_at: DateTime.utc_now()
        }
      
      # Test API key for enterprise customers
      api_key == "rsolv_test_enterprise_xyz789" ->
        %{
          id: "test_enterprise_customer",
          name: "Test Enterprise Customer",
          email: "enterprise@example.com",
          api_key: api_key,
          tier: "enterprise",
          flags: ["ai_access", "enterprise_access"],
          monthly_limit: 1000,
          current_usage: 5,
          active: true,
          trial: false,
          created_at: DateTime.utc_now()
        }
      
      # Full access test API key with no quota limits
      api_key == "rsolv_test_full_access_no_quota_2025" ->
        %{
          id: "test_full_access",
          name: "Test Full Access",
          email: "test-full-access@rsolv.dev",
          api_key: api_key,
          tier: "enterprise",
          flags: ["ai_access", "enterprise_access", "quota_exempt"],
          monthly_limit: 999999,  # Effectively unlimited
          current_usage: 0,
          active: true,
          trial: false,
          created_at: DateTime.utc_now()
        }
      
          # Check database for customer-specific keys
          true ->
            require Logger
            Logger.info("[Accounts] Checking database for API key: #{api_key}")
            
            import Ecto.Query
            
            query = from c in "customers",
                    where: c.api_key == ^api_key and c.active == true,
                    select: %{
                      id: c.id,
                      name: c.name,
                      email: c.email,
                      api_key: c.api_key,
                      monthly_limit: c.monthly_limit,
                      current_usage: c.current_usage,
                      active: c.active,
                      trial: c.subscription_status == "trial",
                      created_at: c.inserted_at
                    }
            
            case Rsolv.Repo.one(query) do
              nil -> 
                Logger.info("[Accounts] No customer found in database for API key")
                nil
              customer -> 
                Logger.info("[Accounts] Found customer in database: #{customer.name}")
                customer
            end
        end
      
      updated_customer ->
        updated_customer
    end
  end
  
  def get_customer_by_api_key(_), do: nil
  
  @doc """
  Updates a customer's attributes.
  """
  def update_customer(customer, attrs) do
    # Mock implementation - in production this would update the database
    updated_customer = Map.merge(customer, attrs)
    
    # Store the updated customer for subsequent lookups
    customers = :persistent_term.get(@table_key, %{})
    new_customers = Map.put(customers, customer.api_key, updated_customer)
    :persistent_term.put(@table_key, new_customers)
    
    {:ok, updated_customer}
  end
  
  @doc """
  Gets a customer by ID.
  """
  def get_customer!(customer_id) do
    # First check if we have an updated version stored
    test_customers = :persistent_term.get(@table_key, %{})
    updated_customer = Enum.find_value(test_customers, fn {_api_key, customer} ->
      if customer.id == customer_id, do: customer, else: nil
    end)
    
    case updated_customer do
      nil ->
        # Return default mock customer
        %{
          id: customer_id,
          name: "Test Customer",
          email: "test@example.com",
          api_key: "rsolv_test_abc123",
          monthly_limit: 100,
          current_usage: 15,
          active: true,
          trial: true,
          created_at: DateTime.utc_now()
        }
      customer -> customer
    end
  end
  
  @doc """
  Records usage for a customer.
  """
  def record_usage(usage_data) do
    # Mock implementation - in production this would store in database
    require Logger
    Logger.info("Recording usage: #{inspect(usage_data)}")
    {:ok, usage_data}
  end
  
  @doc """
  Gets customer usage summary.
  """
  def get_customer_usage(customer_id) do
    # Mock implementation
    %{
      customer_id: customer_id,
      total_tokens: 5000,
      total_requests: 3,
      current_month_usage: 2
    }
  end
  
  @doc """
  Reset test customer storage (for testing).
  """
  def reset_test_customers() do
    :persistent_term.put(@table_key, %{})
    :ok
  end
end