defmodule RSOLV.Credentials do
  @moduledoc """
  The Credentials context for managing AI provider credentials.
  """
  
  require Logger
  
  # Mock provider keys for demo
  @provider_keys %{
    "anthropic" => System.get_env("ANTHROPIC_API_KEY") || "sk-ant-mock-key",
    "openai" => System.get_env("OPENAI_API_KEY") || "sk-mock-key",
    "openrouter" => System.get_env("OPENROUTER_API_KEY") || "sk-or-mock-key",
    "ollama" => "local"
  }
  
  @doc """
  Creates a temporary credential for a provider.
  """
  def create_temporary_credential(%{
    customer_id: customer_id,
    provider: provider,
    encrypted_key: _encrypted_key,
    expires_at: expires_at,
    usage_limit: usage_limit
  }) do
    # In production, this would store in database
    # For demo, return the actual provider key
    credential = %{
      id: "cred_#{:crypto.strong_rand_bytes(8) |> Base.url_encode64(padding: false)}",
      customer_id: customer_id,
      provider: provider,
      api_key: @provider_keys[provider] || "mock_key_#{provider}",
      encrypted_key: @provider_keys[provider] || "mock_key_#{provider}",  # For compatibility
      expires_at: expires_at,
      usage_limit: usage_limit
    }
    
    Logger.info("Created temporary credential for customer #{customer_id}, provider #{provider}")
    {:ok, credential}
  end
  
  @doc """
  Updates metadata for a credential.
  """
  def update_metadata(credential, metadata) do
    Logger.info("Updating credential metadata: #{inspect(metadata)}")
    {:ok, Map.merge(credential, metadata)}
  end
  
  @doc """
  Stores a credential with TTL.
  """
  def store_credential(customer_id, provider, credential, ttl_minutes) do
    # In production, this would store in Redis or database
    # For now, we'll just return success
    Logger.info("Storing credential for customer #{customer_id}, provider #{provider}, TTL #{ttl_minutes}m")
    {:ok, credential}
  end
  
  @doc """
  Gets a stored credential by ID.
  """
  def get_credential(credential_id, customer_id) do
    # Mock implementation
    {:ok, %{
      id: credential_id,
      customer_id: customer_id,
      api_key: "vended_#{credential_id}",
      expires_at: DateTime.add(DateTime.utc_now(), 3600, :second)
    }}
  end
  
  @doc """
  Refreshes a credential before expiry.
  """
  def refresh_credential(credential_id, customer_id) do
    # Mock implementation
    {:ok, %{
      id: "refreshed_#{credential_id}",
      customer_id: customer_id,
      api_key: "refreshed_vended_#{credential_id}",
      expires_at: DateTime.add(DateTime.utc_now(), 3600, :second)
    }}
  end
end