defmodule RSOLV.Credentials do
  @moduledoc """
  The Credentials context for managing AI provider credentials.
  """
  
  require Logger
  
  # Storage for credential tracking
  @credentials_table {__MODULE__, :credentials}
  
  # Get provider keys at runtime - generate temp keys for testing
  defp get_provider_key(provider) do
    case provider do
      "anthropic" -> 
        if Mix.env() == :test do
          "temp_ant_#{:crypto.strong_rand_bytes(8) |> Base.url_encode64(padding: false)}"
        else
          System.get_env("ANTHROPIC_API_KEY") || "sk-ant-mock-key"
        end
      "openai" -> 
        if Mix.env() == :test do
          "temp_oai_#{:crypto.strong_rand_bytes(8) |> Base.url_encode64(padding: false)}"
        else
          System.get_env("OPENAI_API_KEY") || "sk-mock-key"
        end
      "openrouter" -> System.get_env("OPENROUTER_API_KEY") || "sk-or-mock-key"
      "ollama" -> "local"
      _ -> "mock_key_#{provider}"
    end
  end
  
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
      api_key: get_provider_key(provider),
      encrypted_key: get_provider_key(provider),  # For compatibility
      expires_at: expires_at,
      usage_limit: usage_limit
    }
    
    # Track credential creation for count
    track_credential(credential)
    
    Logger.info("Created temporary credential for customer #{customer_id}, provider #{provider}")
    {:ok, credential}
  end
  
  @doc """
  Updates metadata for a credential.
  """
  def update_metadata(credential, metadata) do
    Logger.info("Updating credential metadata: #{inspect(metadata)}")
    updated_credential = Map.merge(credential, metadata)
    
    # Update the credential in storage
    credentials = :persistent_term.get(@credentials_table, [])
    updated_credentials = Enum.map(credentials, fn cred ->
      if cred.id == credential.id do
        updated_credential
      else
        cred
      end
    end)
    :persistent_term.put(@credentials_table, updated_credentials)
    
    {:ok, updated_credential}
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
  Gets a stored credential by ID only.
  """
  def get_credential(credential_id) do
    # Mock implementation
    %{
      id: credential_id,
      customer_id: "test_customer",
      api_key: "vended_#{credential_id}",
      expires_at: DateTime.add(DateTime.utc_now(), 3600, :second)
    }
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
  
  @doc """
  Counts active credentials for a customer.
  """
  def count_active_credentials(customer_id) do
    # Count credentials for this customer
    credentials = :persistent_term.get(@credentials_table, [])
    count = Enum.count(credentials, fn cred -> 
      cred.customer_id == customer_id and not Map.get(cred, :revoked, false)
    end)
    
    Logger.info("Counting active credentials for customer #{customer_id}")
    {:ok, count}
  end
  
  @doc """
  Gets the latest credential for a customer.
  """
  def get_latest_credential(customer_id) do
    # Get the most recent credential for this customer
    credentials = :persistent_term.get(@credentials_table, [])
    customer_credentials = Enum.filter(credentials, fn cred -> 
      cred.customer_id == customer_id 
    end)
    
    case customer_credentials do
      [] -> 
        # Return mock if no credentials found
        %{
          id: "latest_cred_#{customer_id}",
          customer_id: customer_id,
          provider: "anthropic",
          github_job_id: nil,
          github_run_id: nil,
          created_at: DateTime.utc_now()
        }
      [latest | _] -> latest  # Return the first (most recent) credential
    end
  end
  
  @doc """
  Revokes a credential.
  """
  def revoke_credential(credential) do
    # Mock implementation
    Logger.info("Revoking credential #{credential.id}")
    {:ok, Map.put(credential, :revoked, true)}
  end
  
  # Pattern match for create_temporary_credential with simpler parameters
  def create_temporary_credential(%{
    customer_id: customer_id,
    provider: provider,
    expires_at: expires_at
  } = params) when not is_map_key(params, :encrypted_key) do
    create_temporary_credential(%{
      customer_id: customer_id,
      provider: provider,
      encrypted_key: get_provider_key(provider),
      expires_at: expires_at,
      usage_limit: 100
    })
  end
  
  # Helper function to track credentials
  defp track_credential(credential) do
    credentials = :persistent_term.get(@credentials_table, [])
    new_credentials = [credential | credentials]
    :persistent_term.put(@credentials_table, new_credentials)
  end
  
  @doc """
  Reset credential storage (for testing).
  """
  def reset_credentials() do
    :persistent_term.put(@credentials_table, [])
    :ok
  end
end