defmodule Rsolv.Credentials do
  @moduledoc """
  The Credentials context for managing AI provider credentials.

  ## Credential Vending Architecture

  This module implements temporary credential vending for AI providers. When customers
  request credentials via `/api/v1/credentials/exchange`, we return time-limited API keys
  for the requested providers.

  ## Graceful Fallback Behavior

  **IMPORTANT**: This module uses graceful fallback to mock keys when provider API keys
  are not configured in the environment:

  - `ANTHROPIC_API_KEY` → falls back to `"sk-ant-mock-key"`
  - `OPENAI_API_KEY` → falls back to `"sk-mock-key"`
  - `OPENROUTER_API_KEY` → falls back to `"sk-or-mock-key"`

  This design allows:
  - ✅ Application continues running without all provider keys configured
  - ✅ Anthropic-only deployments (primary use case) work without OpenAI/OpenRouter keys
  - ⚠️ Credential exchange succeeds even with mock keys (no validation at vending time)
  - ⚠️ Customers receive mock keys for unconfigured providers (will fail at AI provider API)

  See `RSOLV-infrastructure/DEPLOYMENT.md` for operational guidance on which keys to populate.
  See `RFCs/RFC-057-FIX-CREDENTIAL-VENDING.md` for architecture details.
  """

  require Logger

  # Storage for credential tracking
  @credentials_table {__MODULE__, :credentials}

  # Get provider keys at runtime with graceful fallback to mock keys for testing/partial deployments
  defp get_provider_key(provider) do
    case provider do
      "anthropic" ->
        # Try both uppercase and lowercase with hyphens (Kubernetes style)
        System.get_env("ANTHROPIC_API_KEY") || System.get_env("anthropic-api-key") ||
          "sk-ant-mock-key"

      "openai" ->
        # Try both uppercase and lowercase with hyphens (Kubernetes style)
        System.get_env("OPENAI_API_KEY") || System.get_env("openai-api-key") || "sk-mock-key"

      "openrouter" ->
        System.get_env("OPENROUTER_API_KEY") || System.get_env("openrouter-api-key") ||
          "sk-or-mock-key"

      "ollama" ->
        "local"

      _ ->
        "mock_key_#{provider}"
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
    Logger.info(
      "[Credentials] Starting create_temporary_credential for customer #{customer_id}, provider #{provider}"
    )

    # In production, this would store in database
    # For demo, return the actual provider key
    provider_key =
      try do
        Logger.info("[Credentials] Getting provider key for #{provider}")
        get_provider_key(provider)
      rescue
        e ->
          Logger.error("[Credentials] Error getting provider key: #{inspect(e)}")
          Logger.error("[Credentials] Stack trace: #{inspect(__STACKTRACE__)}")
          reraise e, __STACKTRACE__
      end

    Logger.info("[Credentials] Got provider key for #{provider}")

    credential = %{
      id: "cred_#{:crypto.strong_rand_bytes(8) |> Base.url_encode64(padding: false)}",
      customer_id: customer_id,
      provider: provider,
      api_key: provider_key,
      # For compatibility
      encrypted_key: provider_key,
      expires_at: expires_at,
      usage_limit: usage_limit
    }

    # Track credential creation for count
    track_credential(credential)

    Logger.info("Created temporary credential for customer #{customer_id}, provider #{provider}")
    {:ok, credential}
  end

  # Pattern match for create_temporary_credential with simpler parameters
  def create_temporary_credential(
        %{
          customer_id: customer_id,
          provider: provider,
          expires_at: expires_at
        } = params
      )
      when not is_map_key(params, :encrypted_key) do
    create_temporary_credential(%{
      customer_id: customer_id,
      provider: provider,
      encrypted_key: get_provider_key(provider),
      expires_at: expires_at,
      usage_limit: 100
    })
  end

  @doc """
  Updates metadata for a credential.
  """
  def update_metadata(credential, metadata) do
    Logger.info("Updating credential #{credential.id} metadata: #{inspect(metadata)}")
    updated_credential = Map.merge(credential, metadata)

    # Update the credential in storage
    credentials = :persistent_term.get(@credentials_table, [])
    Logger.info("Found #{length(credentials)} stored credentials, looking for #{credential.id}")

    {updated_credentials, found} =
      Enum.map_reduce(credentials, false, fn cred, acc ->
        if cred.id == credential.id do
          Logger.info("Found and updating credential #{credential.id}")
          {updated_credential, true}
        else
          {cred, acc}
        end
      end)

    if found do
      :persistent_term.put(@credentials_table, updated_credentials)
      Logger.info("Successfully updated credential #{credential.id} in storage")
    else
      Logger.warning("Credential #{credential.id} not found in storage!")
    end

    {:ok, updated_credential}
  end

  @doc """
  Stores a credential with TTL.
  """
  def store_credential(customer_id, provider, credential, ttl_minutes) do
    # In production, this would store in DETS for distributed persistence
    # For now, we'll just return success
    Logger.info(
      "Storing credential for customer #{customer_id}, provider #{provider}, TTL #{ttl_minutes}m"
    )

    {:ok, credential}
  end

  @doc """
  Gets a stored credential by ID.
  """
  def get_credential(credential_id, customer_id) do
    # Mock implementation
    {:ok,
     %{
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
    # Look for credential in storage
    credentials = :persistent_term.get(@credentials_table, [])

    case Enum.find(credentials, fn cred -> cred.id == credential_id end) do
      # Return nil if not found (will trigger 404)
      nil -> nil
      credential -> credential
    end
  end

  @doc """
  Refreshes a credential before expiry.
  """
  def refresh_credential(credential_id, customer_id) do
    # Mock implementation
    {:ok,
     %{
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

    count =
      Enum.count(credentials, fn cred ->
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
    Logger.info("get_latest_credential: Found #{length(credentials)} total credentials")

    customer_credentials =
      Enum.filter(credentials, fn cred ->
        cred.customer_id == customer_id
      end)

    Logger.info(
      "get_latest_credential: Found #{length(customer_credentials)} credentials for customer #{customer_id}"
    )

    case customer_credentials do
      [] ->
        Logger.info("get_latest_credential: No credentials found, returning mock")
        # Return mock if no credentials found
        %{
          id: "latest_cred_#{customer_id}",
          customer_id: customer_id,
          provider: "anthropic",
          github_job_id: nil,
          github_run_id: nil,
          created_at: DateTime.utc_now()
        }

      [latest | _] ->
        Logger.info(
          "get_latest_credential: Returning credential #{latest.id}, github_job_id: #{Map.get(latest, :github_job_id, "nil")}"
        )

        # Return the first (most recent) credential
        latest
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
