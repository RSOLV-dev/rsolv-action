defmodule RSOLVWeb.CredentialController do
  use RSOLVWeb, :controller

  alias RSOLV.Accounts
  alias RSOLV.Credentials
  alias RSOLV.RateLimiter

  require Logger

  @max_ttl_minutes 240  # 4 hours max

  def exchange(conn, params) do
    Logger.info("[CredentialController] Starting exchange with params: #{inspect(params)}")
    
    with {:ok, api_key} <- validate_api_key(params),
         {:ok, customer} <- authenticate_customer(api_key),
         :ok <- check_rate_limit(customer),
         :ok <- check_usage_limits(customer),
         {:ok, providers} <- validate_providers(params),
         {:ok, ttl_minutes} <- validate_ttl(params) do
      
      Logger.info("[CredentialController] About to call generate_credentials")
      
      result = try do
        generate_credentials(customer, providers, ttl_minutes)
      rescue
        e ->
          Logger.error("[CredentialController] Error in generate_credentials: #{inspect(e)}")
          Logger.error("[CredentialController] Stack trace: #{inspect(__STACKTRACE__)}")
          {:error, :generation_failed}
      end
      
      case result do
        {:ok, credentials} ->
          Logger.info("[CredentialController] generate_credentials succeeded")
          
          :ok = store_github_metadata(conn, credentials)
          
          conn
          |> put_status(:ok)
          |> json(%{
            credentials: format_credentials(credentials),
            usage: %{
              remaining_fixes: customer.monthly_limit - customer.current_usage,
              reset_at: get_reset_date()
            }
          })
        
        {:error, _reason} ->
          conn
          |> put_status(:internal_server_error)
          |> json(%{error: "Failed to generate credentials"})
      end
    else
      {:error, :invalid_api_key} ->
        conn
        |> put_status(:unauthorized)
        |> json(%{error: "Invalid API key"})
      
      {:error, :rate_limited} ->
        conn
        |> put_status(:too_many_requests)
        |> put_resp_header("retry-after", "60")
        |> json(%{error: "Rate limit exceeded", retry_after: 60})
      
      {:error, :usage_limit_exceeded} ->
        conn
        |> put_status(:forbidden)
        |> json(%{error: "Monthly usage limit exceeded"})
      
      {:error, :missing_parameters} ->
        conn
        |> put_status(:bad_request)
        |> json(%{error: "Missing required parameters"})
      
      error ->
        Logger.error("Credential exchange error: #{inspect(error)}")
        conn
        |> put_status(:internal_server_error)
        |> json(%{error: "Internal server error"})
    end
  end

  def refresh(conn, params) do
    with {:ok, api_key} <- validate_api_key(params),
         {:ok, customer} <- authenticate_customer(api_key),
         {:ok, credential_id} <- validate_credential_id(params),
         {:ok, credential} <- get_customer_credential(customer, credential_id),
         :ok <- check_refresh_eligibility(credential),
         {:ok, new_credential} <- refresh_credential(credential) do
      
      conn
      |> put_status(:ok)
      |> json(%{
        credentials: %{
          credential.provider => %{
            api_key: decrypt_credential(new_credential),
            expires_at: new_credential.expires_at
          }
        }
      })
    else
      {:error, :not_found} ->
        conn
        |> put_status(:not_found)
        |> json(%{error: "Credential not found"})
      
      {:error, :access_denied} ->
        conn
        |> put_status(:forbidden)
        |> json(%{error: "Access denied"})
      
      {:error, :not_eligible_for_refresh} ->
        conn
        |> put_status(:bad_request)
        |> json(%{error: "Credential not eligible for refresh"})
      
      error ->
        Logger.error("Credential refresh error: #{inspect(error)}")
        conn
        |> put_status(:internal_server_error)
        |> json(%{error: "Internal server error"})
    end
  end

  def report_usage(conn, params) do
    with {:ok, api_key} <- validate_api_key(params),
         {:ok, customer} <- authenticate_customer(api_key),
         {:ok, usage_data} <- validate_usage_data(params),
         :ok <- record_usage(customer, usage_data),
         :ok <- update_customer_usage(customer, usage_data) do
      
      conn
      |> put_status(:ok)
      |> json(%{status: "recorded"})
    else
      {:error, :invalid_api_key} ->
        conn
        |> put_status(:unauthorized)
        |> json(%{error: "Invalid API key"})
      
      error ->
        Logger.error("Usage reporting error: #{inspect(error)}")
        conn
        |> put_status(:internal_server_error)
        |> json(%{error: "Internal server error"})
    end
  end

  # Private functions

  defp validate_api_key(%{"api_key" => api_key}) when is_binary(api_key), do: {:ok, api_key}
  defp validate_api_key(_), do: {:error, :missing_parameters}

  defp authenticate_customer(api_key) do
    Logger.info("[CredentialController] Authenticating API key: #{api_key}")
    
    case Accounts.get_customer_by_api_key(api_key) do
      nil -> 
        Logger.error("[CredentialController] No customer found for API key: #{api_key}")
        {:error, :invalid_api_key}
      customer -> 
        Logger.info("[CredentialController] Found customer: #{customer.name} (ID: #{customer.id})")
        {:ok, customer}
    end
  end

  defp check_rate_limit(customer) do
    case RateLimiter.check_rate_limit(customer.id, :credential_exchange) do
      :ok -> :ok
      {:error, :rate_limited} -> {:error, :rate_limited}
    end
  end

  defp check_usage_limits(customer) do
    if customer.current_usage >= customer.monthly_limit do
      {:error, :usage_limit_exceeded}
    else
      :ok
    end
  end

  defp validate_providers(%{"providers" => providers}) when is_list(providers) do
    valid_providers = ["anthropic", "openai", "openrouter", "ollama"]
    
    if Enum.all?(providers, &(&1 in valid_providers)) do
      {:ok, providers}
    else
      {:error, :invalid_providers}
    end
  end
  defp validate_providers(_), do: {:error, :missing_parameters}

  defp validate_ttl(%{"ttl_minutes" => ttl}) when is_integer(ttl) do
    {:ok, min(ttl, @max_ttl_minutes)}
  end
  defp validate_ttl(_), do: {:ok, 60}  # Default 1 hour

  defp generate_credentials(customer, providers, ttl_minutes) do
    Logger.info("Starting credential generation for customer #{customer.id}, providers: #{inspect(providers)}")
    
    credentials = Enum.map(providers, fn provider ->
      Logger.info("Generating credential for provider: #{provider}")
      generate_provider_credential(customer, provider, ttl_minutes)
    end)
    
    Logger.info("Successfully generated #{length(credentials)} credentials")
    {:ok, credentials}
  rescue
    e ->
      Logger.error("Failed to generate credentials: #{inspect(e)}")
      Logger.error("Stack trace: #{inspect(__STACKTRACE__)}")
      {:error, :generation_failed}
  end

  defp generate_provider_credential(customer, provider, ttl_minutes) do
    expires_at = DateTime.add(DateTime.utc_now(), ttl_minutes * 60, :second)
    
    # Let the Credentials module handle the actual API key retrieval
    {:ok, credential} = Credentials.create_temporary_credential(%{
      customer_id: customer.id,
      provider: provider,
      expires_at: expires_at,
      usage_limit: customer.monthly_limit - customer.current_usage
    })
    
    credential
  end

  defp store_github_metadata(conn, credentials) do
    job_id = get_req_header(conn, "x-github-job") |> List.first()
    run_id = get_req_header(conn, "x-github-run") |> List.first()
    
    if job_id || run_id do
      Enum.each(credentials, fn credential ->
        Credentials.update_metadata(credential, %{
          github_job_id: job_id,
          github_run_id: run_id
        })
      end)
    end
    
    :ok
  end

  defp format_credentials(credentials) do
    Enum.reduce(credentials, %{}, fn credential, acc ->
      Map.put(acc, credential.provider, %{
        api_key: decrypt_credential(credential),
        expires_at: DateTime.to_iso8601(credential.expires_at)
      })
    end)
  end

  defp decrypt_credential(credential) do
    # Return the actual API key from the credential
    # In production, this would decrypt the encrypted_key
    credential.api_key || credential.encrypted_key
  end

  defp get_reset_date do
    now = DateTime.utc_now()
    
    now
    |> DateTime.to_date()
    |> Date.beginning_of_month()
    |> Date.add(Date.days_in_month(now))
    |> DateTime.new!(~T[00:00:00], "Etc/UTC")
    |> DateTime.to_iso8601()
  end

  defp validate_credential_id(%{"credential_id" => id}) when is_binary(id), do: {:ok, id}
  defp validate_credential_id(_), do: {:error, :missing_parameters}

  defp get_customer_credential(customer, credential_id) do
    case Credentials.get_credential(credential_id) do
      nil -> 
        {:error, :not_found}
      credential ->
        if credential.customer_id == customer.id do
          {:ok, credential}
        else
          {:error, :access_denied}
        end
    end
  end

  defp check_refresh_eligibility(credential) do
    # Allow refresh if credential expires within 5 minutes
    if DateTime.diff(credential.expires_at, DateTime.utc_now()) < 300 do
      :ok
    else
      {:error, :not_eligible_for_refresh}
    end
  end

  defp refresh_credential(old_credential) do
    # Revoke old credential
    Credentials.revoke_credential(old_credential)
    
    # Generate new credential with same provider
    new_credential = generate_provider_credential(
      %{id: old_credential.customer_id, monthly_limit: 100, current_usage: 0},
      old_credential.provider,
      60  # 1 hour TTL for refreshed credentials
    )
    
    {:ok, new_credential}
  end

  defp validate_usage_data(params) do
    with {:ok, provider} <- validate_provider(params),
         {:ok, tokens} <- validate_tokens(params),
         {:ok, requests} <- validate_requests(params) do
      {:ok, %{
        provider: provider,
        tokens_used: tokens,
        request_count: requests,
        job_id: params["job_id"]
      }}
    else
      _ -> {:error, :invalid_usage_data}
    end
  end

  defp validate_provider(%{"provider" => provider}) when is_binary(provider), do: {:ok, provider}
  defp validate_provider(_), do: {:error, :missing_provider}

  defp validate_tokens(%{"tokens_used" => tokens}) when is_integer(tokens), do: {:ok, tokens}
  defp validate_tokens(_), do: {:error, :missing_tokens}

  defp validate_requests(%{"request_count" => count}) when is_integer(count), do: {:ok, count}
  defp validate_requests(_), do: {:error, :missing_requests}

  defp record_usage(customer, usage_data) do
    case Accounts.record_usage(%{
      customer_id: customer.id,
      provider: usage_data.provider,
      tokens_used: usage_data.tokens_used,
      request_count: usage_data.request_count,
      job_id: usage_data.job_id
    }) do
      {:ok, _} -> :ok
      error -> error
    end
  end

  defp update_customer_usage(customer, usage_data) do
    # Approximate 1 fix per 2000 tokens
    fixes_used = div(usage_data.tokens_used, 2000)
    new_usage = customer.current_usage + fixes_used
    
    case Accounts.update_customer(customer, %{current_usage: new_usage}) do
      {:ok, _} -> :ok
      error -> error
    end
  end
end