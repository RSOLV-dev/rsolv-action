defmodule RsolvApi.Webhooks.EventRouter do
  @moduledoc """
  Routes webhook events from various platforms to appropriate handlers.
  Supports multi-platform webhook processing with extensible architecture.
  """

  alias RsolvApi.Webhooks.Handlers.GitHubHandler
  
  @doc """
  Routes incoming webhook event to the appropriate platform handler
  """
  def route_event(platform, headers, payload) do
    case platform do
      "github" ->
        event_type = get_header(headers, "x-github-event")
        route_github_event(event_type, payload)
        
      "gitlab" ->
        {:error, :platform_not_implemented}
        
      _ ->
        {:error, :unsupported_platform}
    end
  end
  
  @doc """
  Verifies webhook signature based on platform
  """
  def verify_signature(platform, signature, payload, secret) do
    case platform do
      "github" ->
        verify_github_signature(signature, payload, secret)
        
      "gitlab" ->
        {:error, :platform_not_implemented}
        
      _ ->
        {:error, :unsupported_platform}
    end
  end
  
  @doc """
  Extracts platform from webhook headers
  """
  def extract_platform(headers) do
    cond do
      get_header(headers, "x-github-event") != nil ->
        "github"
        
      get_header(headers, "x-gitlab-event") != nil ->
        "gitlab"
        
      true ->
        "unknown"
    end
  end
  
  # Private functions
  
  defp route_github_event(event_type, payload) do
    case event_type do
      "pull_request" ->
        GitHubHandler.handle_event("pull_request", payload)
        
      "issues" ->
        GitHubHandler.handle_event("issues", payload)
        
      nil ->
        {:error, :missing_event_type}
        
      _ ->
        {:error, :unsupported_event}
    end
  end
  
  defp verify_github_signature(nil, _payload, _secret) do
    {:error, :missing_signature}
  end
  
  defp verify_github_signature(signature, payload, secret) do
    expected_signature = compute_github_signature(payload, secret)
    
    # Debug logging
    require Logger
    Logger.debug("Signature verification - received: #{signature}")
    Logger.debug("Signature verification - expected: #{expected_signature}")
    
    if secure_compare(signature, expected_signature) do
      :ok
    else
      {:error, :invalid_signature}
    end
  end
  
  defp compute_github_signature(payload, secret) do
    "sha256=" <> Base.encode16(:crypto.mac(:hmac, :sha256, secret, payload), case: :lower)
  end
  
  defp secure_compare(a, b) do
    # Constant-time comparison to prevent timing attacks
    if byte_size(a) == byte_size(b) do
      a_hash = :crypto.hash(:sha256, a)
      b_hash = :crypto.hash(:sha256, b)
      a_hash == b_hash
    else
      false
    end
  end
  
  defp get_header(headers, key) do
    headers
    |> Enum.find(fn {k, _v} -> String.downcase(k) == String.downcase(key) end)
    |> case do
      {_k, v} -> v
      nil -> nil
    end
  end
end