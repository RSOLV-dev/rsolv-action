defmodule RSOLVWeb.PatternController do
  use RSOLVWeb, :controller

  alias RsolvApi.Security
  alias RSOLV.Accounts
  alias RsolvApi.FeatureFlags

  action_fallback RSOLVWeb.FallbackController

  @doc """
  GET /api/v1/patterns/public/:language
  Public patterns - no authentication required
  """
  def public(conn, %{"language" => language}) do
    if FeatureFlags.tier_access_allowed?("public", nil) do
      patterns = Security.list_patterns_by_language_and_tier(language, "public")
      formatted_patterns = Security.format_patterns_for_api(patterns)
      
      json(conn, %{
        patterns: formatted_patterns,
        tier: "public",
        language: language,
        count: length(formatted_patterns)
      })
    else
      {:error, :public_patterns_disabled}
    end
  end

  @doc """
  GET /api/v1/patterns/protected/:language
  Protected patterns - API key required
  """
  def protected(conn, %{"language" => language}) do
    with {:ok, _customer} <- authenticate_request(conn) do
      patterns = Security.list_patterns_by_language_and_tier(language, "protected")
      formatted_patterns = Security.format_patterns_for_api(patterns)
      
      json(conn, %{
        patterns: formatted_patterns,
        tier: "protected",
        language: language,
        count: length(formatted_patterns)
      })
    end
  end

  @doc """
  GET /api/v1/patterns/ai/:language
  AI patterns - API key + AI flag required
  """
  def ai(conn, %{"language" => language}) do
    with {:ok, customer} <- authenticate_request(conn),
         true <- has_ai_access?(customer) do
      patterns = Security.list_patterns_by_language_and_tier(language, "ai")
      formatted_patterns = Security.format_patterns_for_api(patterns)
      
      json(conn, %{
        patterns: formatted_patterns,
        tier: "ai",
        language: language,
        count: length(formatted_patterns)
      })
    else
      false ->
        {:error, :ai_access_denied}
      
      error ->
        error
    end
  end

  @doc """
  GET /api/v1/patterns/enterprise/:language
  Enterprise patterns - Enterprise auth required
  """
  def enterprise(conn, %{"language" => language}) do
    with {:ok, customer} <- authenticate_request(conn),
         true <- is_enterprise?(customer) do
      patterns = Security.list_patterns_by_language_and_tier(language, "enterprise")
      formatted_patterns = Security.format_patterns_for_api(patterns)
      
      json(conn, %{
        patterns: formatted_patterns,
        tier: "enterprise",
        language: language,
        count: length(formatted_patterns)
      })
    else
      false ->
        {:error, :enterprise_access_denied}
      
      error ->
        error
    end
  end

  @doc """
  GET /api/v1/patterns/:language
  Combined patterns based on customer's access level
  """
  def by_language(conn, %{"language" => language}) do
    # Determine accessible tiers based on authentication
    {api_key, customer, ai_enabled} = get_auth_context(conn)
    accessible_tiers = Security.get_accessible_tiers(api_key, customer, ai_enabled)
    
    patterns = Security.list_patterns_by_language(language, accessible_tiers)
    formatted_patterns = Security.format_patterns_for_api(patterns)
    
    json(conn, %{
      patterns: formatted_patterns,
      accessible_tiers: accessible_tiers,
      language: language,
      count: length(formatted_patterns)
    })
  end

  @doc """
  GET /api/v1/patterns/public
  All public patterns (cross-language) - no authentication required
  """
  def all_public(conn, _params) do
    if FeatureFlags.tier_access_allowed?("public", nil) do
      patterns = Security.list_patterns_by_tier("public")
      formatted_patterns = Security.format_patterns_for_api(patterns)
      
      json(conn, %{
        patterns: formatted_patterns,
        tier: "public",
        language: "all",
        count: length(formatted_patterns)
      })
    else
      {:error, :public_patterns_disabled}
    end
  end

  @doc """
  GET /api/v1/patterns/protected
  All protected patterns (cross-language) - API key required
  """
  def all_protected(conn, _params) do
    with {:ok, _customer} <- authenticate_request(conn) do
      patterns = Security.list_patterns_by_tier("protected")
      formatted_patterns = Security.format_patterns_for_api(patterns)
      
      json(conn, %{
        patterns: formatted_patterns,
        tier: "protected",
        language: "all",
        count: length(formatted_patterns)
      })
    end
  end

  @doc """
  GET /api/v1/patterns/ai
  All AI patterns (cross-language) - API key + AI flag required
  """
  def all_ai(conn, _params) do
    with {:ok, customer} <- authenticate_request(conn),
         true <- has_ai_access?(customer) do
      patterns = Security.list_patterns_by_tier("ai")
      formatted_patterns = Security.format_patterns_for_api(patterns)
      
      json(conn, %{
        patterns: formatted_patterns,
        tier: "ai",
        language: "all",
        count: length(formatted_patterns)
      })
    else
      false ->
        {:error, :ai_access_denied}
      
      error ->
        error
    end
  end

  @doc """
  GET /api/v1/patterns/enterprise
  All enterprise patterns (cross-language) - Enterprise auth required
  """
  def all_enterprise(conn, _params) do
    with {:ok, customer} <- authenticate_request(conn),
         true <- is_enterprise?(customer) do
      patterns = Security.list_patterns_by_tier("enterprise")
      formatted_patterns = Security.format_patterns_for_api(patterns)
      
      json(conn, %{
        patterns: formatted_patterns,
        tier: "enterprise",
        language: "all",
        count: length(formatted_patterns)
      })
    else
      false ->
        {:error, :enterprise_access_denied}
      
      error ->
        error
    end
  end

  @doc """
  GET /api/v1/patterns
  All patterns based on customer's access level (cross-language)
  """
  def all(conn, _params) do
    # Determine accessible tiers based on authentication
    {api_key, customer, ai_enabled} = get_auth_context(conn)
    accessible_tiers = Security.get_accessible_tiers(api_key, customer, ai_enabled)
    
    patterns = Security.list_all_patterns(accessible_tiers)
    formatted_patterns = Security.format_patterns_for_api(patterns)
    
    json(conn, %{
      patterns: formatted_patterns,
      accessible_tiers: accessible_tiers,
      language: "all",
      count: length(formatted_patterns)
    })
  end

  # Private functions

  defp authenticate_request(conn) do
    case get_req_header(conn, "authorization") do
      ["Bearer " <> api_key] ->
        case Accounts.get_customer_by_api_key(api_key) do
          nil ->
            {:error, :invalid_api_key}

          customer ->
            {:ok, customer}
        end

      _ ->
        {:error, :missing_api_key}
    end
  end

  defp get_auth_context(conn) do
    case get_req_header(conn, "authorization") do
      ["Bearer " <> api_key] ->
        customer = Accounts.get_customer_by_api_key(api_key)
        # Grant AI access to all authenticated customers for now
        ai_enabled = customer != nil
        {api_key, customer, ai_enabled}

      _ ->
        {nil, nil, false}
    end
  end

  defp has_ai_access?(customer) do
    # Use feature flags to determine AI access
    FeatureFlags.tier_access_allowed?("ai", customer)
  end

  defp is_enterprise?(customer) do
    # Use feature flags to determine enterprise access
    FeatureFlags.tier_access_allowed?("enterprise", customer)
  end
end