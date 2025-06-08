defmodule RSOLVWeb.PatternController do
  use RSOLVWeb, :controller

  alias RsolvApi.Security
  alias RSOLV.Accounts

  action_fallback RSOLVWeb.FallbackController

  @doc """
  GET /api/v1/patterns/public/:language
  Public patterns - no authentication required
  """
  def public(conn, %{"language" => language}) do
    patterns = Security.list_patterns_by_language_and_tier(language, "public")
    formatted_patterns = Security.format_patterns_for_api(patterns)
    
    json(conn, %{
      patterns: formatted_patterns,
      tier: "public",
      language: language,
      count: length(formatted_patterns)
    })
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
        conn
        |> put_status(:forbidden)
        |> json(%{error: "AI pattern access not enabled for this account"})
      
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
        conn
        |> put_status(:forbidden)
        |> json(%{error: "Enterprise tier required"})
      
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

  # Private functions

  defp authenticate_request(conn) do
    case get_req_header(conn, "authorization") do
      ["Bearer " <> api_key] ->
        case Accounts.get_customer_by_api_key(api_key) do
          nil ->
            conn
            |> put_status(:unauthorized)
            |> json(%{error: "Invalid API key"})
            |> halt()

          customer ->
            {:ok, customer}
        end

      _ ->
        conn
        |> put_status(:unauthorized)
        |> json(%{error: "API key required"})
        |> halt()
    end
  end

  defp get_auth_context(conn) do
    case get_req_header(conn, "authorization") do
      ["Bearer " <> api_key] ->
        customer = Accounts.get_customer_by_api_key(api_key)
        ai_enabled = customer && customer.ai_enabled
        {api_key, customer, ai_enabled}

      _ ->
        {nil, nil, false}
    end
  end

  defp has_ai_access?(customer) do
    customer && customer.ai_enabled
  end

  defp is_enterprise?(customer) do
    customer && customer.tier == "enterprise"
  end
end