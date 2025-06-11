defmodule RSOLVWeb.PatternController do
  use RSOLVWeb, :controller

  alias RsolvApi.Security
  alias RsolvApi.Security.{ASTPattern, Pattern}
  alias RSOLV.Accounts
  alias RsolvApi.FeatureFlags
  
  # Require refactored pattern modules so they're available at runtime
  require RsolvApi.Security.Patterns.Javascript.SqlInjectionConcat
  require RsolvApi.Security.Patterns.Javascript.SqlInjectionInterpolation
  require RsolvApi.Security.Patterns.Javascript.XssInnerhtml
  require RsolvApi.Security.Patterns.Javascript.XssDocumentWrite

  action_fallback RSOLVWeb.FallbackController
  
  @doc """
  GET /api/v1/patterns
  Get patterns based on query parameters
  
  Query params:
  - language: javascript, python, ruby, etc. (default: javascript)
  - tier: public, protected, ai, enterprise (default: public)
  - format: standard or enhanced (default: standard)
  """
  def index(conn, params) do
    language = params["language"] || "javascript"
    tier = String.to_existing_atom(params["tier"] || "public")
    format = String.to_existing_atom(params["format"] || "standard")
    
    patterns = ASTPattern.get_patterns(language, tier, format)
    
    # Convert patterns to API format
    formatted_patterns = Enum.map(patterns, &format_pattern(&1, format))
    
    # Add metadata for monitoring
    metadata = %{
      language: language,
      tier: to_string(tier),
      format: to_string(format),
      count: length(patterns),
      enhanced: format == :enhanced
    }
    
    conn
    |> put_resp_header("x-pattern-version", "2.0")
    |> json(%{
      patterns: formatted_patterns,
      metadata: metadata
    })
  end
  
  defp format_pattern(%ASTPattern{} = pattern, :enhanced) do
    # For enhanced patterns, include all fields
    %{
      id: pattern.id,
      name: pattern.name,
      description: pattern.description,
      type: to_string(pattern.type),
      severity: to_string(pattern.severity),
      languages: pattern.languages,
      frameworks: pattern.frameworks || [],
      patterns: ensure_list(regex_to_string(pattern.regex)),
      cwe_id: pattern.cwe_id,
      owasp_category: pattern.owasp_category,
      recommendation: pattern.recommendation,
      test_cases: pattern.test_cases,
      # AST enhancement fields
      ast_rules: format_ast_rules(pattern.ast_rules),
      context_rules: format_context_rules(pattern.context_rules),
      confidence_rules: pattern.confidence_rules,
      min_confidence: pattern.min_confidence
    }
  end
  
  defp format_pattern(%ASTPattern{} = pattern, :standard) do
    # For AST patterns in standard format, convert to standard format
    Pattern.to_api_format(pattern)
  end
  
  defp format_pattern(pattern, :standard) do
    # For standard patterns, use existing Pattern.to_api_format/1
    Pattern.to_api_format(pattern)
  end
  
  defp format_pattern(pattern, format) do
    # Catch-all for debugging
    require Logger
    Logger.warn("Unmatched format_pattern: struct=#{pattern.__struct__}, format=#{format}")
    Pattern.to_api_format(pattern)
  end
  
  defp regex_to_string(%Regex{} = regex), do: Regex.source(regex)
  defp regex_to_string(regexes) when is_list(regexes) do
    Enum.map(regexes, fn 
      %Regex{} = r -> Regex.source(r)
      other -> to_string(other)
    end)
  end
  defp regex_to_string(other), do: to_string(other)
  
  defp format_context_rules(nil), do: nil
  defp format_context_rules(rules) when is_map(rules) do
    Map.new(rules, fn
      {:exclude_paths, paths} when is_list(paths) ->
        {:exclude_paths, Enum.map(paths, &regex_to_string/1)}
      {k, v} ->
        {k, v}
    end)
  end
  
  defp format_ast_rules(nil), do: nil
  defp format_ast_rules(rules) when is_map(rules) do
    Map.new(rules, fn
      {:parent_node, parent} when is_map(parent) ->
        {:parent_node, Map.new(parent, fn
          {:callee_matches, regex} -> {:callee_matches, regex_to_string(regex)}
          {k, v} -> {k, v}
        end)}
      {:name_matches, regex} -> {:name_matches, regex_to_string(regex)}
      {:body_excludes, regex} -> {:body_excludes, regex_to_string(regex)}
      {k, v} -> {k, v}
    end)
  end

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
  def by_language(conn, params) do
    language = params["language"]
    
    # Support format parameter for AST enhancements
    format = try do
      String.to_existing_atom(params["format"] || "standard")
    rescue
      ArgumentError -> :standard
    end
    
    # Check if metadata should be included
    include_metadata = params["include_metadata"] == "true"
    
    # Determine accessible tiers based on authentication
    {api_key, customer, ai_enabled} = get_auth_context(conn)
    accessible_tiers = Security.get_accessible_tiers(api_key, customer, ai_enabled)
    
    # Use highest tier available for comprehensive patterns
    tier = determine_highest_tier(accessible_tiers)
    
    # Get patterns in requested format
    patterns = ASTPattern.get_patterns(language, tier, format)
    
    # Format each pattern based on the requested format
    formatted_patterns = patterns
    |> Enum.map(&format_pattern(&1, format))
    |> maybe_add_metadata(include_metadata)
    
    json(conn, %{
      patterns: formatted_patterns,
      accessible_tiers: accessible_tiers,
      language: language,
      count: length(formatted_patterns),
      format: format
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
  
  @doc """
  GET /api/v1/patterns/enhanced/:language
  Enhanced patterns with AST rules for a specific language
  """
  def enhanced(conn, %{"language" => language}) do
    with {:ok, customer} <- authenticate_request(conn) do
      patterns = Security.get_enhanced_patterns_for_language(language)
      formatted_patterns = Security.format_patterns_for_enhanced_api(patterns)
      
      json(conn, %{
        patterns: formatted_patterns,
        format: "enhanced",
        language: language,
        count: length(formatted_patterns),
        enhanced_count: Enum.count(formatted_patterns, & &1[:supports_ast])
      })
    end
  end
  
  @doc """
  GET /api/v1/patterns/enhanced
  All enhanced patterns with AST rules (cross-language)
  """
  def all_enhanced(conn, _params) do
    with {:ok, customer} <- authenticate_request(conn) do
      languages = ["javascript", "python", "java", "ruby", "php", "elixir"]
      
      all_patterns = Enum.flat_map(languages, fn lang ->
        Security.get_enhanced_patterns_for_language(lang)
      end)
      
      formatted_patterns = Security.format_patterns_for_enhanced_api(all_patterns)
      
      json(conn, %{
        patterns: formatted_patterns,
        format: "enhanced",
        language: "all",
        count: length(formatted_patterns),
        enhanced_count: Enum.count(formatted_patterns, & &1[:supports_ast])
      })
    end
  end

  @doc """
  Get detailed vulnerability metadata for a specific pattern.
  """
  def metadata(conn, %{"id" => pattern_id}) do
    # Try to find the pattern by ID across all pattern modules
    result = with {:ok, pattern_module} <- find_pattern_module(pattern_id),
                  true <- function_exported?(pattern_module, :vulnerability_metadata, 0) do
      metadata = pattern_module.vulnerability_metadata()
      
      # Convert atom keys to strings for JSON serialization
      formatted_metadata = format_metadata_for_api(metadata, pattern_id)
      
      json(conn, formatted_metadata)
    else
      {:error, :not_found} ->
        conn
        |> put_status(:not_found)
        |> json(%{error: "Pattern not found"})
        
      false ->
        # Pattern exists but doesn't have metadata yet
        conn
        |> put_status(:not_found)
        |> json(%{error: "Metadata not available for this pattern"})
    end
  end

  # Private functions
  
  defp find_pattern_module(pattern_id) do
    # Map of migrated patterns to their modules
    # Once all patterns are migrated, we can improve this function
    
    pattern_modules = %{
      "js-sql-injection-concat" => RsolvApi.Security.Patterns.Javascript.SqlInjectionConcat,
      "js-sql-injection-interpolation" => RsolvApi.Security.Patterns.Javascript.SqlInjectionInterpolation,
      "js-xss-innerhtml" => RsolvApi.Security.Patterns.Javascript.XssInnerhtml,
      "js-xss-document-write" => RsolvApi.Security.Patterns.Javascript.XssDocumentWrite
    }
    
    case Map.get(pattern_modules, pattern_id) do
      nil ->
        {:error, :not_found}
        
      module ->
        # Temporarily skip function_exported? check for vulnerability_metadata
        # since the use macro seems to be causing issues with visibility
        if function_exported?(module, :pattern, 0) do
          {:ok, module}
        else
          {:error, :not_found}
        end
    end
  end
  
  defp format_metadata_for_api(metadata, pattern_id) do
    base_metadata = %{
      pattern_id: pattern_id,
      description: metadata.description,
      references: Enum.map(metadata.references, &stringify_keys/1),
      attack_vectors: metadata.attack_vectors,
      real_world_impact: Map.get(metadata, :real_world_impact, []),
      cve_examples: metadata |> Map.get(:cve_examples, []) |> Enum.map(&stringify_keys/1),
      known_exploits: Map.get(metadata, :known_exploits, []),
      detection_notes: Map.get(metadata, :detection_notes, "")
    }
    
    # Add additional_context if present
    case Map.get(metadata, :additional_context) do
      nil -> base_metadata
      context -> Map.put(base_metadata, :additional_context, stringify_keys(context))
    end
  end
  
  defp stringify_keys(map) when is_map(map) do
    Map.new(map, fn 
      {k, v} when is_list(v) -> {to_string(k), v}
      {k, v} when is_map(v) -> {to_string(k), stringify_keys(v)}
      {k, v} -> {to_string(k), v}
    end)
  end
  
  defp maybe_add_metadata(patterns, false), do: patterns
  defp maybe_add_metadata(patterns, true) do
    Enum.map(patterns, fn pattern ->
      # Try to find the pattern module and add metadata if available
      # Handle both atom and string keys for pattern ID
      pattern_id = pattern[:id] || pattern["id"]
      
      case find_pattern_module(pattern_id) do
        {:ok, module} ->
          if function_exported?(module, :vulnerability_metadata, 0) do
            metadata = module.vulnerability_metadata()
            Map.put(pattern, :vulnerability_metadata, format_metadata_for_api(metadata, pattern_id))
          else
            pattern
          end
          
        {:error, :not_found} ->
          pattern
      end
    end)
  end

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

  defp determine_highest_tier(accessible_tiers) do
    cond do
      :enterprise in accessible_tiers -> :enterprise
      :ai in accessible_tiers -> :ai
      :protected in accessible_tiers -> :protected
      true -> :public
    end
  end
  
  defp ensure_list(value) when is_list(value), do: value
  defp ensure_list(value), do: [value]
end