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
  require RsolvApi.Security.Patterns.Javascript.CommandInjectionExec
  require RsolvApi.Security.Patterns.Javascript.CommandInjectionSpawn
  require RsolvApi.Security.Patterns.Javascript.PathTraversalJoin
  require RsolvApi.Security.Patterns.Javascript.PathTraversalConcat
  require RsolvApi.Security.Patterns.Javascript.WeakCryptoMd5
  require RsolvApi.Security.Patterns.Javascript.WeakCryptoSha1
  require RsolvApi.Security.Patterns.Javascript.HardcodedSecretPassword
  require RsolvApi.Security.Patterns.Javascript.HardcodedSecretApiKey
  require RsolvApi.Security.Patterns.Javascript.EvalUserInput
  require RsolvApi.Security.Patterns.Javascript.UnsafeRegex
  require RsolvApi.Security.Patterns.Javascript.PrototypePollution
  require RsolvApi.Security.Patterns.Javascript.InsecureDeserialization
  require RsolvApi.Security.Patterns.Javascript.OpenRedirect
  require RsolvApi.Security.Patterns.Javascript.XxeExternalEntities
  require RsolvApi.Security.Patterns.Javascript.NosqlInjection
  require RsolvApi.Security.Patterns.Javascript.LdapInjection
  require RsolvApi.Security.Patterns.Javascript.XpathInjection
  require RsolvApi.Security.Patterns.Javascript.Ssrf
  require RsolvApi.Security.Patterns.Javascript.MissingCsrfProtection
  require RsolvApi.Security.Patterns.Javascript.JwtNoneAlgorithm
  require RsolvApi.Security.Patterns.Javascript.DebugConsoleLog
  require RsolvApi.Security.Patterns.Javascript.InsecureRandom
  require RsolvApi.Security.Patterns.Javascript.TimingAttackComparison

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
      tier: to_string(pattern.tier || pattern.default_tier || "public"),
      languages: pattern.languages,
      frameworks: pattern.frameworks || [],
      patterns: ensure_list(regex_to_string(pattern.regex)),
      cweId: pattern.cwe_id,
      owaspCategory: pattern.owasp_category,
      recommendation: pattern.recommendation,
      testCases: pattern.test_cases,
      # AST enhancement fields
      supportsAst: true,
      astRules: format_ast_rules(pattern.ast_rules),
      contextRules: format_context_rules(pattern.context_rules),
      confidenceRules: pattern.confidence_rules,
      minConfidence: pattern.min_confidence
    }
  end
  
  defp format_pattern(%ASTPattern{} = pattern, :standard) do
    # For AST patterns in standard format, convert to standard format
    Pattern.to_api_format(pattern)
  end
  
  defp format_pattern(%Pattern{} = pattern, :enhanced) do
    # For regular patterns with enhanced format, check if we can find the module
    pattern_module = case find_pattern_module(pattern.id) do
      {:ok, module} -> module
      _ -> nil
    end
    
    if pattern_module && function_exported?(pattern_module, :ast_enhancement, 0) do
      # Pattern supports AST enhancement
      ast_enhancement = apply(pattern_module, :ast_enhancement, [])
      
      # Convert to enhanced format with AST fields
      %{
        id: pattern.id,
        name: pattern.name,
        description: pattern.description,
        type: to_string(pattern.type),
        severity: to_string(pattern.severity),
        tier: to_string(pattern.default_tier || "public"),
        languages: pattern.languages,
        frameworks: pattern.frameworks || [],
        patterns: ensure_list(regex_to_string(pattern.regex)),
        cweId: pattern.cwe_id,
        owaspCategory: pattern.owasp_category,
        recommendation: pattern.recommendation,
        testCases: pattern.test_cases,
        # AST enhancement fields - properly formatted
        supportsAst: true,
        astRules: format_ast_rules(ast_enhancement[:ast_rules]),
        contextRules: format_context_rules(ast_enhancement[:context_rules]),
        confidenceRules: ast_enhancement[:confidence_rules],
        minConfidence: ast_enhancement[:min_confidence]
      }
    else
      # Pattern doesn't support AST enhancement, return standard format with supportsAst: false
      pattern_map = Pattern.to_api_format(pattern)
      Map.put(pattern_map, :supportsAst, false)
    end
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
  
  defp format_ast_rules(nil), do: []
  defp format_ast_rules(rules) when is_list(rules) do
    # If rules is a list, return it as-is
    rules
  end
  defp format_ast_rules(rules) when is_map(rules) do
    # Convert map to list format for API compatibility
    # The API expects ast_rules as a list, not a map
    # Also handle the deep regex conversion properly
    formatted_rules = rules
    |> Enum.map(fn {k, v} -> {k, deep_convert_regex_to_string(v)} end)
    |> Map.new()
    
    [formatted_rules]
  end
  
  defp deep_convert_regex_to_string(%Regex{} = regex), do: regex_to_string(regex)
  defp deep_convert_regex_to_string(value) when is_map(value) do
    value
    |> Enum.map(fn {k, v} -> {k, deep_convert_regex_to_string(v)} end)
    |> Map.new()
  end
  defp deep_convert_regex_to_string(value) when is_list(value) do
    Enum.map(value, &deep_convert_regex_to_string/1)
  end
  defp deep_convert_regex_to_string(value), do: value

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
  def protected(conn, params = %{"language" => language}) do
    with {:ok, _customer} <- authenticate_request(conn) do
      format = String.to_existing_atom(params["format"] || "standard")
      patterns = Security.list_patterns_by_language_and_tier(language, "protected")
      
      # Use format_patterns to handle enhanced format
      formatted_patterns = Enum.map(patterns, &format_pattern(&1, format))
      
      response = %{
        patterns: formatted_patterns,
        tier: "protected",
        language: language,
        count: length(formatted_patterns)
      }
      
      # Add format field for enhanced format
      response = if format == :enhanced do
        Map.put(response, :format, "enhanced")
      else
        response
      end
      
      json(conn, response)
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
      format: to_string(format)
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
  def all(conn, params) do
    # Check if this should use legacy behavior:
    # 1. When explicit query parameters are provided (language, tier, format)
    # 2. When no parameters at all (default to javascript/public for backward compatibility)
    use_legacy = params["language"] || params["tier"] || params["format"] || map_size(params) == 0
    
    if use_legacy do
      # Legacy behavior: use index logic with query parameters
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
    else
      # New behavior: cross-language patterns based on authentication
      {api_key, customer, ai_enabled} = get_auth_context(conn)
      accessible_tiers = Security.get_accessible_tiers(api_key, customer, ai_enabled)
      
      patterns = Security.list_all_patterns(accessible_tiers)
      formatted_patterns = Security.format_patterns_for_api(patterns)
      
      conn
      |> put_resp_header("x-pattern-version", "2.0")
      |> json(%{
        patterns: formatted_patterns,
        accessible_tiers: accessible_tiers,
        language: "all",
        count: length(formatted_patterns)
      })
    end
  end
  
  @doc """
  GET /api/v1/patterns/enhanced/:language
  Enhanced patterns with AST rules for a specific language
  """
  def enhanced(conn, %{"language" => language}) do
    with {:ok, _customer} <- authenticate_request(conn) do
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
    with {:ok, _customer} <- authenticate_request(conn) do
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
    case find_pattern_module(pattern_id) do
      {:ok, pattern_module} ->
        try do
          metadata = pattern_module.vulnerability_metadata()
          
          # Convert atom keys to strings for JSON serialization
          formatted_metadata = format_metadata_for_api(metadata, pattern_id)
          
          json(conn, formatted_metadata)
        rescue
          UndefinedFunctionError ->
            # Pattern exists but doesn't have metadata yet
            conn
            |> put_status(:not_found)
            |> json(%{error: "Metadata not available for this pattern"})
        end
        
      {:error, :not_found} ->
        conn
        |> put_status(:not_found)
        |> json(%{error: "Pattern not found"})
    end
  end

  # Private functions
  
  
  defp format_metadata_for_api(metadata, pattern_id) do
    base_metadata = %{
      pattern_id: pattern_id,
      description: metadata.description,
      references: Enum.map(metadata.references, &stringify_keys/1),
      attack_vectors: metadata.attack_vectors,
      real_world_impact: Map.get(metadata, :real_world_impact, []),
      cve_examples: metadata |> Map.get(:cve_examples, []) |> Enum.map(&stringify_keys/1),
      known_exploits: Map.get(metadata, :known_exploits, []),
      detection_notes: Map.get(metadata, :detection_notes, ""),
      safe_alternatives: Map.get(metadata, :safe_alternatives, [])
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
          try do
            metadata = module.vulnerability_metadata()
            Map.put(pattern, :vulnerability_metadata, format_metadata_for_api(metadata, pattern_id))
          rescue
            UndefinedFunctionError ->
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

  # V2 API endpoints - Enhanced format by default
  
  @doc """
  GET /api/v2/patterns/public/:language
  V2 endpoint for public patterns with enhanced format
  """
  def v2_public(conn, %{"language" => language}) do
    # Force enhanced format for v2
    params = %{"language" => language, "format" => "enhanced"}
    public(conn, params)
  end

  @doc """
  GET /api/v2/patterns/protected/:language 
  V2 endpoint for protected patterns with enhanced format
  """
  def v2_protected(conn, %{"language" => language}) do
    # Force enhanced format for v2
    params = Map.put(conn.params, "format", "enhanced")
    protected(conn, params)
  end

  @doc """
  GET /api/v2/patterns/ai/:language
  V2 endpoint for AI patterns with enhanced format
  """
  def v2_ai(conn, %{"language" => language}) do
    # Force enhanced format for v2
    params = %{"language" => language, "format" => "enhanced"}
    ai(conn, params)
  end

  @doc """
  GET /api/v2/patterns/enterprise/:language
  V2 endpoint for enterprise patterns with enhanced format
  """
  def v2_enterprise(conn, %{"language" => language}) do
    # Force enhanced format for v2
    params = %{"language" => language, "format" => "enhanced"}
    enterprise(conn, params)
  end

  @doc """
  GET /api/v2/patterns/:language
  V2 endpoint for all accessible patterns by language with enhanced format
  """
  def v2_by_language(conn, %{"language" => language}) do
    # Force enhanced format for v2
    params = Map.put(conn.params, "format", "enhanced")
    by_language(conn, params)
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
      "enterprise" in accessible_tiers -> :enterprise
      "ai" in accessible_tiers -> :ai
      "protected" in accessible_tiers -> :protected
      true -> :public
    end
  end
  
  defp ensure_list(value) when is_list(value), do: value
  defp ensure_list(value), do: [value]
  
  defp find_pattern_module(pattern_id) do
    # Try dynamic module resolution first
    module = case pattern_id do
      "js-" <> rest -> 
        module_name = rest
        |> String.split("-")
        |> Enum.map(&Macro.camelize/1)
        |> Enum.join("")
        
        try do
          Module.safe_concat([RsolvApi.Security.Patterns.Javascript, module_name])
        rescue
          ArgumentError -> nil
        end
        
      "python-" <> rest ->
        module_name = rest
        |> String.split("-")
        |> Enum.map(&Macro.camelize/1)
        |> Enum.join("")
        
        try do
          Module.safe_concat([RsolvApi.Security.Patterns.Python, module_name])
        rescue
          ArgumentError -> nil
        end
        
      "elixir-" <> rest ->
        module_name = rest
        |> String.split("-")
        |> Enum.map(&Macro.camelize/1)
        |> Enum.join("")
        
        try do
          Module.safe_concat([RsolvApi.Security.Patterns.Elixir, module_name])
        rescue
          ArgumentError -> nil
        end
        
      "ruby-" <> rest ->
        module_name = rest
        |> String.split("-")
        |> Enum.map(&Macro.camelize/1)
        |> Enum.join("")
        
        try do
          Module.safe_concat([RsolvApi.Security.Patterns.Ruby, module_name])
        rescue
          ArgumentError -> nil
        end
        
      "java-" <> rest ->
        module_name = rest
        |> String.split("-")
        |> Enum.map(&Macro.camelize/1)
        |> Enum.join("")
        
        try do
          Module.safe_concat([RsolvApi.Security.Patterns.Java, module_name])
        rescue
          ArgumentError -> nil
        end
        
      "php-" <> rest ->
        module_name = rest
        |> String.split("-")
        |> Enum.map(&Macro.camelize/1)
        |> Enum.join("")
        
        try do
          Module.safe_concat([RsolvApi.Security.Patterns.Php, module_name])
        rescue
          ArgumentError -> nil
        end
        
      _ ->
        nil
    end
    
    if module do
      {:ok, module}
    else
      {:error, :not_found}
    end
  end
end