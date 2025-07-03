defmodule RsolvWeb.PatternController do
  use RsolvWeb, :controller

  alias Rsolv.Security
  alias Rsolv.Security.{ASTPattern, Pattern, DemoPatterns}
  alias Rsolv.Accounts
  
  # Require refactored pattern modules so they're available at runtime
  require Rsolv.Security.Patterns.Javascript.SqlInjectionConcat
  require Rsolv.Security.Patterns.Javascript.SqlInjectionInterpolation
  require Rsolv.Security.Patterns.Javascript.XssInnerhtml
  require Rsolv.Security.Patterns.Javascript.XssDocumentWrite
  require Rsolv.Security.Patterns.Javascript.CommandInjectionExec
  require Rsolv.Security.Patterns.Javascript.CommandInjectionSpawn
  require Rsolv.Security.Patterns.Javascript.PathTraversalJoin
  require Rsolv.Security.Patterns.Javascript.PathTraversalConcat
  require Rsolv.Security.Patterns.Javascript.WeakCryptoMd5
  require Rsolv.Security.Patterns.Javascript.WeakCryptoSha1
  require Rsolv.Security.Patterns.Javascript.HardcodedSecretPassword
  require Rsolv.Security.Patterns.Javascript.HardcodedSecretApiKey
  require Rsolv.Security.Patterns.Javascript.EvalUserInput
  require Rsolv.Security.Patterns.Javascript.UnsafeRegex
  require Rsolv.Security.Patterns.Javascript.PrototypePollution
  require Rsolv.Security.Patterns.Javascript.InsecureDeserialization
  require Rsolv.Security.Patterns.Javascript.OpenRedirect
  require Rsolv.Security.Patterns.Javascript.XxeExternalEntities
  require Rsolv.Security.Patterns.Javascript.NosqlInjection
  require Rsolv.Security.Patterns.Javascript.LdapInjection
  require Rsolv.Security.Patterns.Javascript.XpathInjection
  require Rsolv.Security.Patterns.Javascript.Ssrf
  require Rsolv.Security.Patterns.Javascript.MissingCsrfProtection
  require Rsolv.Security.Patterns.Javascript.JwtNoneAlgorithm
  require Rsolv.Security.Patterns.Javascript.DebugConsoleLog
  require Rsolv.Security.Patterns.Javascript.InsecureRandom
  require Rsolv.Security.Patterns.Javascript.TimingAttackComparison

  action_fallback RsolvWeb.FallbackController
  
  @doc """
  GET /api/v1/patterns
  DEPRECATED: This endpoint still supports tier parameter for backward compatibility.
  Use the 'all' endpoint instead.
  
  Query params:
  - language: javascript, python, ruby, etc. (default: javascript)
  - tier: DEPRECATED - ignored but kept for backward compatibility
  - format: standard or enhanced (default: standard)
  """
  def index(conn, params) do
    # Log deprecation warning
    require Logger
    Logger.warning("PatternController.index is deprecated. Use 'all' endpoint instead.")
    
    # Redirect to the new tier-less endpoint
    all(conn, params)
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
  
  # Pattern building helpers for better readability
  
  defp build_enhanced_ast_pattern(pattern) do
    %{
      id: pattern.id,
      name: pattern.name,
      description: pattern.description,
      type: to_string(pattern.type),
      severity: to_string(pattern.severity),
      languages: pattern.languages,
      frameworks: pattern.frameworks || [],
      patterns: pattern.regex |> regex_to_string() |> ensure_list(),
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
  
  defp build_standard_ast_pattern(pattern) do
    %{
      id: pattern.id,
      name: pattern.name,
      description: pattern.description,
      type: to_string(pattern.type),
      severity: to_string(pattern.severity),
      languages: pattern.languages,
      frameworks: pattern.frameworks || [],
      patterns: pattern.regex |> regex_to_string() |> ensure_list(),
      cweId: pattern.cwe_id,
      owaspCategory: pattern.owasp_category,
      recommendation: pattern.recommendation,
      testCases: pattern.test_cases
    }
  end
  
  # Regex conversion helpers
  
  defp deep_convert_regex_to_string(%Regex{} = regex), do: regex_to_string(regex)
  defp deep_convert_regex_to_string(value) when is_map(value) do
    value
    |> Enum.map(fn {k, v} -> {k, deep_convert_regex_to_string(v)} end)
    |> Map.new()
  end
  defp deep_convert_regex_to_string(value) when is_list(value) do
    Enum.map(value, &deep_convert_regex_to_string/1)
  end
  defp deep_convert_regex_to_string(value) when is_tuple(value) do
    value |> Tuple.to_list() |> Enum.map(&deep_convert_regex_to_string/1) |> List.to_tuple()
  end
  defp deep_convert_regex_to_string(value), do: value

  @doc """
  GET /api/v1/patterns/public/:language
  DEPRECATED: Use /api/v1/patterns/:language without authentication instead.
  Legacy endpoint kept for backward compatibility.
  """
  def public(conn, %{"language" => language}) do
    # Log deprecation warning
    require Logger
    Logger.warning("PatternController.public is deprecated. Use 'all' endpoint without authentication.")
    
    # Return demo patterns (same as unauthenticated access)
    patterns = DemoPatterns.get_demo_patterns(language)
    formatted_patterns = Enum.map(patterns, fn pattern ->
      format_pattern_without_tier(pattern, :standard)
    end)
    
    json(conn, %{
      patterns: formatted_patterns,
      language: language,
      count: length(formatted_patterns)
    })
  end

  @doc """
  GET /api/v1/patterns/protected/:language
  DEPRECATED: Use /api/v1/patterns/:language with authentication instead.
  Legacy endpoint kept for backward compatibility.
  """
  def protected(conn, params = %{"language" => language}) do
    # Log deprecation warning
    require Logger
    Logger.warning("PatternController.protected is deprecated. Use 'all' endpoint with authentication.")
    
    with {:ok, _customer} <- authenticate_request(conn) do
      format = String.to_existing_atom(params["format"] || "standard")
      
      # Return all patterns (same as authenticated access)
      patterns = ASTPattern.get_all_patterns_for_language(language, format)
      formatted_patterns = Enum.map(patterns, fn pattern ->
        format_pattern_without_tier(pattern, format)
      end)
      
      response = %{
        patterns: formatted_patterns,
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
  DEPRECATED: All authenticated users now get all patterns.
  Legacy endpoint kept for backward compatibility.
  """
  def ai(conn, params = %{"language" => language}) do
    # Log deprecation warning
    require Logger
    Logger.warning("PatternController.ai is deprecated. All authenticated users get all patterns.")
    
    with {:ok, _customer} <- authenticate_request(conn) do
      format = String.to_existing_atom(params["format"] || "standard")
      
      # Return all patterns for authenticated users
      patterns = ASTPattern.get_all_patterns_for_language(language, format)
      formatted_patterns = Enum.map(patterns, fn pattern ->
        format_pattern_without_tier(pattern, format)
      end)
      
      response = %{
        patterns: formatted_patterns,
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
  GET /api/v1/patterns/enterprise/:language
  DEPRECATED: All authenticated users now get all patterns.
  Legacy endpoint kept for backward compatibility.
  """
  def enterprise(conn, params = %{"language" => language}) do
    # Log deprecation warning
    require Logger
    Logger.warning("PatternController.enterprise is deprecated. All authenticated users get all patterns.")
    
    with {:ok, _customer} <- authenticate_request(conn) do
      format = String.to_existing_atom(params["format"] || "standard")
      
      # Return all patterns for authenticated users
      patterns = ASTPattern.get_all_patterns_for_language(language, format)
      formatted_patterns = Enum.map(patterns, fn pattern ->
        format_pattern_without_tier(pattern, format)
      end)
      
      response = %{
        patterns: formatted_patterns,
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
  GET /api/v1/patterns/:language
  DEPRECATED: Use /api/v1/patterns with language parameter instead.
  Legacy endpoint kept for backward compatibility.
  """
  def by_language(conn, params) do
    # Log deprecation warning
    require Logger
    Logger.warning("PatternController.by_language is deprecated. Use 'all' endpoint instead.")
    
    # Redirect to the new tier-less endpoint
    all(conn, params)
  end

  @doc """
  GET /api/v1/patterns/public
  DEPRECATED: Use /api/v1/patterns without authentication instead.
  Legacy endpoint kept for backward compatibility.
  """
  def all_public(conn, _params) do
    # Log deprecation warning
    require Logger
    Logger.warning("PatternController.all_public is deprecated. Use 'all' endpoint without authentication.")
    
    # Return demo patterns for all languages
    patterns = DemoPatterns.get_demo_patterns()
    formatted_patterns = Enum.map(patterns, fn pattern ->
      format_pattern_without_tier(pattern, :standard)
    end)
    
    json(conn, %{
      patterns: formatted_patterns,
      language: "all",
      count: length(formatted_patterns)
    })
  end

  @doc """
  GET /api/v1/patterns/protected
  DEPRECATED: Use /api/v1/patterns with authentication instead.
  Legacy endpoint kept for backward compatibility.
  """
  def all_protected(conn, _params) do
    # Log deprecation warning
    require Logger
    Logger.warning("PatternController.all_protected is deprecated. Use 'all' endpoint with authentication.")
    
    with {:ok, _customer} <- authenticate_request(conn) do
      # Return all patterns for authenticated users (all languages)
      languages = ["javascript", "python", "ruby", "java", "elixir", "php"]
      patterns = Enum.flat_map(languages, fn lang ->
        ASTPattern.get_all_patterns_for_language(lang, :standard)
      end)
      
      formatted_patterns = Enum.map(patterns, fn pattern ->
        format_pattern_without_tier(pattern, :standard)
      end)
      
      json(conn, %{
        patterns: formatted_patterns,
        language: "all", 
        count: length(formatted_patterns)
      })
    end
  end

  @doc """
  GET /api/v1/patterns/ai
  DEPRECATED: All authenticated users now get all patterns.
  Legacy endpoint kept for backward compatibility.
  """
  def all_ai(conn, _params) do
    # Log deprecation warning
    require Logger
    Logger.warning("PatternController.all_ai is deprecated. All authenticated users get all patterns.")
    
    with {:ok, _customer} <- authenticate_request(conn) do
      # Return all patterns for authenticated users (all languages)
      languages = ["javascript", "python", "ruby", "java", "elixir", "php"]
      patterns = Enum.flat_map(languages, fn lang ->
        ASTPattern.get_all_patterns_for_language(lang, :standard)
      end)
      
      formatted_patterns = Enum.map(patterns, fn pattern ->
        format_pattern_without_tier(pattern, :standard)
      end)
      
      json(conn, %{
        patterns: formatted_patterns,
        language: "all", 
        count: length(formatted_patterns)
      })
    end
  end

  @doc """
  GET /api/v1/patterns/enterprise
  DEPRECATED: All authenticated users now get all patterns.
  Legacy endpoint kept for backward compatibility.
  """
  def all_enterprise(conn, _params) do
    # Log deprecation warning
    require Logger
    Logger.warning("PatternController.all_enterprise is deprecated. All authenticated users get all patterns.")
    
    with {:ok, _customer} <- authenticate_request(conn) do
      # Return all patterns for authenticated users (all languages)
      languages = ["javascript", "python", "ruby", "java", "elixir", "php"]
      patterns = Enum.flat_map(languages, fn lang ->
        ASTPattern.get_all_patterns_for_language(lang, :standard)
      end)
      
      formatted_patterns = Enum.map(patterns, fn pattern ->
        format_pattern_without_tier(pattern, :standard)
      end)
      
      json(conn, %{
        patterns: formatted_patterns,
        language: "all", 
        count: length(formatted_patterns)
      })
    end
  end

  @doc """
  GET /api/v1/patterns
  Get security patterns for a language.
  
  Query params:
  - language: javascript, python, ruby, etc. (default: javascript)
  - tier: DEPRECATED - kept for backward compatibility but ignored
  - format: standard (default) or enhanced (with AST rules)
  
  Access model:
  - With API key: Access to all ~181 patterns
  - Without API key: Access to ~20 demo patterns only
  """
  def all(conn, params) do
    language = params["language"] || "javascript"
    format = String.to_existing_atom(params["format"] || "standard")
    
    # Check if user has API key
    has_api_key = has_valid_api_key?(conn)
    
    # Debug logging
    require Logger
    Logger.info("PatternController.all - has_api_key: #{has_api_key}, language: #{language}")
    
    # Get patterns based on authentication
    patterns = if has_api_key do
      # Return all patterns for the language
      all_patterns = ASTPattern.get_all_patterns_for_language(language, format)
      Logger.info("With API key - returning #{length(all_patterns)} patterns")
      all_patterns
    else
      # Return only demo patterns
      demo_patterns = DemoPatterns.get_demo_patterns(language)
      Logger.info("Without API key - returning #{length(demo_patterns)} demo patterns")
      demo_patterns
    end
    
    # Convert patterns to API format (removing tier information)
    formatted_patterns = Enum.map(patterns, fn pattern ->
      format_pattern_without_tier(pattern, format)
    end)
    
    # Build metadata without tier information
    metadata = %{
      language: language,
      format: to_string(format),
      count: length(formatted_patterns),
      enhanced: format == :enhanced,
      access_level: if(has_api_key, do: "full", else: "demo")
    }
    
    conn
    |> put_resp_header("x-pattern-version", "2.0")
    |> json(%{
      patterns: formatted_patterns,
      metadata: metadata
    })
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
  def v2_protected(conn, %{"language" => _language}) do
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
  def v2_by_language(conn, %{"language" => _language}) do
    # Force enhanced format for v2
    params = Map.put(conn.params, "format", "enhanced")
    by_language(conn, params)
  end

  
  defp ensure_list(value) when is_list(value), do: value
  defp ensure_list(value), do: [value]
  
  defp has_valid_api_key?(conn) do
    case get_req_header(conn, "authorization") do
      ["Bearer " <> api_key] ->
        # Check if API key is valid
        case Accounts.get_customer_by_api_key(api_key) do
          nil -> false
          _customer -> true
        end
      _ ->
        false
    end
  end
  
  defp format_pattern_without_tier(%Pattern{} = pattern, format) do
    base_format = Pattern.to_api_format(pattern)
    
    # Remove tier field
    formatted = Map.delete(base_format, :tier)
    
    # Add enhanced fields if requested
    if format == :enhanced do
      # Add AST enhancement fields if available
      case get_ast_enhancement_fields(pattern) do
        nil -> formatted
        ast_fields -> Map.put(formatted, :astEnhancement, ast_fields)
      end
    else
      formatted
    end
  end
  
  defp format_pattern_without_tier(%ASTPattern{} = pattern, format) do
    formatted = case format do
      :enhanced ->
        # Include AST rules for enhanced format
        build_enhanced_ast_pattern(pattern)
        |> Map.delete(:tier)
        
      :standard ->
        # Standard format without AST rules
        build_standard_ast_pattern(pattern)
        |> Map.delete(:tier)
    end
    
    formatted
  end
  
  defp format_pattern_without_tier(pattern, _format) do
    # Fallback for other pattern types
    pattern
    |> Map.delete(:tier)
    |> Map.delete(:default_tier)
  end
  
  defp get_ast_enhancement_fields(%Pattern{} = pattern) do
    # Try to get AST enhancement from the pattern module
    pattern_module = pattern_id_to_module(pattern.id)
    
    if pattern_module && function_exported?(pattern_module, :ast_enhancement, 0) do
      apply(pattern_module, :ast_enhancement, [])
    else
      nil
    end
  rescue
    _ -> nil
  end

  defp pattern_id_to_module(pattern_id) do
    # Convert pattern ID to module name
    # e.g., "js-xss-dom-manipulation" -> Rsolv.Security.Patterns.Javascript.XssDomManipulation
    parts = String.split(pattern_id, "-")
    
    if length(parts) >= 2 do
      [lang | rest] = parts
      
      language = case lang do
        "js" -> "Javascript"
        "ts" -> "Typescript"
        "py" -> "Python"
        "rb" -> "Ruby"
        "php" -> "Php"
        "go" -> "Go"
        "java" -> "Java"
        _ -> String.capitalize(lang)
      end
      
      pattern_name = rest
        |> Enum.map(&String.capitalize/1)
        |> Enum.join("")
      
      module_name = Module.concat([
        Rsolv.Security.Patterns,
        language,
        pattern_name
      ])
      
      if Code.ensure_loaded?(module_name) do
        module_name
      else
        nil
      end
    else
      nil
    end
  end
  
  defp find_pattern_module(pattern_id) do
    # Try dynamic module resolution first
    module = case pattern_id do
      "js-" <> rest -> 
        module_name = rest
        |> String.split("-")
        |> Enum.map(&Macro.camelize/1)
        |> Enum.join("")
        
        try do
          Module.safe_concat([Rsolv.Security.Patterns.Javascript, module_name])
        rescue
          ArgumentError -> nil
        end
        
      "python-" <> rest ->
        module_name = rest
        |> String.split("-")
        |> Enum.map(&Macro.camelize/1)
        |> Enum.join("")
        
        try do
          Module.safe_concat([Rsolv.Security.Patterns.Python, module_name])
        rescue
          ArgumentError -> nil
        end
        
      "elixir-" <> rest ->
        module_name = rest
        |> String.split("-")
        |> Enum.map(&Macro.camelize/1)
        |> Enum.join("")
        
        try do
          Module.safe_concat([Rsolv.Security.Patterns.Elixir, module_name])
        rescue
          ArgumentError -> nil
        end
        
      "ruby-" <> rest ->
        module_name = rest
        |> String.split("-")
        |> Enum.map(&Macro.camelize/1)
        |> Enum.join("")
        
        try do
          Module.safe_concat([Rsolv.Security.Patterns.Ruby, module_name])
        rescue
          ArgumentError -> nil
        end
        
      "java-" <> rest ->
        module_name = rest
        |> String.split("-")
        |> Enum.map(&Macro.camelize/1)
        |> Enum.join("")
        
        try do
          Module.safe_concat([Rsolv.Security.Patterns.Java, module_name])
        rescue
          ArgumentError -> nil
        end
        
      "php-" <> rest ->
        module_name = rest
        |> String.split("-")
        |> Enum.map(&Macro.camelize/1)
        |> Enum.join("")
        
        try do
          Module.safe_concat([Rsolv.Security.Patterns.Php, module_name])
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