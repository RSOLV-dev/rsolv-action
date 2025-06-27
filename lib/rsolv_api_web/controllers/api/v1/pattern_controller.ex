defmodule RSOLVWeb.Api.V1.PatternController do
  use RSOLVWeb, :controller
  
  alias RsolvApi.Security.ASTPattern
  alias RsolvApi.Security.Pattern
  alias RsolvApi.Security.DemoPatterns
  alias RSOLV.Accounts
  
  @doc """
  Get security patterns for a language.
  
  Query params:
  - language: javascript, python, ruby, etc.
  - tier: DEPRECATED - kept for backward compatibility but ignored
  - format: standard (default) or enhanced (with AST rules)
  
  Access model:
  - With API key: Access to all ~181 patterns
  - Without API key: Access to ~20 demo patterns only
  """
  def index(conn, params) do
    try do
      language = params["language"] || "javascript"
      format = case params["format"] do
        "enhanced" -> :enhanced
        _ -> :standard
      end
      
      # Check if user has API key
      has_api_key = has_valid_api_key?(conn)
      
      # Get patterns based on authentication
      patterns = if has_api_key do
        # Return all patterns for the language
        ASTPattern.get_all_patterns_for_language(language, format)
      else
        # Return only demo patterns
        DemoPatterns.get_demo_patterns(language)
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
    rescue
      e ->
        # Log the error for debugging
        require Logger
        Logger.error("Pattern API error: #{inspect(e)}")
        Logger.error(Exception.format_stacktrace())
        
        # Return proper 500 error response
        conn
        |> put_status(:internal_server_error)
        |> json(%{
          error: "Internal server error",
          message: "An error occurred while processing patterns"
        })
    end
  end
  
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
    # e.g., "js-xss-dom-manipulation" -> RsolvApi.Security.Patterns.Javascript.XssDomManipulation
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
        RsolvApi.Security.Patterns,
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
  
  defp format_pattern_without_tier(%ASTPattern{} = pattern, format) do
    formatted = case format do
      :enhanced ->
        # Include AST rules for enhanced format
        pattern
        |> Map.from_struct()
        |> Map.delete(:default_tier)
        |> Map.delete(:tier)
        |> convert_regex_to_string()
        |> format_ast_enhanced_pattern()
        
      :standard ->
        # Standard format without AST rules
        pattern
        |> Pattern.to_api_format()
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
  
  # Convert regex fields to strings for JSON serialization
  defp convert_regex_to_string(pattern_map) do
    pattern_map
    |> Map.update(:regex, nil, &regex_to_strings/1)
    |> Map.update(:ast_rules, nil, &convert_ast_rules_regex/1)
    |> Map.update(:context_rules, nil, &convert_context_rules_regex/1)
    |> convert_all_regex_deeply()
  end
  
  # Deep conversion of any remaining regex objects
  defp convert_all_regex_deeply(map) when is_map(map) do
    map
    |> Enum.map(fn
      {k, %Regex{} = v} -> {k, Regex.source(v)}
      {k, v} when is_map(v) -> {k, convert_all_regex_deeply(v)}
      {k, v} when is_list(v) -> {k, convert_list_regex(v)}
      {k, v} -> {k, v}
    end)
    |> Enum.into(%{})
  end
  defp convert_all_regex_deeply(value), do: value
  
  defp convert_list_regex(list) when is_list(list) do
    Enum.map(list, fn
      %Regex{} = r -> Regex.source(r)
      v when is_map(v) -> convert_all_regex_deeply(v)
      v when is_list(v) -> convert_list_regex(v)
      v -> v
    end)
  end
  
  defp regex_to_strings(nil), do: nil
  defp regex_to_strings(%Regex{} = regex), do: [Regex.source(regex)]
  defp regex_to_strings(list) when is_list(list) do
    Enum.map(list, fn
      %Regex{} = r -> Regex.source(r)
      string -> string
    end)
  end
  defp regex_to_strings(other), do: other
  
  defp convert_ast_rules_regex(nil), do: nil
  defp convert_ast_rules_regex(ast_rules) when is_map(ast_rules) do
    ast_rules
    |> Enum.map(fn
      {:ancestor_requirements, req} when is_map(req) ->
        {:ancestor_requirements, convert_map_regex_values(req)}
      {:parent_node, node} when is_map(node) ->
        {:parent_node, convert_map_regex_values(node)}
      {k, v} when is_map(v) ->
        {k, convert_map_regex_values(v)}
      {k, v} -> {k, v}
    end)
    |> Enum.into(%{})
  end
  defp convert_ast_rules_regex(other), do: other
  
  defp convert_context_rules_regex(nil), do: nil
  defp convert_context_rules_regex(context_rules) when is_map(context_rules) do
    context_rules
    |> Enum.map(fn
      {:exclude_paths, paths} when is_list(paths) ->
        {:exclude_paths, Enum.map(paths, &regex_to_string/1)}
      {k, v} -> {k, v}
    end)
    |> Enum.into(%{})
  end
  defp convert_context_rules_regex(other), do: other
  
  defp convert_map_regex_values(map) when is_map(map) do
    map
    |> Enum.map(fn
      {k, %Regex{} = v} -> {k, Regex.source(v)}
      {k, v} -> {k, v}
    end)
    |> Enum.into(%{})
  end
  
  defp regex_to_string(%Regex{} = regex), do: Regex.source(regex)
  defp regex_to_string(other), do: other
  
  # Format enhanced pattern to match expected API format
  defp format_ast_enhanced_pattern(pattern_map) do
    # Ensure all required fields are present with proper formatting
    pattern_map
    |> Map.put(:regex_patterns, pattern_map[:regex])
    |> Map.delete(:regex)
    |> Map.put(:type, to_string(pattern_map[:type] || ""))
    |> Map.put(:severity, to_string(pattern_map[:severity] || ""))
    |> Map.update(:test_cases, %{}, fn test_cases ->
      case test_cases do
        %{vulnerable: v, safe: s} -> %{vulnerable: v, safe: s}
        _ -> %{vulnerable: [], safe: []}
      end
    end)
    |> Map.put(:examples, %{
      vulnerable: get_in(pattern_map, [:test_cases, :vulnerable]) |> List.first() || "",
      safe: get_in(pattern_map, [:test_cases, :safe]) |> List.first() || ""
    })
  end
end