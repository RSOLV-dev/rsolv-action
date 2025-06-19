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
  - With API key: Access to all ~172 patterns
  - Without API key: Access to ~20 demo patterns only
  """
  def index(conn, params) do
    language = params["language"] || "javascript"
    format = String.to_existing_atom(params["format"] || "standard")
    
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
      # TODO: Add AST enhancement fields if available
      formatted
    else
      formatted
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
end