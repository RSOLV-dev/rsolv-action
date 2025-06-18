defmodule RSOLVWeb.Api.V1.PatternController do
  use RSOLVWeb, :controller
  
  alias RsolvApi.Security.ASTPattern
  alias RsolvApi.Security.Pattern
  
  @doc """
  Get security patterns for a language and tier.
  
  Query params:
  - language: javascript, python, ruby, etc.
  - tier: public, protected, ai, enterprise
  - format: standard (default) or enhanced (with AST rules)
  """
  def index(conn, params) do
    language = params["language"] || "javascript"
    tier = String.to_existing_atom(params["tier"] || "public")
    format = String.to_existing_atom(params["format"] || "standard")
    
    patterns = ASTPattern.get_patterns(language, tier, format)
    
    # Convert patterns to API format
    formatted_patterns = Enum.map(patterns, fn pattern ->
      case format do
        :enhanced ->
          # For enhanced patterns, include AST rules
          pattern
          |> Map.from_struct()
          |> Map.put(:tier, to_string(pattern.default_tier))
          
        :standard ->
          # For standard patterns, use the Pattern.to_api_format function
          Pattern.to_api_format(pattern)
      end
    end)
    
    # Add metadata for monitoring
    metadata = %{
      language: language,
      tier: tier,
      format: format,
      count: length(formatted_patterns),
      enhanced: format == :enhanced
    }
    
    conn
    |> put_resp_header("x-pattern-version", "2.0")
    |> json(%{
      patterns: formatted_patterns,
      metadata: metadata
    })
  end
end