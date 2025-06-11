defmodule RSOLVWeb.Api.V1.PatternController do
  use RSOLVWeb, :controller
  
  alias RsolvApi.Security.ASTPattern
  
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
    
    # Add metadata for monitoring
    metadata = %{
      language: language,
      tier: tier,
      format: format,
      count: length(patterns),
      enhanced: format == :enhanced
    }
    
    conn
    |> put_resp_header("x-pattern-version", "2.0")
    |> json(%{
      patterns: patterns,
      metadata: metadata
    })
  end
end