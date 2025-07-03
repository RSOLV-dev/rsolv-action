defmodule Rsolv.Security.Patterns.Common do
  @moduledoc """
  Common security patterns that apply across multiple languages.
  
  These patterns detect vulnerabilities that are not language-specific,
  such as weak JWT secrets, which can appear in any language.
  """
  
  alias Rsolv.Security.Patterns.Common.WeakJwtSecret
  
  @doc """
  Returns all common security patterns.
  
  ## Examples
  
      iex> patterns = Rsolv.Security.Patterns.Common.all()
      iex> length(patterns)
      1
  """
  def all do
    [
      WeakJwtSecret.pattern()
    ]
  end
end