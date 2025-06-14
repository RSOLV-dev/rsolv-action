defmodule RsolvApi.Security.PatternMatcher do
  @moduledoc """
  Pattern matching functionality for security patterns.
  
  Provides utilities to test if code matches security patterns.
  """

  @doc """
  Checks if the given code matches any of the patterns defined in the pattern module.
  
  ## Parameters
    - pattern_module: The pattern module (e.g., RsolvApi.Security.Patterns.Python.WeakHashSha1)
    - code: The source code to check
  
  ## Returns
    - true if any pattern matches
    - false otherwise
  """
  def matches?(pattern_module, code) when is_binary(code) do
    pattern = pattern_module.pattern()
    
    Enum.any?(pattern.patterns, fn regex ->
      Regex.match?(regex, code)
    end)
  end
  
  def matches?(_pattern_module, nil), do: false
end