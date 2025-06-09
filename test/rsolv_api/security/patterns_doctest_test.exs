defmodule RsolvApi.Security.PatternsDoctestTest do
  use ExUnit.Case, async: true
  
  alias RsolvApi.Security.Pattern

  # Test JavaScript patterns
  doctest RsolvApi.Security.Patterns.Javascript
  
  # Test Python patterns
  doctest RsolvApi.Security.Patterns.Python
  
  # Test Java patterns
  doctest RsolvApi.Security.Patterns.Java
  
  # Test Elixir patterns
  doctest RsolvApi.Security.Patterns.Elixir
  
  # Test PHP patterns
  doctest RsolvApi.Security.Patterns.Php
  
  # Test CVE patterns
  doctest RsolvApi.Security.Patterns.Cve
  
  # Ruby module is excluded due to compilation issues
end